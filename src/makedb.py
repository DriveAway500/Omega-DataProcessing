import glob
import gzip
import json
import multiprocessing as mp
import os
import re
import sqlite3
import time

FILE_PATTERN = "nvdcve-2.0-*.json.gz"
DB_DIR = "."                 # pasta onde os .db por ano serão criados
DB_NAME_TEMPLATE = "cve_{year}.db"  # ex: cve_2023.db
BATCH_SIZE = 20_000  # linhas por executemany, evita picos de memória

# Casa "nvdcve-2.0-2023.json.gz" -> "2023"
# Arquivos sem ano no nome (ex: nvdcve-2.0-modified.json.gz,
# nvdcve-2.0-recent.json.gz) caem no grupo "misc".
YEAR_RE = re.compile(r"nvdcve-2\.0-(\d{4})\.json\.gz$")


def extract_year(file_path):
    m = YEAR_RE.search(os.path.basename(file_path))
    return m.group(1) if m else "misc"


def db_path_for_year(year):
    return os.path.join(DB_DIR, DB_NAME_TEMPLATE.format(year=year))


def connect_db(db_path):
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous  = NORMAL;
        PRAGMA temp_store   = MEMORY;
        PRAGMA cache_size   = -131072;   -- ~128MB de cache
        PRAGMA mmap_size    = 268435456; -- 256MB
        """
    )
    return conn


def create_schema(conn):
    """Cria só a tabela principal. Índice/FTS vêm depois de carregar os dados."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS recent_cve (
            cve_id TEXT PRIMARY KEY,
            last_modified TEXT,
            data TEXT
        )
        """
    )
    conn.commit()


def parse_file(file_path):
    """Descompacta e faz parse do JSON (CPU-bound)."""
    with gzip.open(file_path, "rt", encoding="utf-8") as f:
        payload = json.load(f)

    records = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        last_modified = cve.get("lastModified")
        if cve_id and last_modified:
            records.append(
                (cve_id, last_modified, json.dumps(cve, separators=(",", ":")))
            )
    return records


UPSERT_SQL = """
    INSERT INTO recent_cve (cve_id, last_modified, data)
    VALUES (?, ?, ?)
    ON CONFLICT(cve_id) DO UPDATE SET
        last_modified = excluded.last_modified,
        data = excluded.data
    WHERE excluded.last_modified > recent_cve.last_modified
"""


def load_data(conn, records):
    conn.execute("BEGIN")
    cur = conn.cursor()
    for i in range(0, len(records), BATCH_SIZE):
        cur.executemany(UPSERT_SQL, records[i : i + BATCH_SIZE])
    conn.commit()
    return len(records)


def finalize_db(conn):
    """Cria índice + FTS5 e popula tudo em bloco (não linha a linha)."""
    cur = conn.cursor()

    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_recent_cve_last_modified
        ON recent_cve(last_modified DESC)
        """
    )

    # FTS5 "external content": não duplica o JSON, só guarda o índice invertido
    cur.execute(
        """
        CREATE VIRTUAL TABLE IF NOT EXISTS recent_cve_fts USING fts5(
            cve_id UNINDEXED,
            data,
            content='recent_cve',
            content_rowid='rowid'
        )
        """
    )

    # popula a FTS de uma vez só — muito mais rápido que trigger por linha
    cur.execute("INSERT INTO recent_cve_fts(recent_cve_fts) VALUES('rebuild')")

    # triggers só passam a existir agora: mantêm a FTS em dia em cargas
    # incrementais futuras, sem pesar na carga inicial em massa já feita
    cur.executescript(
        """
        CREATE TRIGGER IF NOT EXISTS recent_cve_ai AFTER INSERT ON recent_cve BEGIN
            INSERT INTO recent_cve_fts(rowid, cve_id, data)
            VALUES (new.rowid, new.cve_id, new.data);
        END;

        CREATE TRIGGER IF NOT EXISTS recent_cve_ad AFTER DELETE ON recent_cve BEGIN
            INSERT INTO recent_cve_fts(recent_cve_fts, rowid, cve_id, data)
            VALUES('delete', old.rowid, old.cve_id, old.data);
        END;

        CREATE TRIGGER IF NOT EXISTS recent_cve_au AFTER UPDATE ON recent_cve BEGIN
            INSERT INTO recent_cve_fts(recent_cve_fts, rowid, cve_id, data)
            VALUES('delete', old.rowid, old.cve_id, old.data);
            INSERT INTO recent_cve_fts(rowid, cve_id, data)
            VALUES (new.rowid, new.cve_id, new.data);
        END;
        """
    )
    conn.commit()

    # compacta segmentos da FTS e atualiza estatísticas do planner
    cur.execute("INSERT INTO recent_cve_fts(recent_cve_fts) VALUES('optimize')")
    cur.execute("ANALYZE")
    conn.commit()


def process_one_file(file_path):
    """
    Roda em processo separado. Cada arquivo .gz corresponde a um ano
    (ou "misc" para modified/recent), então todo o ciclo — parse,
    schema, carga, índice e FTS — acontece aqui, isolado no seu
    próprio arquivo .db. Como cada processo escreve em um .db
    diferente, não há contenção de lock entre eles.
    """
    year = extract_year(file_path)
    db_path = db_path_for_year(year)

    t0 = time.time()
    records = parse_file(file_path)

    conn = connect_db(db_path)
    try:
        create_schema(conn)
        n = load_data(conn, records)
        finalize_db(conn)
        conn.execute("PRAGMA optimize")
    finally:
        conn.close()

    elapsed = time.time() - t0
    return file_path, db_path, n, elapsed


def process_files(file_pattern=FILE_PATTERN, workers=None):
    files = sorted(glob.glob(file_pattern))
    if not files:
        print("Nenhum arquivo encontrado.")
        return

    os.makedirs(DB_DIR, exist_ok=True)

    t0 = time.time()
    total = 0
    with mp.Pool(processes=workers) as pool:
        for file_path, db_path, n, elapsed in pool.imap_unordered(
            process_one_file, files
        ):
            total += n
            print(f"  {file_path} -> {db_path}: {n} CVEs em {elapsed:.1f}s")

    print(f"{total} registros carregados em {len(files)} bancos, "
          f"tempo total: {time.time() - t0:.1f}s")


if __name__ == "__main__":
    process_files()
