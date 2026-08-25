"""
Build rápido de um banco SQLite de CVEs (feeds NVD 2.0) com busca full-text
instantânea, mesmo com grande volume de dados.
 
Estratégia:
  1. Cria só a tabela principal (sem índices, sem FTS, sem triggers).
  2. Descompacta e faz parse dos .json.gz em paralelo (CPU-bound).
  3. Faz upsert de tudo em UMA única transação (poucos fsyncs).
  4. Só então cria índice, tabela FTS5 (external content) e a popula em bloco.
  5. Cria os triggers de sincronização da FTS — eles só entram em ação em
     cargas incrementais futuras, não pesam na carga inicial em massa.
"""
 
import glob
import gzip
import json
import multiprocessing as mp
import sqlite3
import time
 
DB_PATH = "database.db"
FILE_PATTERN = "nvdcve-2.0-*.json.gz"
BATCH_SIZE = 20_000  # linhas por executemany, evita picos de memória
 
 
def connect_db(db_path=DB_PATH):
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
    """Roda em processo separado: descompacta e faz parse do JSON (CPU-bound)."""
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
    return file_path, records
 
 
UPSERT_SQL = """
    INSERT INTO recent_cve (cve_id, last_modified, data)
    VALUES (?, ?, ?)
    ON CONFLICT(cve_id) DO UPDATE SET
        last_modified = excluded.last_modified,
        data = excluded.data
    WHERE excluded.last_modified > recent_cve.last_modified
"""
 
 
def load_data(conn, file_pattern=FILE_PATTERN, workers=None):
    files = sorted(glob.glob(file_pattern))
    if not files:
        print("Nenhum arquivo encontrado.")
        return 0
 
    total = 0
    conn.execute("BEGIN")  # transação única para toda a carga
    cur = conn.cursor()
 
    with mp.Pool(processes=workers) as pool:
        for file_path, records in pool.imap_unordered(parse_file, files):
            for i in range(0, len(records), BATCH_SIZE):
                cur.executemany(UPSERT_SQL, records[i : i + BATCH_SIZE])
            total += len(records)
            print(f"  {file_path}: {len(records)} CVEs")
 
    conn.commit()
    return total
 
 
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
 
 
def process_files(db_path=DB_PATH, file_pattern=FILE_PATTERN, workers=None):
    t0 = time.time()
    conn = connect_db(db_path)
    try:
        create_schema(conn)
 
        total = load_data(conn, file_pattern, workers=workers)
        print(f"{total} registros carregados em {time.time() - t0:.1f}s")
 
        t1 = time.time()
        finalize_db(conn)
        print(f"Índice/FTS criados em {time.time() - t1:.1f}s")
 
        conn.execute("PRAGMA optimize")
    finally:
        conn.close()
 
    print(f"Tempo total: {time.time() - t0:.1f}s")
 
 
if __name__ == "__main__":
    process_files()
