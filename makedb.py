import glob
import gzip
import json
import sqlite3

def init_db(db_path="database.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS recent_cve (
            cve_id TEXT PRIMARY KEY,
            last_modified TEXT,
            data TEXT
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_recent_cve_last_modified 
        ON recent_cve(last_modified DESC);
    """)

    cursor.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS recent_cve_fts USING fts5(
            cve_id UNINDEXED,
            data
        );
    """)

    cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS recent_cve_ai AFTER INSERT ON recent_cve BEGIN
            INSERT INTO recent_cve_fts(cve_id, data) VALUES (new.cve_id, new.data);
        END;
    """)
    cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS recent_cve_ad AFTER DELETE ON recent_cve BEGIN
            INSERT INTO recent_cve_fts(recent_cve_fts, cve_id, data) VALUES('delete', old.cve_id, old.data);
        END;
    """)
    cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS recent_cve_au AFTER UPDATE ON recent_cve BEGIN
            INSERT INTO recent_cve_fts(recent_cve_fts, cve_id, data) VALUES('delete', old.cve_id, old.data);
            INSERT INTO recent_cve_fts(cve_id, data) VALUES (new.cve_id, new.data);
        END;
    """)

    conn.commit()
    return conn


def process_files(db_path="database.db", file_pattern="nvdcve-2.0-*.json.gz"):
    conn = init_db(db_path)
    cursor = conn.cursor()

    files = sorted(glob.glob(file_pattern))

    for file_path in files:
        with gzip.open(file_path, "rt", encoding="utf-8") as f:
            payload = json.load(f)

        vulnerabilities = payload.get("vulnerabilities", [])
        records = []

        for item in vulnerabilities:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            last_modified = cve.get("lastModified")

            if cve_id and last_modified:
                records.append((cve_id, last_modified, json.dumps(cve)))

        cursor.executemany(
            """
            INSERT INTO recent_cve (cve_id, last_modified, data)
            VALUES (?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                last_modified = excluded.last_modified,
                data = excluded.data
            """,
            records,
        )

        conn.commit()

    conn.close()


if __name__ == "__main__":
    process_files()