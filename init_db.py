import sqlite3
from pathlib import Path

DB_PATH = "tapntrack.db"

conn = sqlite3.connect(DB_PATH)
conn.execute("""
    CREATE TABLE IF NOT EXISTS receipts (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        code      TEXT UNIQUE NOT NULL,
        s3_url    TEXT NOT NULL,
        store_id  TEXT,
        created   TEXT NOT NULL,
        expires   TEXT NOT NULL,
        tapped    INTEGER DEFAULT 0
    )
""")
conn.commit()
conn.close()
print("Database initialized.")
