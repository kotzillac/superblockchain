# SPDX-License-Identifier: GPL-3.0-or-later

import sqlite3

conn = sqlite3.connect("blockchain.db")
cursor = conn.cursor()

cursor.execute("PRAGMA journal_mode=WAL;")

cursor.execute("PRAGMA synchronous=NORMAL;")

cursor.execute("PRAGMA cache_size=-20000;")

cursor.execute("""
CREATE TABLE IF NOT EXISTS storage (
    key BLOB PRIMARY KEY,
    value BLOB NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS blocks (
    height INTEGER PRIMARY KEY,
    data BLOB NOT NULL
);
""")

conn.commit()


def _encode(value: bytes | int) -> bytes:
    # 256-bit contract words are stored big-endian
    if isinstance(value, int):
        return value.to_bytes(32, "big", signed=value < 0)
    return bytes(value)


def readbc(key: bytes | int) -> int:
    row = cursor.execute(
        "SELECT value FROM storage WHERE key = ?", (_encode(key),)
    ).fetchone()
    return int.from_bytes(row[0], "big") if row else 0


def writebc(key: bytes | int, value: bytes | int) -> None:
    cursor.execute(
        "INSERT INTO storage(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (_encode(key), _encode(value)),
    )
    conn.commit()

def writeblock(height: int, data: bytes) -> None:
    cursor.execute("INSERT INTO blocks (height, data) VALUES (?, ?)", (height, data))

def readblock(height: int) -> bytes:
    
