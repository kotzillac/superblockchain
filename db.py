#    Copyright (C) 2026  Kotzilac
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
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
)
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
