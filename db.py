# SPDX-License-Identifier: GPL-3.0-or-later

"""RocksDB-backed storage for the blockchain.

Key layout (all keys are bytes, values are bytes):
  b"storage:" + <32-byte big-endian key>  -> <32-byte big-endian value>
  b"block:"   + <8-byte big-endian height> -> serialized block bytes
  b"code:"    + <20-byte address>          -> contract bytecode
  b"meta:height"                           -> <8-byte big-endian tip height>
  b"meta:hash"                             -> tip block hash (32 bytes)

The public API is unchanged from the old SQLite version:
  readbc / writebc, readblock / writeblock
plus contract-code helpers and an atomic batch writer used by main.py
to commit a block together with its storage writes.
"""

import os
import threading

import rocksdict

DB_PATH = os.environ.get("DOCHACOIN_DB_PATH", "blockchain.rocksdb")

_lock = threading.RLock()
_db: rocksdict.Rdict | None = None


def _open() -> rocksdict.Rdict:
    global _db
    if _db is None:
        _db = rocksdict.Rdict(DB_PATH)
    return _db


def close() -> None:
    global _db
    with _lock:
        if _db is not None:
            _db.close()
            _db = None


def flush() -> None:
    with _lock:
        _open().flush()


def _encode(value: bytes | int) -> bytes:
    # 256-bit contract words are stored big-endian
    if isinstance(value, int):
        return value.to_bytes(32, "big", signed=value < 0)
    return bytes(value)


def _decode(raw: bytes | None) -> int:
    return int.from_bytes(raw, "big") if raw is not None else 0


def _storage_key(key: bytes | int) -> bytes:
    return b"storage:" + _encode(key)


def _block_key(height: int) -> bytes:
    return b"block:" + int(height).to_bytes(8, "big")


def _code_key(address: bytes) -> bytes:
    return b"code:" + bytes(address)


def readbc(key: bytes | int) -> int:
    with _lock:
        return _decode(_open().get(_storage_key(key)))


def writebc(key: bytes | int, value: bytes | int) -> None:
    with _lock:
        _open().put(_storage_key(key), _encode(value))


def writeblock(height: int, data: bytes) -> None:
    with _lock:
        _open().put(_block_key(height), bytes(data))


def readblock(height: int) -> bytes | None:
    with _lock:
        return _open().get(_block_key(height))


def write_code(address: bytes, code: bytes) -> None:
    with _lock:
        _open().put(_code_key(address), bytes(code))


def read_code(address: bytes) -> bytes | None:
    with _lock:
        return _open().get(_code_key(address))


def get_height() -> int:
    with _lock:
        raw = _open().get(b"meta:height")
    return int.from_bytes(raw, "big") if raw is not None else -1


def readbc_many(keys) -> dict:
    """Read several storage slots in one locked pass."""
    with _lock:
        return {key: _decode(_open().get(_storage_key(key))) for key in keys}


def writebc_many(values: dict) -> None:
    """Write several storage slots in one atomic batch."""
    with _lock:
        batch = rocksdict.WriteBatch()
        for key, value in values.items():
            batch.put(_storage_key(key), _encode(value))
        _open().write(batch)


def get_tip_hash() -> bytes | None:
    with _lock:
        return _open().get(b"meta:hash")


def commit_block(height: int, data: bytes, tip_hash: bytes,
                 storage: dict[bytes | int, bytes | int] | None = None,
                 code: dict[bytes, bytes] | None = None) -> None:
    """Atomically store a block, the new tip, and optional storage/code writes."""
    with _lock:
        batch = rocksdict.WriteBatch()
        batch.put(_block_key(height), bytes(data))
        batch.put(b"meta:height", int(height).to_bytes(8, "big"))
        batch.put(b"meta:hash", bytes(tip_hash))
        for key, value in (storage or {}).items():
            batch.put(_storage_key(key), _encode(value))
        for address, bytecode in (code or {}).items():
            batch.put(_code_key(address), bytes(bytecode))
        _open().write(batch)
    
