# SPDX-License-Identifier: GPL-3.0-or-later

"""Dochacoin node: RocksDB storage, Merkle Tree, dHeavyHash PoW, p2p.py.

Run:
    python main.py [--port 8080] [--mine] [--data-dir PATH]

Without ``--mine`` the node only syncs/validates blocks received over
p2p.  With ``--mine`` it also mines blocks from the mempool.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import struct
import sys
import threading
import time
from dataclasses import dataclass, field

import blake3

import db
import p2p
import smartcontract
from dHeavyHash import dHeavyHash

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("dochacoin")

BLAKE3 = lambda x: blake3.blake3(x).digest()
ZERO_HASH = b"\x00" * 32
GENESIS_SENDER = b"\x00" * 20
BLOCK_INTERVAL = 10  # seconds between blocks (target)
MAX_TXS_PER_BLOCK = 1000
INITIAL_TARGET = 1 << 248  # ~8 leading zero bits; retargeted every 10 blocks
RETARGET_INTERVAL = 10
MIN_TARGET = 1 << 200
MAX_TARGET = 1 << 252


# ---------------------------------------------------------------------------
# Transactions
# ---------------------------------------------------------------------------

@dataclass
class Transaction:
    sender: bytes
    receiver: bytes
    amount: int
    additional_info: bytes = b""
    # kind: 0 = transfer, 1 = contract deploy, 2 = contract call
    kind: int = 0
    gas: int = 0
    data: bytes = b""  # bytecode (deploy) or calldata words (call)

    def serialize(self) -> bytes:
        return (
            bytes(self.sender).ljust(20, b"\x00")[:20]
            + bytes(self.receiver).ljust(20, b"\x00")[:20]
            + int(self.amount).to_bytes(32, "big", signed=self.amount < 0)
            + bytes([self.kind & 0xFF])
            + int(self.gas).to_bytes(8, "big")
            + len(self.additional_info).to_bytes(4, "big")
            + bytes(self.additional_info)
            + len(self.data).to_bytes(4, "big")
            + bytes(self.data)
        )

    @classmethod
    def deserialize(cls, raw: bytes) -> "Transaction":
        if len(raw) < 20 + 20 + 32 + 1 + 8 + 4 + 4:
            raise ValueError("transaction too short")
        off = 0
        sender, receiver = raw[off:off + 20], raw[off + 20:off + 40]
        off += 40
        amount = int.from_bytes(raw[off:off + 32], "big", signed=True)
        off += 32
        kind = raw[off]
        off += 1
        gas = int.from_bytes(raw[off:off + 8], "big")
        off += 8
        info_len = int.from_bytes(raw[off:off + 4], "big")
        off += 4
        info = raw[off:off + info_len]
        off += info_len
        data_len = int.from_bytes(raw[off:off + 4], "big")
        off += 4
        data = raw[off:off + data_len]
        if len(info) != info_len or len(data) != data_len:
            raise ValueError("transaction truncated")
        return cls(sender, receiver, amount, info, kind, gas, data)

    def hash(self) -> bytes:
        return BLAKE3(self.serialize())

    def to_dict(self) -> dict:
        return {
            "sender": self.sender.hex(),
            "receiver": self.receiver.hex(),
            "amount": self.amount,
            "additional_info": self.additional_info.hex(),
            "kind": self.kind,
            "gas": self.gas,
            "data": self.data.hex(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Transaction":
        return cls(
            sender=bytes.fromhex(d.get("sender", "")),
            receiver=bytes.fromhex(d.get("receiver", "")),
            amount=int(d.get("amount", 0)),
            additional_info=bytes.fromhex(d.get("additional_info", "")),
            kind=int(d.get("kind", 0)),
            gas=int(d.get("gas", 0)),
            data=bytes.fromhex(d.get("data", "")),
        )


# ---------------------------------------------------------------------------
# Merkle Tree (BLAKE3, sorted pairs, odd nodes promoted)
# ---------------------------------------------------------------------------

def _leaf_hash(data: bytes) -> bytes:
    return BLAKE3(b"\x00" + data)


def _node_hash(left: bytes, right: bytes) -> bytes:
    if left > right:
        left, right = right, left
    return BLAKE3(b"\x01" + left + right)


def merkle_root(leaves: list[bytes]) -> bytes:
    """Merkle root of raw leaf payloads; empty tree -> ZERO_HASH."""
    if not leaves:
        return ZERO_HASH
    level = [_leaf_hash(x) for x in leaves]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_node_hash(level[i], level[i + 1]))
            else:
                nxt.append(level[i])
        level = nxt
    return level[0]


def merkle_proof(leaves: list[bytes], index: int) -> list[bytes]:
    """Inclusion proof for ``leaves[index]`` (sibling hashes, bottom-up)."""
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index out of range")
    level = [_leaf_hash(x) for x in leaves]
    proof: list[bytes] = []
    idx = index
    while len(level) > 1:
        sibling = idx ^ 1
        if sibling < len(level):
            proof.append(level[sibling])
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_node_hash(level[i], level[i + 1]))
            else:
                nxt.append(level[i])
        level = nxt
        idx //= 2
    return proof


def verify_proof(leaf: bytes, proof: list[bytes], index: int, root: bytes) -> bool:
    current = _leaf_hash(leaf)
    idx = index
    for sibling in proof:
        current = _node_hash(current, sibling)
        idx //= 2
    return current == root


# ---------------------------------------------------------------------------
# Blocks
# ---------------------------------------------------------------------------

@dataclass
class Block:
    transactions: list[Transaction] = field(default_factory=list)
    previous_hash: bytes = ZERO_HASH
    nonce: int = 0
    target: int = INITIAL_TARGET
    timestamp: int = 0
    merkle_root: bytes = ZERO_HASH
    height: int = 0

    def header_bytes(self) -> bytes:
        return (
            bytes(self.previous_hash).ljust(32, b"\x00")[:32]
            + bytes(self.merkle_root).ljust(32, b"\x00")[:32]
            + int(self.timestamp).to_bytes(8, "big")
            + int(self.nonce).to_bytes(8, "big")
            + int(self.target).to_bytes(32, "big")
            + int(self.height).to_bytes(8, "big")
        )

    def hash(self) -> bytes:
        return dHeavyHash(self.header_bytes())

    def serialize(self) -> bytes:
        out = [self.header_bytes(), len(self.transactions).to_bytes(4, "big")]
        for tx in self.transactions:
            raw = tx.serialize()
            out.append(len(raw).to_bytes(4, "big"))
            out.append(raw)
        return b"".join(out)

    @classmethod
    def deserialize(cls, raw: bytes) -> "Block":
        if len(raw) < 32 + 32 + 8 + 8 + 32 + 8 + 4:
            raise ValueError("block too short")
        off = 0
        previous_hash = raw[off:off + 32]
        off += 32
        root = raw[off:off + 32]
        off += 32
        timestamp = int.from_bytes(raw[off:off + 8], "big")
        off += 8
        nonce = int.from_bytes(raw[off:off + 8], "big")
        off += 8
        target = int.from_bytes(raw[off:off + 32], "big")
        off += 32
        height = int.from_bytes(raw[off:off + 8], "big")
        off += 8
        count = int.from_bytes(raw[off:off + 4], "big")
        off += 4
        txs = []
        for _ in range(count):
            if off + 4 > len(raw):
                raise ValueError("block truncated")
            tx_len = int.from_bytes(raw[off:off + 4], "big")
            off += 4
            txs.append(Transaction.deserialize(raw[off:off + tx_len]))
            off += tx_len
        return cls(txs, previous_hash, nonce, target, timestamp, root, height)

    def to_dict(self) -> dict:
        return {
            "transactions": [tx.to_dict() for tx in self.transactions],
            "previous_hash": self.previous_hash.hex(),
            "nonce": self.nonce,
            "target": self.target,
            "timestamp": self.timestamp,
            "merkle_root": self.merkle_root.hex(),
            "height": self.height,
            "hash": self.hash().hex(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Block":
        return cls(
            transactions=[Transaction.from_dict(t) for t in d.get("transactions", [])],
            previous_hash=bytes.fromhex(d.get("previous_hash", "")) or ZERO_HASH,
            nonce=int(d.get("nonce", 0)),
            target=int(d.get("target", INITIAL_TARGET)),
            timestamp=int(d.get("timestamp", 0)),
            merkle_root=bytes.fromhex(d.get("merkle_root", "")) or ZERO_HASH,
            height=int(d.get("height", 0)),
        )


def compute_target(height: int, prev_block: Block | None) -> int:
    """Difficulty retarget every RETARGET_INTERVAL blocks."""
    if height == 0 or prev_block is None:
        return INITIAL_TARGET
    if height % RETARGET_INTERVAL != 0:
        return prev_block.target
    first = load_block(height - RETARGET_INTERVAL)
    if first is None:
        return prev_block.target
    actual = max(1, prev_block.timestamp - first.timestamp)
    expected = RETARGET_INTERVAL * BLOCK_INTERVAL
    target = prev_block.target * actual // expected
    return max(MIN_TARGET, min(MAX_TARGET, target))


def mine_block(block: Block) -> Block:
    """Search a nonce whose dHeavyHash is below the target."""
    block.merkle_root = merkle_root([tx.serialize() for tx in block.transactions])
    nonce = 0
    while True:
        block.nonce = nonce
        if int.from_bytes(block.hash(), "big") < block.target:
            return block
        nonce += 1


def validate_block(block: Block, prev_block: Block | None) -> bool:
    if block.merkle_root != merkle_root([tx.serialize() for tx in block.transactions]):
        return False
    if int.from_bytes(block.hash(), "big") >= block.target:
        return False
    if prev_block is not None:
        if block.previous_hash != prev_block.hash():
            return False
        if block.height != prev_block.height + 1:
            return False
        if block.target != compute_target(block.height, prev_block):
            return False
    return True


# ---------------------------------------------------------------------------
# Chain state
# ---------------------------------------------------------------------------

blockchain: list[Block] = []
mempool: list[Transaction] = []
_lock = threading.RLock()


def load_block(height: int) -> Block | None:
    raw = db.readblock(height)
    return Block.deserialize(raw) if raw is not None else None


def loadblockchain() -> None:
    """Load the chain from RocksDB into memory."""
    blockchain.clear()
    height = 0
    while True:
        block = load_block(height)
        if block is None:
            break
        blockchain.append(block)
        height += 1
    log.info("Loaded %d blocks (tip height %d)", len(blockchain), db.get_height())


def _apply_transactions(block: Block) -> tuple[dict, dict]:
    """Execute block transactions; returns (storage writes, code writes)."""
    storage: dict = {}
    code: dict = {}

    def reader(key: bytes) -> int:
        return storage.get(key, db.readbc(key))

    for tx in block.transactions:
        if tx.kind == 1:  # deploy
            address = smartcontract.contract_address(tx.data)
            code[address] = bytes(tx.data)
        elif tx.kind == 2:  # contract call
            bytecode = code.get(tx.receiver, db.read_code(tx.receiver))
            if bytecode is None:
                continue
            args = [
                int.from_bytes(tx.data[i:i + 32], "big")
                for i in range(0, len(tx.data) - 31, 32)
            ]
            result = smartcontract.execute_contract(
                bytecode, tx.receiver, tx.sender, args, tx.gas or 100_000, reader
            )
            if result.success:
                storage.update(result.writes)
        else:  # plain transfer: sender balance -= amount, receiver += amount
            sender_key = bytes(tx.sender).ljust(32, b"\x00")[:32]
            receiver_key = bytes(tx.receiver).ljust(32, b"\x00")[:32]
            sender_bal = storage.get(sender_key, db.readbc(sender_key))
            receiver_bal = storage.get(receiver_key, db.readbc(receiver_key))
            if sender_bal < tx.amount:
                continue
            storage[sender_key] = sender_bal - tx.amount
            storage[receiver_key] = receiver_bal + tx.amount
    return storage, code


def add_block(block: Block) -> bool:
    """Validate and append a block; persists it atomically with its writes."""
    with _lock:
        prev = blockchain[-1] if blockchain else None
        if prev is not None and block.height <= prev.height:
            return False
        if not validate_block(block, prev):
            return False
        storage, code = _apply_transactions(block)
        db.commit_block(block.height, block.serialize(), block.hash(), storage, code)
        blockchain.append(block)
        # Drop included transactions from the mempool
        included = {tx.hash() for tx in block.transactions}
        mempool[:] = [tx for tx in mempool if tx.hash() not in included]
        log.info("Block %d accepted (%d txs)", block.height, len(block.transactions))
        return True


def create_genesis() -> Block:
    """Create (and persist) the genesis block if the chain is empty."""
    if db.get_height() >= 0:
        return load_block(db.get_height())
    block = Block(
        transactions=[],
        previous_hash=ZERO_HASH,
        target=INITIAL_TARGET,
        timestamp=int(time.time()),
        height=0,
    )
    mine_block(block)
    db.commit_block(0, block.serialize(), block.hash())
    blockchain.append(block)
    log.info("Genesis block created")
    return block


def add_transaction(tx: Transaction) -> bool:
    with _lock:
        if any(t.hash() == tx.hash() for t in mempool):
            return False
        mempool.append(tx)
        return True


def mine_once() -> Block | None:
    """Mine one block from the mempool (used by --mine and tests)."""
    with _lock:
        prev = blockchain[-1] if blockchain else None
        height = (prev.height + 1) if prev else 0
        txs = list(mempool[:MAX_TXS_PER_BLOCK])
        block = Block(
            transactions=txs,
            previous_hash=prev.hash() if prev else ZERO_HASH,
            target=compute_target(height, prev),
            timestamp=int(time.time()),
            height=height,
        )
        mine_block(block)
        if add_block(block):
            p2p.broadcast_block(block.to_dict())
            return block
        return None


# ---------------------------------------------------------------------------
# p2p callbacks (p2p.py speaks JSON dicts)
# ---------------------------------------------------------------------------

def on_tx_received(tx_data: dict) -> bool:
    try:
        tx = Transaction.from_dict(tx_data)
    except (ValueError, TypeError):
        return False
    return add_transaction(tx)


def on_block_received(block_data: dict) -> bool:
    try:
        block = Block.from_dict(block_data)
    except (ValueError, TypeError):
        return False
    return add_block(block)


async def _miner_loop() -> None:
    while True:
        await asyncio.sleep(BLOCK_INTERVAL)
        try:
            mine_once()
        except Exception:
            log.exception("Mining failed")


async def _run(port: int, mine: bool) -> None:
    tasks = [asyncio.create_task(p2p.start_network(port, on_tx_received, on_block_received))]
    if mine:
        tasks.append(asyncio.create_task(_miner_loop()))
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        pass
    finally:
        await p2p.shutdown()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Dochacoin node")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--mine", action="store_true", help="mine blocks from the mempool")
    parser.add_argument("--data-dir", default=None, help="RocksDB path (overrides DOCHACOIN_DB_PATH)")
    args = parser.parse_args(argv)

    if args.data_dir:
        import os
        os.environ["DOCHACOIN_DB_PATH"] = args.data_dir
        db.DB_PATH = args.data_dir

    loadblockchain()
    if not blockchain:
        create_genesis()

    try:
        asyncio.run(_run(args.port, args.mine))
    except KeyboardInterrupt:
        pass
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
