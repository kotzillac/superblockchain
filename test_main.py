# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for db (RocksDB), smartcontract (DVM) and main (Merkle/blocks).

Run:  python -m unittest test_main -v
"""

import os
import tempfile
import unittest

os.environ["DOCHACOIN_DB_PATH"] = tempfile.mkdtemp(prefix="dochacoin-test-")

import db
import main
import smartcontract as sc


def counter_code() -> bytes:
    """Contract: storage[0] += 1; return storage[0]."""
    return sc.assemble(
        sc.addi(sc.A0, sc.ZERO, sc.SYS_SLOAD),
        sc.addi(sc.A1, sc.ZERO, 0),
        sc.ecall(),
        sc.addi(sc.A0, sc.A0, 1),
        sc.addi(sc.S0, sc.A0, 0),
        sc.addi(sc.A0, sc.ZERO, sc.SYS_SSTORE),
        sc.addi(sc.A1, sc.ZERO, 0),
        sc.addi(sc.A2, sc.S0, 0),
        sc.ecall(),
        sc.addi(sc.A0, sc.S0, 0),
        sc.halt(),
    )


class TestDB(unittest.TestCase):
    def setUp(self):
        db.close()
        self.tmp = tempfile.mkdtemp(prefix="dochacoin-db-")
        db.DB_PATH = self.tmp

    def tearDown(self):
        db.close()

    def test_storage_roundtrip(self):
        db.writebc(b"key", 12345)
        self.assertEqual(db.readbc(b"key"), 12345)
        self.assertEqual(db.readbc(b"missing"), 0)

    def test_block_roundtrip(self):
        db.writeblock(3, b"blockdata")
        self.assertEqual(db.readblock(3), b"blockdata")
        self.assertIsNone(db.readblock(4))

    def test_code_roundtrip(self):
        db.write_code(b"\x01" * 20, b"code")
        self.assertEqual(db.read_code(b"\x01" * 20), b"code")

    def test_commit_block_atomic(self):
        db.commit_block(0, b"genesis", b"\xaa" * 32, {b"k": 7})
        self.assertEqual(db.get_height(), 0)
        self.assertEqual(db.get_tip_hash(), b"\xaa" * 32)
        self.assertEqual(db.readbc(b"k"), 7)
        self.assertEqual(db.readblock(0), b"genesis")

    def test_many(self):
        db.writebc_many({b"a": 1, b"b": 2})
        self.assertEqual(db.readbc_many([b"a", b"b", b"c"]), {b"a": 1, b"b": 2, b"c": 0})


class TestMerkle(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(main.merkle_root([]), main.ZERO_HASH)

    def test_proofs(self):
        leaves = [b"leaf-%d" % i for i in range(7)]
        root = main.merkle_root(leaves)
        for i, leaf in enumerate(leaves):
            self.assertTrue(main.verify_proof(leaf, main.merkle_proof(leaves, i), i, root))

    def test_tamper_fails(self):
        leaves = [b"a", b"b"]
        root = main.merkle_root(leaves)
        self.assertFalse(main.verify_proof(b"evil", main.merkle_proof(leaves, 0), 0, root))


class TestContracts(unittest.TestCase):
    def test_counter(self):
        store = {}
        code = counter_code()
        addr, caller = b"\x11" * 20, b"\x22" * 20
        r1 = sc.execute_contract(code, addr, caller, reader=lambda k: store.get(k, 0))
        self.assertTrue(r1.success)
        self.assertEqual(r1.result, 1)
        store.update(r1.writes)
        r2 = sc.execute_contract(code, addr, caller, reader=lambda k: store.get(k, 0))
        self.assertEqual(r2.result, 2)

    def test_revert_discards_writes(self):
        code = sc.assemble(
            sc.addi(sc.A0, sc.ZERO, sc.SYS_SSTORE),
            sc.addi(sc.A1, sc.ZERO, 0),
            sc.addi(sc.A2, sc.ZERO, 9),
            sc.ecall(),
            sc.addi(sc.A0, sc.ZERO, sc.SYS_REVERT),
            sc.ecall(),
            sc.halt(),
        )
        r = sc.execute_contract(code, b"\x11" * 20, b"\x22" * 20, reader=lambda k: 0)
        self.assertFalse(r.success)
        self.assertEqual(r.writes, {})

    def test_getarg(self):
        code = sc.assemble(
            sc.addi(sc.A0, sc.ZERO, sc.SYS_GETARG),
            sc.addi(sc.A1, sc.ZERO, 0),
            sc.ecall(),
            sc.halt(),
        )
        r = sc.execute_contract(code, b"\x11" * 20, b"\x22" * 20, args=[777], reader=lambda k: 0)
        self.assertEqual(r.result, 777)

    def test_out_of_gas(self):
        r = sc.execute_contract(counter_code(), b"\x11" * 20, b"\x22" * 20, gas=1, reader=lambda k: 0)
        self.assertFalse(r.success)


class TestChain(unittest.TestCase):
    def setUp(self):
        db.close()
        db.DB_PATH = tempfile.mkdtemp(prefix="dochacoin-chain-")
        main.blockchain.clear()
        main.mempool.clear()

    def tearDown(self):
        db.close()

    def test_genesis_and_mine(self):
        main.loadblockchain()
        genesis = main.create_genesis()
        self.assertEqual(genesis.height, 0)
        self.assertTrue(main.validate_block(genesis, None))
        tx = main.Transaction(b"\x01" * 20, b"\x02" * 20, 5)
        self.assertTrue(main.add_transaction(tx))
        block = main.mine_once()
        self.assertIsNotNone(block)
        self.assertEqual(block.height, 1)
        self.assertEqual(db.get_height(), 1)
        self.assertEqual(len(main.mempool), 0)

    def test_tx_block_roundtrip(self):
        tx = main.Transaction(b"\x01" * 20, b"\x02" * 20, 100, b"info", 2, 5000, b"\x00" * 32)
        tx2 = main.Transaction.deserialize(tx.serialize())
        self.assertEqual(tx2.amount, 100)
        self.assertEqual(tx2.data, tx.data)
        block = main.Block(transactions=[tx], height=1, timestamp=1)
        block2 = main.Block.deserialize(block.serialize())
        self.assertEqual(len(block2.transactions), 1)
        self.assertEqual(block2.transactions[0].hash(), tx.hash())

    def test_contract_deploy_and_call_in_block(self):
        main.loadblockchain()
        main.create_genesis()
        code = counter_code()
        deploy = main.Transaction(b"\x01" * 20, b"\x00" * 20, 0, kind=1, data=code)
        main.add_transaction(deploy)
        main.mine_once()
        address = sc.contract_address(code)
        self.assertEqual(db.read_code(address), code)
        call = main.Transaction(b"\x01" * 20, address, 0, kind=2, gas=100_000)
        main.add_transaction(call)
        main.mine_once()
        key = sc.storage_key(address, 0)
        self.assertEqual(db.readbc(key), 1)


if __name__ == "__main__":
    unittest.main()
