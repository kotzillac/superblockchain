# SPDX-License-Identifier: GPL-3.0-or-later


from dataclasses import dataclass

import blake3
import p2p
import db

BLAKE3 = lambda x: blake3.blake3(x).digest()


@dataclass
class Transaction:
    sender: bytes
    receiver: bytes
    amount: int
    additional_info: bytes

@dataclass
class Block:
    tranasctions: list[Transaction]
    previous_hash: bytes
    nonce: int
    target: int
    timestamp: int

blockchain: list[Block] = []
mempool = list[Transaction]

def loadblockchain():
    c = 0
    while True:
        block = db.readblock(c)
        if block is None:
            break
        blockchain.append(block)
        c += 1

if __name__ == "__main__":
    loadblockchain()