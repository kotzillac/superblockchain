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