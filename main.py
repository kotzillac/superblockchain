import hashlib
from dataclasses import dataclass


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

