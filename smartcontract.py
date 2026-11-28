# SPDX-License-Identifier: GPL-3.0-or-later

"""Smart-contract execution on top of the DVM (RV32I) interpreter.

Contracts are plain RV32I bytecode executed by ``dvm.execute``.  The VM
talks to the outside world only through ECALL syscalls: the contract
places a syscall number in ``a0`` (x10), up to three arguments in
``a1``..``a3`` (x11..x13) and a 64-byte buffer pointer in ``a4`` (x14);
the handler returns ``(response, result)`` where ``response`` (up to
64 bytes) is copied into the buffer and ``result`` becomes the new
``a0``.  This module implements the host side of that protocol.

Syscall numbers (``a0``):

    1  SLOAD   a1 = key (256-bit)            -> a0 = value (256-bit)
    2  SSTORE  a1 = key, a2 = value          -> a0 = 1 on success
    3  CALLER  -> a0 = caller address (160-bit)
    4  ADDRESS -> a0 = this contract address (160-bit)
    5  GETARG  a1 = index                    -> a0 = argument (256-bit)
    6  REVERT  -> aborts the call, storage writes are discarded

Storage is namespaced per contract: the on-chain key is
``BLAKE3(address || key)`` so contracts cannot collide with each other
or with plain balance slots.  All writes go to an in-memory overlay
that is only flushed to RocksDB (via ``db.writebc_many``) when the
call succeeds; a revert or out-of-gas discards them.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

import blake3
import dvm
import db

# Syscall numbers
SYS_SLOAD = 1
SYS_SSTORE = 2
SYS_CALLER = 3
SYS_ADDRESS = 4
SYS_GETARG = 5
SYS_REVERT = 6

DEFAULT_GAS = 100_000
MASK256 = (1 << 256) - 1
MASK160 = (1 << 160) - 1


def _blake3(data: bytes) -> bytes:
    return blake3.blake3(data).digest()


def storage_key(address: bytes, key: int) -> bytes:
    """Namespaced storage key for ``key`` of the contract at ``address``."""
    return _blake3(bytes(address) + (key & MASK256).to_bytes(32, "big"))


def contract_address(code: bytes) -> bytes:
    """Deterministic 20-byte address derived from the contract bytecode."""
    return _blake3(b"dochacoin:contract:" + bytes(code))[:20]


class Revert(Exception):
    """Raised inside a syscall handler to abort the current call."""


@dataclass
class CallResult:
    success: bool
    result: int | None
    gas_used: int
    writes: dict = field(default_factory=dict)
    return_data: bytes = b""


class _Host:
    """Syscall handler bound to one contract call."""

    def __init__(self, address: bytes, caller: bytes, args: list[int],
                 overlay: dict, reader):
        self.address = bytes(address)
        self.caller = bytes(caller)
        self.args = args
        self.overlay = overlay
        self.reader = reader  # callable(key_bytes) -> int

    def __call__(self, a0: int, a1: int, a2: int, a3: int,
                 buf: bytes) -> tuple[bytes | None, int]:
        if a0 == SYS_SLOAD:
            key = storage_key(self.address, a1 & MASK256)
            value = self.overlay.get(key, self.reader(key))
            return (value.to_bytes(32, "big"), value)
        if a0 == SYS_SSTORE:
            key = storage_key(self.address, a1 & MASK256)
            self.overlay[key] = a2 & MASK256
            return (None, 1)
        if a0 == SYS_CALLER:
            value = int.from_bytes(self.caller, "big")
            return (value.to_bytes(32, "big"), value)
        if a0 == SYS_ADDRESS:
            value = int.from_bytes(self.address, "big")
            return (value.to_bytes(32, "big"), value)
        if a0 == SYS_GETARG:
            value = self.args[a1] if 0 <= a1 < len(self.args) else 0
            return (value.to_bytes(32, "big"), value)
        if a0 == SYS_REVERT:
            raise Revert()
        return (None, 0)


def execute_contract(code: bytes, address: bytes, caller: bytes,
                     args: list[int] | None = None, gas: int = DEFAULT_GAS,
                     reader=None) -> CallResult:
    """Run ``code`` as the contract at ``address`` on behalf of ``caller``.

    ``reader`` maps a namespaced storage key (bytes) to its current
    256-bit value; by default it reads from RocksDB via ``db.readbc``.
    On success the returned ``writes`` dict holds the storage changes
    to persist; on revert/out-of-gas it is empty.
    """
    if reader is None:
        reader = db.readbc
    overlay: dict = {}
    host = _Host(address, caller, list(args or []), overlay, reader)
    try:
        result, gas_left = dvm.execute(bytes(code), gas, host)
    except Revert:
        return CallResult(False, None, gas, {})
    if result is None:
        return CallResult(False, None, gas - gas_left, {})
    return CallResult(True, result, gas - gas_left, dict(overlay))


def deploy_contract(code: bytes, caller: bytes) -> bytes:
    """Deploy ``code`` and persist it; returns the contract address."""
    address = contract_address(code)
    db.write_code(address, bytes(code))
    return address


def call_contract(address: bytes, caller: bytes, args: list[int] | None = None,
                  gas: int = DEFAULT_GAS) -> CallResult:
    """Call the contract stored at ``address`` and persist its writes."""
    code = db.read_code(address)
    if code is None:
        return CallResult(False, None, gas, {})
    result = execute_contract(code, address, caller, args, gas)
    if result.success and result.writes:
        db.writebc_many(result.writes)
    return result


# ---------------------------------------------------------------------------
# Minimal RV32I assembler used by the tests (and handy for examples).
# Only the instructions needed to write small contracts are provided.
# ---------------------------------------------------------------------------

def _r(funct7: int, rs2: int, rs1: int, funct3: int, rd: int, opcode: int) -> int:
    return (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode


def _i(imm: int, rs1: int, funct3: int, rd: int, opcode: int) -> int:
    return ((imm & 0xFFF) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode


def _s(imm: int, rs2: int, rs1: int, funct3: int, opcode: int) -> int:
    return (((imm >> 5) & 0x7F) << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | ((imm & 0x1F) << 7) | opcode


def _b(imm: int, rs2: int, rs1: int, funct3: int, opcode: int) -> int:
    return (((imm >> 12) & 1) << 31) | (((imm >> 5) & 0x3F) << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (((imm >> 1) & 0xF) << 8) | (((imm >> 11) & 1) << 7) | opcode


def _u(imm20: int, rd: int, opcode: int) -> int:
    return ((imm20 & 0xFFFFF) << 12) | (rd << 7) | opcode


def _j(imm: int, rd: int, opcode: int) -> int:
    return (((imm >> 20) & 1) << 31) | (((imm >> 1) & 0x3FF) << 21) | (((imm >> 11) & 1) << 20) | (((imm >> 12) & 0xFF) << 12) | (rd << 7) | opcode


def assemble(*words: int) -> bytes:
    return b"".join(struct.pack("<I", w & 0xFFFFFFFF) for w in words)


# Register aliases (RV32I ABI)
ZERO, RA, SP, GP, TP = 0, 1, 2, 3, 4
T0, T1, T2 = 5, 6, 7
S0, S1 = 8, 9
A0, A1, A2, A3, A4, A5, A6, A7 = 10, 11, 12, 13, 14, 15, 16, 17
S2, S3, S4, S5, S6, S7, S8, S9, S10, S11 = 18, 19, 20, 21, 22, 23, 24, 25, 26, 27
T3, T4, T5, T6 = 28, 29, 30, 31

OP_IMM, OP_OP, OP_LOAD, OP_STORE, OP_BRANCH, OP_JAL, OP_JALR, OP_LUI = (
    0b0010011, 0b0110011, 0b0000011, 0b0100011, 0b1100011, 0b1101111, 0b1100111, 0b0110111,
)


def addi(rd: int, rs1: int, imm: int) -> int:
    return _i(imm, rs1, 0b000, rd, OP_IMM)


def add(rd: int, rs1: int, rs2: int) -> int:
    return _r(0x00, rs2, rs1, 0b000, rd, OP_OP)


def sub(rd: int, rs1: int, rs2: int) -> int:
    return _r(0x20, rs2, rs1, 0b000, rd, OP_OP)


def beq(rs1: int, rs2: int, imm: int) -> int:
    return _b(imm, rs2, rs1, 0b000, OP_BRANCH)


def bne(rs1: int, rs2: int, imm: int) -> int:
    return _b(imm, rs2, rs1, 0b001, OP_BRANCH)


def jal(rd: int, imm: int) -> int:
    return _j(imm, rd, OP_JAL)


def ecall() -> int:
    return 0x00000073


def ret() -> int:
    return jal(ZERO, 0)  # jump to self == halt for our purposes is wrong; use jalr to 0?


def halt() -> int:
    """Jump past the end of the code: DVM treats pc == code_len as normal exit."""
    return jal(ZERO, 4)
