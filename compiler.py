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
import re
from pathlib import Path
from typing import NamedTuple


class CompileError(ValueError):
    pass


class Program(NamedTuple):
    code: bytes
    codemap: dict[int, int]


class _Operand(NamedTuple):
    kind: str
    value: int | str


class _Jump(NamedTuple):
    opcode: int
    target: _Operand
    line: int


OP = {
    "NOP": 0,
    "ADD": 1,
    "SUB": 2,
    "MUL": 3,
    "DIV": 4,
    "RET": 5,
    "JMP": 6,
    "CMP": 7,
    "CMH": 8,
    "CML": 9,
    "LOAD": 10,
    "STORE": 11,
    "JE": 12,
    "JNE": 13,
    "SSTORE": 14,
    "SLOAD": 15,
    "PUSH": 16,
    "POP": 17,
    "MOV": 99,  # opcode not implemented yet
}

# data ops are written as "OP source, destination"
# CMH/CML compare "first > second" / "first < second"
# jump targets are 1-based source lines or labels

ALIASES = {
    "GSPEC": "GET_SPECIAL",
    "SSLOAD": "SLOAD",
    "JZ": "JE",
    "JNZ": "JNE",
}

_IMM_RE = re.compile(r"[+-]?(?:0[xX][0-9a-fA-F]+|\d+)\Z")
_LABEL_RE = re.compile(r"[A-Za-z_.][A-Za-z0-9_.]*\Z")
_REG_RE = re.compile(r"[Rr](\d+)\Z")
_SREG_RE = re.compile(r"[Ss](\d+)\Z")


def _pack(op: int, dest: int = 0, src: int = 0, const: int = 0) -> bytes:
    if not (0 <= op <= 0xFF and 0 <= dest <= 0xF and 0 <= src <= 0xF and 0 <= const <= 0xFFFF):
        raise CompileError("instruction word is out of range")
    return ((op << 24) | (dest << 20) | (src << 16) | const).to_bytes(4, "big")


def _parse_int(text: str, line: int) -> int:
    sign = 1
    if text[0] == "-":
        sign = -1
        text = text[1:]
    elif text[0] == "+":
        text = text[1:]
    if not text:
        raise CompileError(f"line {line}: bad immediate")
    if text.lower().startswith("0x"):
        return sign * int(text[2:], 16)
    return sign * int(text, 10)


class _Assembler:
    def __init__(self) -> None:
        self.consts: list[bytes] = []
        self.const_ids: dict[bytes, int] = {}
        self.instrs: list[bytes | _Jump] = []
        self.line_index: dict[int, int] = {}
        self.labels: dict[str, int] = {}
        self.functions: dict[int, tuple[int, int]] = {}
        self.line = 0

    def compile(self, source: str) -> Program:
        if source.startswith("\ufeff"):
            source = source[1:]
        for lineno, raw in enumerate(source.splitlines(), 1):
            self._add_line(raw, lineno)
        self._resolve_jumps()

        const_bytes = b"".join(self.consts)
        code = const_bytes + b"".join(self.instrs)  # type: ignore[arg-type]
        codemap = {0: len(const_bytes)}
        for selector, (index, _argc) in self.functions.items():
            if selector != 0:
                codemap[selector] = len(const_bytes) + 4 * index
        return Program(code, codemap)

    def _add_line(self, raw: str, lineno: int) -> None:
        self.line = lineno
        text = raw.split(";", 1)[0].strip()
        if not text:
            return

        while True:
            match = re.match(r"([A-Za-z_.][A-Za-z0-9_.]*):\s*(.*)\Z", text)
            if not match:
                break
            name = match.group(1)
            if name in self.labels:
                self._error(lineno, f"duplicate label {name}")
            self.labels[name] = len(self.instrs)
            self.line_index.setdefault(lineno, len(self.instrs))
            text = match.group(2).strip()
            if not text:
                return

        parts = text.split(None, 1)
        mnemonic = parts[0].upper()
        rest = parts[1].strip() if len(parts) > 1 else ""
        mnemonic = ALIASES.get(mnemonic, mnemonic)

        if mnemonic == "FUNC":
            self._func(rest, lineno)
            return

        self._gen(mnemonic, self._split(rest, lineno), lineno)

    def _split(self, rest: str, line: int) -> list[str]:
        if not rest:
            return []
        if "," in rest:
            operands = [part.strip() for part in rest.split(",")]
            if any(not part for part in operands):
                self._error(line, "empty operand")
            return operands
        return rest.split()

    def _func(self, rest: str, line: int) -> None:
        match = re.fullmatch(r"(\S+)\s*(?:\(\s*(\d+)\s*\))?", rest)
        if not match:
            self._error(line, "expected FUNC <selector> (<argc>)")
        selector_operand = self._operand(match.group(1), line)
        if selector_operand.kind != "imm":
            self._error(line, "function selector must be an immediate")
        selector = selector_operand.value
        if selector < 0:
            self._error(line, "function selector must be non-negative")
        if selector in self.functions:
            self._error(line, f"duplicate function {selector:#x}")
        if selector == 0 and self.instrs:
            self._error(line, "FUNC 0x00 must be the first function")
        self.functions[selector] = (len(self.instrs), int(match.group(2) or 0))
        self.line_index.setdefault(line, len(self.instrs))

    def _operand(self, text: str, line: int) -> _Operand:
        match = _REG_RE.fullmatch(text)
        if match:
            reg = int(match.group(1))
            if reg > 15:
                self._error(line, f"register R{reg} does not exist")
            return _Operand("reg", reg)

        match = _SREG_RE.fullmatch(text)
        if match:
            reg = int(match.group(1))
            if reg > 3:
                self._error(line, f"register S{reg} does not exist")
            return _Operand("reg", 12 + reg)  # S0..S3 are argument registers

        if _IMM_RE.fullmatch(text):
            return _Operand("imm", _parse_int(text, line))
        if _LABEL_RE.fullmatch(text):
            return _Operand("label", text)
        self._error(line, f"bad operand {text!r}")

    def _gen(self, mnemonic: str, operands: list[str], line: int) -> None:
        if mnemonic in {"ADD", "SUB", "MUL", "DIV"}:
            self._arith(mnemonic, operands, line)
        elif mnemonic in {"CMP", "CMH", "CML"}:
            self._compare(mnemonic, operands, line)
        elif mnemonic == "MOV":
            self._mov(operands, line)
        elif mnemonic == "LOAD":
            self._load(operands, line)
        elif mnemonic == "STORE":
            self._store(operands, line)
        elif mnemonic == "SLOAD":
            self._sload(operands, line)
        elif mnemonic == "SSTORE":
            self._sstore(operands, line)
        elif mnemonic == "PUSH":
            self._push(operands, line)
        elif mnemonic == "POP":
            self._pop(operands, line)
        elif mnemonic == "RET":
            self._ret(operands, line)
        elif mnemonic == "REVERT":
            self._expect(operands, 0, line, mnemonic)
            self.emit(OP["RET"], dest=0)  # revert is a failed return
        elif mnemonic in {"JMP", "JE", "JNE"}:
            self._jump(mnemonic, operands, line)
        elif mnemonic == "GET_SPECIAL":
            self._get_special(operands, line)
        elif mnemonic == "NOP":
            self._expect(operands, 0, line, mnemonic)
            self.emit(OP["NOP"])
        else:
            self._error(line, f"unknown mnemonic {mnemonic}")

    def _arith(self, mnemonic: str, operands: list[str], line: int) -> None:
        self._expect(operands, 2, line, mnemonic)
        source = self._operand(operands[0], line)
        dest = self._operand(operands[1], line)
        dest_reg = self._reg(dest, line, write=True)
        src_reg, const = self._source(source, line)
        self.emit(OP[mnemonic], dest=dest_reg, src=src_reg, const=const)

    def _source(self, operand: _Operand, line: int) -> tuple[int, int]:
        if operand.kind == "reg":
            if operand.value == 0:
                return 0, self.const_index(0, line)
            return operand.value, 0
        if operand.kind == "imm":
            return 0, self.const_index(operand.value, line)
        self._error(line, "expected register or immediate")

    def _compare(self, mnemonic: str, operands: list[str], line: int) -> None:
        self._expect(operands, 2, line, mnemonic)
        left = self._operand(operands[0], line)
        right = self._operand(operands[1], line)
        if left.kind == "label" or right.kind == "label":
            self._error(line, "labels are not allowed in comparisons")
        if mnemonic == "CMP":
            op, dest, src, const = self._cmp_eq(left, right, line)
        elif mnemonic == "CMH":
            op, dest, src, const = self._cmp_gt(left, right, line)
        else:
            op, dest, src, const = self._cmp_lt(left, right, line)
        self.emit(op, dest, src, const)

    def _cmp_eq(self, left: _Operand, right: _Operand, line: int) -> tuple[int, int, int, int]:
        lr, rr = self._reg_value(left), self._reg_value(right)
        li, ri = self._imm_value(left), self._imm_value(right)

        if lr is not None and rr is not None and lr != 0 and rr != 0:
            return OP["CMP"], lr, rr, 0
        if lr is not None and lr != 0 and ri is not None:
            return OP["CMP"], lr, 0, self.const_index(ri, line)
        if li is not None and rr is not None and rr != 0:
            return OP["CMP"], rr, 0, self.const_index(li, line)
        if lr is not None and rr is not None:
            if lr == 0 and rr == 0:
                return OP["CMP"], 0, 0, self.const_index(0, line)
            other = rr if lr == 0 else lr
            return OP["CMP"], other, 0, self.const_index(0, line)
        if li is not None and ri is not None:
            return OP["CMP"], 0, 0, self.const_index(0 if li == ri else 1, line)
        if lr == 0 and ri is not None:
            return OP["CMP"], 0, 0, self.const_index(ri, line)
        if li is not None and rr == 0:
            return OP["CMP"], 0, 0, self.const_index(li, line)
        self._error(line, "bad comparison operands")

    def _cmp_gt(self, left: _Operand, right: _Operand, line: int) -> tuple[int, int, int, int]:
        lr, rr = self._reg_value(left), self._reg_value(right)
        li, ri = self._imm_value(left), self._imm_value(right)

        if lr is not None and rr is not None:
            if lr == 0 and rr == 0:
                return self._cmp_bool(False, line)
            if lr == 0:
                return OP["CMH"], rr, 0, self.const_index(0, line)
            if rr == 0:
                return OP["CML"], lr, 0, self.const_index(0, line)
            return OP["CMH"], rr, lr, 0
        if lr is not None and ri is not None:
            if lr == 0:
                return self._cmp_bool(0 > ri, line)
            return OP["CML"], lr, 0, self.const_index(ri, line)
        if li is not None and rr is not None:
            if rr == 0:
                return self._cmp_bool(li > 0, line)
            return OP["CMH"], rr, 0, self.const_index(li, line)
        if li is not None and ri is not None:
            return self._cmp_bool(li > ri, line)
        self._error(line, "bad comparison operands")

    def _cmp_lt(self, left: _Operand, right: _Operand, line: int) -> tuple[int, int, int, int]:
        lr, rr = self._reg_value(left), self._reg_value(right)
        li, ri = self._imm_value(left), self._imm_value(right)

        if lr is not None and rr is not None:
            if lr == 0 and rr == 0:
                return self._cmp_bool(False, line)
            if lr == 0:
                return OP["CML"], rr, 0, self.const_index(0, line)
            if rr == 0:
                return OP["CMH"], lr, 0, self.const_index(0, line)
            return OP["CML"], rr, lr, 0
        if lr is not None and ri is not None:
            return OP["CMH"], lr, 0, self.const_index(ri, line)
        if li is not None and rr is not None:
            if rr == 0:
                return OP["CML"], 0, 0, self.const_index(li, line)
            return OP["CML"], rr, 0, self.const_index(li, line)
        if li is not None and ri is not None:
            return self._cmp_bool(li < ri, line)
        self._error(line, "bad comparison operands")

    def _cmp_bool(self, value: bool, line: int) -> tuple[int, int, int, int]:
        return OP["CMP"], 0, 0, self.const_index(0 if value else 1, line)

    def _mov(self, operands: list[str], line: int) -> None:
        self._expect(operands, 2, line, "MOV")
        source = self._operand(operands[0], line)
        dest = self._operand(operands[1], line)
        dest_reg = self._reg(dest, line, write=True)
        src_reg, const = self._source(source, line)
        self.emit(OP["MOV"], dest=dest_reg, src=src_reg, const=const)

    def _load(self, operands: list[str], line: int) -> None:
        self._expect(operands, 2, line, "LOAD")
        address = self._operand(operands[0], line)
        dest = self._operand(operands[1], line)
        dest_reg = self._reg(dest, line, write=True)
        src, const = self._stack_address(address, line)
        self.emit(OP["LOAD"], dest=dest_reg, src=src, const=const)

    def _store(self, operands: list[str], line: int) -> None:
        self._expect(operands, 2, line, "STORE")
        address = self._operand(operands[0], line)
        value = self._operand(operands[1], line)
        value_reg = self._reg(value, line, write=True)
        src, const = self._stack_address(address, line)
        self.emit(OP["STORE"], dest=value_reg, src=src, const=const)

    def _stack_address(self, operand: _Operand, line: int) -> tuple[int, int]:
        if operand.kind == "reg":
            return operand.value, 0
        if operand.kind == "imm":
            if not 0 <= operand.value < 32768:
                self._error(line, "stack address is outside 32768 slots")
            return 0, operand.value
        self._error(line, "stack address must be a register or immediate")

    def _sload(self, operands: list[str], line: int) -> None:
        self._expect(operands, 2, line, "SLOAD")
        key = self._operand(operands[0], line)
        dest = self._operand(operands[1], line)
        dest_reg = self._reg(dest, line, write=True)

        if key.kind == "reg":
            self.emit(OP["SLOAD"], dest=dest_reg, src=key.value)
        elif key.kind == "imm":
            self.emit(OP["SLOAD"], dest=dest_reg, const=key.value)
        else:
            self._error(line, "SLOAD key must be a register or immediate")

    def _sstore(self, operands: list[str], line: int) -> None:
        self._expect(operands, 2, line, "SSTORE")
        key = self._operand(operands[0], line)
        value = self._operand(operands[1], line)
        if key.kind != "reg" or value.kind != "reg":
            self._error(line, "SSTORE operands must be registers")
        self.emit(OP["SSTORE"], dest=value.value, src=key.value)

    def _push(self, operands: list[str], line: int) -> None:
        self._expect(operands, 1, line, "PUSH")
        operand = self._operand(operands[0], line)
        if operand.kind == "reg":
            self.emit(OP["PUSH"], src=operand.value)
        elif operand.kind == "imm":
            self._imm16(operand.value, line)
            self.emit(OP["PUSH"], const=operand.value)
        else:
            self._error(line, "PUSH needs a register or immediate")

    def _pop(self, operands: list[str], line: int) -> None:
        self._expect(operands, 1, line, "POP")
        dest = self._operand(operands[0], line)
        self.emit(OP["POP"], dest=self._reg(dest, line, write=True))

    def _ret(self, operands: list[str], line: int) -> None:
        if not operands:
            self.emit(OP["RET"], dest=0)
            return
        self._expect(operands, 1, line, "RET")
        operand = self._operand(operands[0], line)
        if operand.kind == "reg":
            self.emit(OP["RET"], dest=operand.value)
        elif operand.kind == "imm":
            if not 0 <= operand.value <= 15:
                self._error(line, "RET immediate must fit in 4 bits")
            self.emit(OP["RET"], dest=operand.value)
        else:
            self._error(line, "RET needs a register or immediate")

    def _jump(self, mnemonic: str, operands: list[str], line: int) -> None:
        self._expect(operands, 1, line, mnemonic)
        target = self._operand(operands[0], line)
        if target.kind == "reg":
            self._error(line, "jump target must be a line number or label")
        if target.kind == "imm" and target.value < 1:
            self._error(line, "line number must be positive")
        self.line_index.setdefault(line, len(self.instrs))
        self.instrs.append(_Jump(OP[mnemonic], target, line))

    def _get_special(self, operands: list[str], line: int) -> None:
        self._expect(operands, 2, line, "GET_SPECIAL")
        # opcode is not implemented yet; keep the syntax and emit nothing
        self.line_index.setdefault(line, len(self.instrs))

    def _resolve_jumps(self) -> None:
        resolved: list[bytes] = []
        for item in self.instrs:
            if isinstance(item, _Jump):
                target = self._target_index(item.target, item.line)
                resolved.append(_pack(item.opcode, const=target))
            else:
                resolved.append(item)
        self.instrs = resolved

    def _target_index(self, target: _Operand, line: int) -> int:
        if target.kind == "label":
            if target.value not in self.labels:
                self._error(line, f"unknown label {target.value}")
            index = self.labels[target.value]
        else:
            line_no = target.value
            if line_no in self.line_index:
                index = self.line_index[line_no]
            else:
                later = [number for number in self.line_index if number > line_no]
                if not later:
                    self._error(line, f"no instruction after line {line_no}")
                index = self.line_index[min(later)]
        if not 0 <= index <= 0xFFFF:
            self._error(line, "jump target is too far")
        return index

    def emit(self, op: int, dest: int = 0, src: int = 0, const: int = 0) -> None:
        self.line_index.setdefault(self.line, len(self.instrs))
        self.instrs.append(_pack(op, dest, src, const))

    def const_index(self, value: int, line: int) -> int:
        if value < 0:
            if value < -(1 << 255):
                self._error(line, "constant does not fit in 256 bits")
            data = value.to_bytes(32, "big", signed=True)
        else:
            if value >= (1 << 256):
                self._error(line, "constant does not fit in 256 bits")
            data = value.to_bytes(32, "big")
        index = self.const_ids.get(data)
        if index is None:
            if len(self.consts) >= 0x10000:
                self._error(line, "too many constants")
            index = len(self.consts)
            self.const_ids[data] = index
            self.consts.append(data)
        return index

    def _reg(self, operand: _Operand, line: int, write: bool = False) -> int:
        if operand.kind != "reg":
            self._error(line, "expected register")
        reg = operand.value
        if write and not 1 <= reg <= 11:
            self._error(line, f"register {reg} is not writable")
        return reg

    @staticmethod
    def _reg_value(operand: _Operand) -> int | None:
        return operand.value if operand.kind == "reg" else None

    @staticmethod
    def _imm_value(operand: _Operand) -> int | None:
        return operand.value if operand.kind == "imm" else None

    def _imm16(self, value: int, line: int) -> None:
        if not 0 <= value <= 0xFFFF:
            self._error(line, "immediate does not fit in 16 bits")

    def _expect(self, operands: list[str], count: int, line: int, mnemonic: str) -> None:
        if len(operands) != count:
            self._error(line, f"{mnemonic} expects {count} operand(s)")

    @staticmethod
    def _error(line: int, message: str):
        raise CompileError(f"line {line}: {message}")


def compile_source(source: str) -> Program:
    return _Assembler().compile(source)


def compile_file(path: str | Path) -> Program:
    return compile_source(Path(path).read_text(encoding="utf-8-sig"))


def assemble(source: str) -> bytes:
    return compile_source(source).code


def assemble_file(path: str | Path) -> bytes:
    return compile_file(path).code


compile = compile_source


def main() -> None:
    import sys

    if len(sys.argv) < 2:
        raise SystemExit("usage: python compiler.py <file.scd>")
    c = compile_file(sys.argv[1])
    if len(sys.argv) >= 3:
            Path(sys.argv[2]).write_bytes(c.code)
    print(c.code.hex())
    print("Code Map:  ", c.codemap)


if __name__ == "__main__":
    main()
