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
from collections.abc import Callable
from typing import NamedTuple

from bitstruct import compile as cf

icf = cf('u8u4u4u16') 

type Key = bytes
type Value = bytes
type Result = int
type Gas = int

class Instruction(NamedTuple):
    opcode: int
    first_register: int
    second_register: int
    constant_num: int

class EditBC(NamedTuple):
    key: Key
    value: Value

def execute(code: bytes, codemap: dict[bytes, int], gas: int, readbc: Callable[[Key], Result], writebc: Callable[[Key, Value], None]) -> tuple[Result | None, Gas]:
    codestart = codemap.get(0x00)
    code = bytearray(code)
    consts = code[:codestart]
    constsa = []
    code = code[codestart:]

    if len(consts) % 32 == 0:
        for i in range(len(consts) // 32):
            start = i * 32
            end = start + 32
            constsa.append(consts[start:end])
    consts = constsa
    offset = 0
    bytecode: list[Instruction] = []
    while offset < len(code):
        element = Instruction._make(icf.unpack_from(code, offset))
        bytecode.append(element)
        offset += 4

    # finally, execution
    editlist: list[EditBC] = [] 
    registers: list[int] = [0] * 16
    stack: list[int] = [0] * 32768 # 1MB stack, a lot of 256 bits.
    cmptrue: bool = False
    pc = 0
    limit = len(bytecode)

    while pc < limit:
        op, dest, src, const = bytecode[pc]
        pc += 1
        match op:
            case 1: # ADD
                gas -= 1
                if gas <= 0: return (None, gas)
                if dest == 0 or dest >= 12: return (None, gas)
                if src == 0:
                    registers[dest] += consts[const]
                else:
                    registers[dest] -= registers[src]
            case 2: # SUB
                gas -= 1
                if gas <= 0: return (None, gas)
                if dest == 0 or dest >= 12: return (None, gas)
                if src == 0:
                    registers[dest] -= consts[const]
                else:
                    registers[dest] -= registers[src]
            case 3: # MUL
                gas -= 2
                if gas <= 0: return (None, gas)
                if dest == 0 or dest >= 12: return (None, gas)
                if src == 0:
                    registers[dest] *= consts[const]
                else:
                    registers[dest] *= registers[src]
            case 4: # DIV
                gas -= 5
                if gas <= 0: return (None, gas)
                if dest == 0 or dest >= 12: return (None, gas)
                if src == 0:
                    registers[dest] = consts[const] // registers[dest]
                else:
                    registers[dest] = registers[src] // registers[dest]
            case 5: # RET
                return (dest if dest != 0 else src, gas)
            case 6: # JMP
                gas -= 1
                pc = src if src != 0 else const
            case 7: # CMP
                gas -= 1
                if gas <= 0: return (None, gas)
                if src == 0 or dest == 0:
                    cmptrue = (registers[dest] == consts[const])
                else:
                    cmptrue = (registers[dest] == registers[src])
            case 8: # CMH
                gas -= 1
                if gas <= 0: return (None, gas)
                if src == 0 or dest == 0:
                    cmptrue = (registers[dest] < consts[const])
                else:
                    cmptrue = (registers[dest] < registers[src])
            case 9: # CML
                gas -= 1
                if gas <= 0: return (None, gas)
                if src == 0 or dest == 0:
                    cmptrue = (registers[dest] > consts[const])
                else:
                    cmptrue = (registers[dest] > registers[src])
            case 10: # LOAD
                gas -= 3
                if gas <= 0: return (None, gas)
                if dest == 0 or dest >= 12: return (None, gas)
                if src < 0 or src >= 32768: return (None, gas)
                registers[dest] = stack[src]
            case 11: # STORE
                gas -= 3
                if gas <= 0: return (None, gas)
                if src < 0 or src >= 32768: return (None, gas)
                stack[src] = registers[dest]
            case 12: #JE
                gas -= 1
                if gas <= 0: return (None, gas)
                if cmptrue:
                    pc = const
                    cmptrue = False
            case 13: #JNE
                gas -= 1
                if gas <= 0: return (None, gas)
                if not cmptrue:
                    pc = const
                    cmptrue = False
            case 14: # SSTORE
                gas -= 15000
                if gas <= 0: return (None, gas)
                editlist.append(EditBC(dest, src))
            case 15: # SLOAD
                gas -= 500
                if gas <= 0: return (None, gas)
                if dest == 0 or dest >= 12: return (None, gas)
                x = 0
                for k, v in editlist[::-1]:
                    if k == registers[src]:
                        registers[dest] = v
                        x = v
                if x == 0:
                    registers[dest] = readbc(registers[src])
