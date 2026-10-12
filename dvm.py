from collections.abc import Callable
from typing import NamedTuple

from bitstruct import compile as cf

icf = cf('u8u4u4u16') 

type Key = bytes
type Value = bytes
type Result = bytes
type Gas = int

class Instruction(NamedTuple):
    opcode: int
    first_register: int
    second_register: int
    constant_num: int

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
    registers: list[int] = [0] * 16
    cmptrue: bool = False
    gas = gas
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
            case 10: # 
                

execute(b"1234567812345678123456781234567823456781234567812345678123456781dshagdjhsadgasjhdgashddsfsdfdsfsdf", {0x00: 64}, None, None)