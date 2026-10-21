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
import ast
import pathlib
import sys


class Disassembler:
    OP_MAP = {
        0: "NOP",
        1: "ADD",
        2: "SUB",
        3: "MUL",
        4: "DIV",
        5: "RET",
        6: "JMP",
        7: "CMP",
        8: "CMH",
        9: "CML",
        10: "LOAD",
        11: "STORE",
        12: "JE",
        13: "JNE",
        14: "SSTORE",
        15: "SLOAD",
        16: "PUSH",
        17: "POP",
        99: "MOV",
    }

    def _fmt_reg(self, reg_idx: int) -> str:
        if reg_idx >= 10:
            return f"S{reg_idx - 10}"
        return f"r{reg_idx}"

    def decode_instruction(self, instr_hex: str) -> str:
        val = int(instr_hex, 16)
        
        opcode = (val >> 24) & 0xFF
        src_idx = (val >> 20) & 0x0F
        dest_idx = (val >> 16) & 0x0F
        const_idx = val & 0xFFFF

        op_name = self.OP_MAP.get(opcode, f"UNKNOWN_0x{opcode:02X}")
        
        src = self._fmt_reg(src_idx)
        dest = self._fmt_reg(dest_idx)
        
        return f"    {op_name} {src}, {dest}, CONST:{const_idx}"

    def disassemble(self, hex_code: str, code_map: dict[int, int]) -> str:
        hex_code = hex_code.strip().lower().replace("0x", "")
        
        start_bytes = code_map.get(0, 0)

        offset_to_lines = {}
        for line_id, offset in code_map.items():
            offset_to_lines.setdefault(offset, []).append(line_id)

        pure_code_hex = hex_code[start_bytes * 2:]
        
        instr_size = 8
        instrs = [pure_code_hex[i:i+instr_size] for i in range(0, len(pure_code_hex), instr_size)]

        output = []
        current_line = 0
        
        sorted_lines = sorted(code_map.keys())
        
        for idx, instr in enumerate(instrs):
            current_byte_offset = start_bytes + (idx * 4)
            
            if current_byte_offset in offset_to_lines:
                lines_here = sorted(offset_to_lines[current_byte_offset])
                for l_id in lines_here[:-1]:
                    output.append(f":0x{l_id:x}")
                
                current_line = lines_here[-1]
                output.append(f":0x{current_line:x}")

            decoded = self.decode_instruction(instr)
            output.append(decoded)
                
        return "\n".join(output)


if __name__ == "__main__":
    try:
        code: str = ""
        try:
            code = pathlib.Path(sys.argv[1]).read_bytes().hex()
        except FileNotFoundError:
            code = sys.argv[1].encode().hex()
        code_map = dict(ast.literal_eval(sys.argv[2]))

        disasm = Disassembler()
        print(disasm.disassemble(code, code_map))
    except IndexError:
        print("Не было задано аргументов.")