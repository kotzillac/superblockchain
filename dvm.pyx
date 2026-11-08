# cython: language_level=3
# boundscheck: false
from collections.abc import Callable
from libc.stdint cimport int32_t, uint32_t, int8_t, uint8_t
from libc.string cimport memset

type Key = bytes
type Value = bytes
type Result = int
type Gas = int

# VM memory: 524288 words * 4 bytes = 2 MiB of addressable byte space.
cdef int32_t MEM_WORDS = 524288
cdef int32_t MEM_BYTES = MEM_WORDS * 4

# ---------------------------------------------------------------------------
# Bit helpers
# ---------------------------------------------------------------------------
cdef inline int32_t get_bit_slice(int32_t value, int8_t start, int8_t end) noexcept:
    cdef uint32_t u_value = <uint32_t>value

    cdef int8_t length = end - start + 1

    cdef uint32_t mask = <uint32_t>((1 << length) - 1)

    return <int32_t>((u_value >> start) & mask)


# Sign-extend the low `bits` bits of a value.
cdef inline int32_t sext(int32_t value, int32_t bits) noexcept:
    cdef int32_t shift = 32 - bits
    return (value << shift) >> shift


# ---------------------------------------------------------------------------
# Instruction fetch (little-endian, 4 bytes -> one 32-bit word)
# ---------------------------------------------------------------------------
cdef inline uint32_t fetch32(int8_t[:] bc, uint32_t pc) noexcept:
    return (<uint32_t>(bc[pc] & 0xff)
            | (<uint32_t>(bc[pc + 1] & 0xff) << 8)
            | (<uint32_t>(bc[pc + 2] & 0xff) << 16)
            | (<uint32_t>(bc[pc + 3] & 0xff) << 24))


# ---------------------------------------------------------------------------
# Byte-addressable memory access inside the word array
# ---------------------------------------------------------------------------
cdef inline int32_t mem_read(int32_t[::1] mem, int32_t addr, int32_t size, int32_t do_sign) noexcept:
    cdef int32_t i, b, idx, sh, val = 0
    for i in range(size):
        idx = (addr + i) >> 2
        if idx < 0 or idx >= MEM_WORDS:
            return 0
        sh = ((addr + i) & 3) * 8
        b = (mem[idx] >> sh) & 0xff
        val |= b << (8 * i)
    if do_sign and size < 4:
        cdef int32_t sft = 32 - 8 * size
        val = (val << sft) >> sft
    return val


cdef inline void mem_write(int32_t[::1] mem, int32_t addr, int32_t value, int32_t size) noexcept:
    cdef int32_t i, b, idx, sh
    for i in range(size):
        idx = (addr + i) >> 2
        if idx < 0 or idx >= MEM_WORDS:
            return
        sh = ((addr + i) & 3) * 8
        b = (value >> (8 * i)) & 0xff
        mem[idx] = (mem[idx] & ~(0xff << sh)) | (b << sh)


# ---------------------------------------------------------------------------
# Interpreter
# ---------------------------------------------------------------------------
def execute(code: bytes, gas: int, readbc: Callable[[Key], Result], writebc: Callable[[Key, Value], None]) -> tuple[Result | None, Gas]:
    cdef int32_t[524288] memory
    memset(&memory[0], 0, sizeof(memory))
    cdef int32_t[32] registers
    memset(&registers[0], 0, sizeof(registers))

    cdef int8_t[:] bc = code

    cdef uint32_t pc = 0
    cdef uint32_t instraw = 0
    cdef int32_t opcode, rd, rs1, rs2, funct3, funct7
    cdef int32_t imm, shamt, addr, next_pc, taken
    cdef int32_t result

    while True:
        if pc + 3 >= len(code):
            break

        instraw = fetch32(bc, pc)
        opcode = instraw & 0x7f
        next_pc = <int32_t>pc + 4                 # default: sequential

        # Gas table: add/sub/xor/or/and/sll/srl and all others cost 1 gas,
        # except loads/stores: lb=4, lh=4, lw=3, lbu=3, lhu=3, sb=4, sh=4, sw=3.
        funct3 = (instraw >> 12) & 0x7
        if opcode == 0b0000011 or opcode == 0b0100011:   # LOAD / STORE
            if funct3 == 0b000 or funct3 == 0b001:
                gas -= 4                                  # lb / lh / sb / sh
            else:
                gas -= 3                                  # lw / lbu / lhu / sw
        else:
            gas -= 1                                      # everything else
        if gas < 0:
            break                                         # out of gas -> stop

        if opcode == 0b0110011:            # OP : R-type
            rd     = (instraw >> 7) & 0x1f
            funct3 = (instraw >> 12) & 0x7
            rs1    = (instraw >> 15) & 0x1f
            rs2    = (instraw >> 20) & 0x1f
            funct7 = (instraw >> 25) & 0x7f

            result = 0
            if funct3 == 0b000 and funct7 == 0x00:
                result = registers[rs1] + registers[rs2]                    # ADD
            elif funct3 == 0b000 and funct7 == 0x20:
                result = registers[rs1] - registers[rs2]                    # SUB
            elif funct3 == 0b001 and funct7 == 0x00:
                result = registers[rs1] << (registers[rs2] & 0x1f)          # SLL
            elif funct3 == 0b010 and funct7 == 0x00:
                result = 1 if registers[rs1] < registers[rs2] else 0        # SLT
            elif funct3 == 0b011 and funct7 == 0x00:
                result = 1 if (<uint32_t>registers[rs1]) < (<uint32_t>registers[rs2]) else 0  # SLTU
            elif funct3 == 0b100 and funct7 == 0x00:
                result = registers[rs1] ^ registers[rs2]                    # XOR
            elif funct3 == 0b101 and funct7 == 0x00:
                result = <int32_t>(<uint32_t>registers[rs1] >> (registers[rs2] & 0x1f))  # SRL
            elif funct3 == 0b101 and funct7 == 0x20:
                result = registers[rs1] >> (registers[rs2] & 0x1f)          # SRA
            elif funct3 == 0b110 and funct7 == 0x00:
                result = registers[rs1] | registers[rs2]                    # OR
            elif funct3 == 0b111 and funct7 == 0x00:
                result = registers[rs1] & registers[rs2]                    # AND
            else:
                break                             # illegal funct3/funct7 -> stop

            if rd != 0:
                registers[rd] = result

        elif opcode == 0b0010011:            # OP-IMM : I-type
            rd     = (instraw >> 7) & 0x1f
            funct3 = (instraw >> 12) & 0x7
            rs1    = (instraw >> 15) & 0x1f
            imm    = sext(<int32_t>(instraw >> 20), 12)
            shamt  = (instraw >> 20) & 0x1f

            result = 0
            if funct3 == 0b000:
                result = registers[rs1] + imm                                # ADDI
            elif funct3 == 0b010:
                result = 1 if registers[rs1] < imm else 0                    # SLTI
            elif funct3 == 0b011:
                result = 1 if (<uint32_t>registers[rs1]) < (<uint32_t>imm) else 0  # SLTIU
            elif funct3 == 0b100:
                result = registers[rs1] ^ imm                                # XORI
            elif funct3 == 0b110:
                result = registers[rs1] | imm                                # ORI
            elif funct3 == 0b111:
                result = registers[rs1] & imm                                # ANDI
            elif funct3 == 0b001 and (instraw >> 25) == 0:
                result = registers[rs1] << shamt                             # SLLI
            elif funct3 == 0b101 and (instraw >> 25) == 0:
                result = <int32_t>(<uint32_t>registers[rs1] >> shamt)        # SRLI
            elif funct3 == 0b101 and (instraw >> 25) == 0x20:
                result = registers[rs1] >> shamt                            # SRAI
            else:
                break                             # illegal funct3 / imm[11:5] -> stop

            if rd != 0:
                registers[rd] = result

        elif opcode == 0b0000011:            # LOAD : I-type
            funct3 = (instraw >> 12) & 0x7
            rd     = (instraw >> 7) & 0x1f
            rs1    = (instraw >> 15) & 0x1f
            addr   = registers[rs1] + sext(<int32_t>(instraw >> 20), 12)

            if funct3 == 0b000:
                result = mem_read(memory, addr, 1, 1)                        # LB
            elif funct3 == 0b001:
                result = mem_read(memory, addr, 2, 1)                        # LH
            elif funct3 == 0b010:
                result = mem_read(memory, addr, 4, 0)                        # LW
            elif funct3 == 0b100:
                result = mem_read(memory, addr, 1, 0)                        # LBU
            elif funct3 == 0b101:
                result = mem_read(memory, addr, 2, 0)                        # LHU
            else:
                break

            if rd != 0:
                registers[rd] = result

        elif opcode == 0b0100011:            # STORE : S-type (no rd write)
            funct3 = (instraw >> 12) & 0x7
            rs1    = (instraw >> 15) & 0x1f
            rs2    = (instraw >> 20) & 0x1f
            imm    = ((instraw >> 25) << 5) | ((instraw >> 7) & 0x1f)
            imm    = sext(imm, 12)
            addr   = registers[rs1] + imm

            if funct3 == 0b000:
                mem_write(memory, addr, registers[rs2], 1)                   # SB
            elif funct3 == 0b001:
                mem_write(memory, addr, registers[rs2], 2)                   # SH
            elif funct3 == 0b010:
                mem_write(memory, addr, registers[rs2], 4)                   # SW
            else:
                break

        elif opcode == 0b0110111:            # LUI : U-type
            rd   = (instraw >> 7) & 0x1f
            imm  = <int32_t>(instraw & 0xfffff000)
            if rd != 0:
                registers[rd] = imm

        elif opcode == 0b0010111:            # AUIPC : U-type
            rd   = (instraw >> 7) & 0x1f
            imm  = <int32_t>(instraw & 0xfffff000)
            if rd != 0:
                registers[rd] = <int32_t>pc + imm

        elif opcode == 0b1101111:            # JAL : J-type
            rd  = (instraw >> 7) & 0x1f
            imm = (((instraw >> 31) & 0x1) << 20)
            imm |= ((instraw >> 12) & 0xff) << 12
            imm |= ((instraw >> 20) & 0x1) << 11
            imm |= ((instraw >> 21) & 0x3ff) << 1
            imm = sext(imm, 21)
            if rd != 0:
                registers[rd] = <int32_t>pc + 4
            next_pc = <int32_t>pc + imm
            if next_pc < 0 or next_pc >= len(code):
                break                             # target out of range -> stop

        elif opcode == 0b1100111:            # JALR : I-type
            funct3 = (instraw >> 12) & 0x7
            if funct3 != 0b000:
                break                          # illegal funct3
            rd   = (instraw >> 7) & 0x1f
            rs1  = (instraw >> 15) & 0x1f
            imm  = sext(<int32_t>(instraw >> 20), 12)
            next_pc = (registers[rs1] + imm) & ~1      # read rs1 before link write (rd may be rs1)
            if next_pc < 0 or next_pc >= len(code):
                break                          # target out of range -> stop
            if rd != 0:
                registers[rd] = <int32_t>pc + 4

        elif opcode == 0b1100011:            # BRANCH : B-type
            funct3 = (instraw >> 12) & 0x7
            rs1    = (instraw >> 15) & 0x1f
            rs2    = (instraw >> 20) & 0x1f
            imm = (((instraw >> 31) & 0x1) << 12)
            imm |= ((instraw >> 7) & 0x1) << 11
            imm |= ((instraw >> 25) & 0x3f) << 5
            imm |= ((instraw >> 8) & 0xf) << 1
            imm = sext(imm, 13)
            next_pc = <int32_t>pc + 4

            taken = 0
            if funct3 == 0b000:
                taken = registers[rs1] == registers[rs2]                    # BEQ
            elif funct3 == 0b001:
                taken = registers[rs1] != registers[rs2]                    # BNE
            elif funct3 == 0b100:
                taken = registers[rs1] < registers[rs2]                     # BLT
            elif funct3 == 0b101:
                taken = registers[rs1] >= registers[rs2]                    # BGE
            elif funct3 == 0b110:
                taken = (<uint32_t>registers[rs1]) < (<uint32_t>registers[rs2])   # BLTU
            elif funct3 == 0b111:
                taken = (<uint32_t>registers[rs1]) >= (<uint32_t>registers[rs2])  # BGEU
            else:
                break

            if taken:
                next_pc = <int32_t>pc + imm
                if next_pc < 0 or next_pc >= len(code):
                    break                       # target out of range -> stop

        elif opcode == 0b0001111:            # MISC-MEM : FENCE (no-op)
            pass

        elif opcode == 0b1110011:            # SYSTEM : ECALL
            if imm 

        else:
            break                             # illegal instruction -> stop

        pc = next_pc

    return (None, gas)