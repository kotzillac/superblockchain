# cython: language_level=3
# boundscheck: false
from collections.abc import Callable
from libc.stdint cimport int32_t, uint32_t, uint64_t, uint8_t
from libc.stddef cimport size_t
from libc.stdlib cimport calloc, free
from libc.string cimport memset
from cpython.bytes cimport PyBytes_FromStringAndSize

# VM memory: 1048576 words * 4 bytes = 4 MiB of addressable byte space.
cdef int32_t MEM_WORDS = 1048576
cdef uint32_t MEM_BYTES = <uint32_t>MEM_WORDS * 4

# ---------------------------------------------------------------------------
# Bit helpers
# ---------------------------------------------------------------------------
cdef inline uint32_t get_bit_slice(uint32_t value, int32_t start, int32_t end) noexcept:
    cdef int32_t length = end - start + 1
    if start < 0 or length <= 0 or length > 32:
        return 0
    if length == 32:
        return value >> start
    return (value >> start) & ((<uint32_t>1 << length) - 1)


# Sign-extend the low its bits of a value without relying on signed shifts.
cdef inline int32_t sext(uint32_t value, uint32_t bits) noexcept:
    cdef uint32_t sign
    if bits == 0 or bits >= 32:
        return <int32_t>value
    sign = <uint32_t>1 << (bits - 1)
    return <int32_t>((value ^ sign) - sign)


# Arithmetic right shift with explicit sign extension.
cdef inline int32_t sra(uint32_t value, uint32_t shamt) noexcept:
    shamt &= 31
    if shamt == 0:
        return <int32_t>value
    if value & 0x80000000:
        return <int32_t>((value >> shamt) | (<uint32_t>0xffffffff << (32 - shamt)))
    return <int32_t>(value >> shamt)


# ---------------------------------------------------------------------------
# Instruction fetch (little-endian, 4 bytes -> one 32-bit word)
# ---------------------------------------------------------------------------
cdef inline uint32_t fetch32(const uint8_t[:] bc, uint32_t pc) noexcept:
    return (<uint32_t>bc[pc]
            | (<uint32_t>bc[pc + 1] << 8)
            | (<uint32_t>bc[pc + 2] << 16)
            | (<uint32_t>bc[pc + 3] << 24))


# ---------------------------------------------------------------------------
# Byte-addressable memory access inside the word array
# ---------------------------------------------------------------------------
cdef inline int32_t mem_read(int32_t* mem, uint32_t addr, int32_t size, int32_t do_sign) noexcept:
    cdef int32_t i
    cdef uint32_t byte_addr, idx, sh, b, val = 0
    if size <= 0 or size > 4:
        return 0
    if addr > MEM_BYTES - <uint32_t>size:
        return 0
    for i in range(size):
        byte_addr = addr + <uint32_t>i
        idx = byte_addr >> 2
        sh = (byte_addr & 3) * 8
        b = (<uint32_t>mem[idx] >> sh) & 0xff
        val |= b << (8 * i)
    if do_sign and size < 4:
        return sext(val, 8 * size)
    return <int32_t>val


cdef inline void mem_write(int32_t* mem, uint32_t addr, uint32_t value, int32_t size) noexcept:
    cdef int32_t i
    cdef uint32_t byte_addr, idx, sh, mask, word
    if size <= 0 or size > 4:
        return
    if addr > MEM_BYTES - <uint32_t>size:
        return
    for i in range(size):
        byte_addr = addr + <uint32_t>i
        idx = byte_addr >> 2
        sh = (byte_addr & 3) * 8
        mask = <uint32_t>0xff << sh
        word = <uint32_t>mem[idx]
        word = (word & ~mask) | (((value >> (8 * i)) & 0xff) << sh)
        mem[idx] = <int32_t>word


# ---------------------------------------------------------------------------
# Interpreter
# ---------------------------------------------------------------------------
def execute(code: bytes, gas: int, systemcall: Callable[[int, int, int, int, bytes], tuple[bytes | None, int]]) -> tuple[int | None, int]:
    cdef int32_t registers[32]
    memset(&registers[0], 0, sizeof(registers))

    cdef const uint8_t[:] bc
    cdef uint32_t code_len
    cdef int32_t* memory = NULL

    cdef uint32_t pc = 0
    cdef uint32_t instraw = 0
    cdef uint32_t next_pc = 0
    cdef uint32_t addr = 0
    cdef uint32_t uimm = 0
    cdef int32_t opcode, rd, rs1, rs2, funct3, funct7
    cdef int32_t imm, shamt, taken
    cdef int32_t result

    cdef uint8_t buff[64]
    cdef uint32_t i
    cdef uint32_t copy_len
    cdef bytes input_bytes
    cdef bytes response
    cdef object out_buf, resu, resu32
    cdef bint normal_exit = False

    bc = code
    code_len = <uint32_t>len(code)
    memory = <int32_t*>calloc(<size_t>MEM_WORDS, sizeof(int32_t))
    if memory == NULL:
        raise MemoryError()

    try:
        while True:
            if pc == code_len:
                normal_exit = True
                break
            if <uint64_t>pc + 4 > <uint64_t>code_len:
                break                              # incomplete instruction -> stop

            instraw = fetch32(bc, pc)
            opcode = instraw & 0x7f
            next_pc = pc + 4                 # default: sequential

            funct3 = (instraw >> 12) & 0x7

            gas -= 2
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
                    result = sext(<uint32_t>registers[rs1] + <uint32_t>registers[rs2], 32)  # ADD
                elif funct3 == 0b000 and funct7 == 0x20:
                    result = sext(<uint32_t>registers[rs1] - <uint32_t>registers[rs2], 32)  # SUB
                elif funct3 == 0b001 and funct7 == 0x00:
                    result = sext(<uint32_t>registers[rs1] << (<uint32_t>registers[rs2] & 0x1f), 32)  # SLL
                elif funct3 == 0b010 and funct7 == 0x00:
                    result = 1 if registers[rs1] < registers[rs2] else 0        # SLT
                elif funct3 == 0b011 and funct7 == 0x00:
                    result = 1 if (<uint32_t>registers[rs1]) < (<uint32_t>registers[rs2]) else 0  # SLTU
                elif funct3 == 0b100 and funct7 == 0x00:
                    result = sext(<uint32_t>registers[rs1] ^ <uint32_t>registers[rs2], 32)  # XOR
                elif funct3 == 0b101 and funct7 == 0x00:
                    result = sext(<uint32_t>registers[rs1] >> (<uint32_t>registers[rs2] & 0x1f), 32)  # SRL
                elif funct3 == 0b101 and funct7 == 0x20:
                    result = sra(<uint32_t>registers[rs1], <uint32_t>registers[rs2] & 0x1f)  # SRA
                elif funct3 == 0b110 and funct7 == 0x00:
                    result = sext(<uint32_t>registers[rs1] | <uint32_t>registers[rs2], 32)  # OR
                elif funct3 == 0b111 and funct7 == 0x00:
                    result = sext(<uint32_t>registers[rs1] & <uint32_t>registers[rs2], 32)  # AND
                else:
                    break                             # illegal funct3/funct7 -> stop

                if rd != 0:
                    registers[rd] = result

            elif opcode == 0b0010011:            # OP-IMM : I-type
                rd     = (instraw >> 7) & 0x1f
                funct3 = (instraw >> 12) & 0x7
                rs1    = (instraw >> 15) & 0x1f
                imm    = sext(instraw >> 20, 12)
                shamt  = (instraw >> 20) & 0x1f

                result = 0
                if funct3 == 0b000:
                    result = sext(<uint32_t>registers[rs1] + <uint32_t>imm, 32)  # ADDI
                elif funct3 == 0b010:
                    result = 1 if registers[rs1] < imm else 0                    # SLTI
                elif funct3 == 0b011:
                    result = 1 if (<uint32_t>registers[rs1]) < (<uint32_t>imm) else 0  # SLTIU
                elif funct3 == 0b100:
                    result = sext(<uint32_t>registers[rs1] ^ <uint32_t>imm, 32)  # XORI
                elif funct3 == 0b110:
                    result = sext(<uint32_t>registers[rs1] | <uint32_t>imm, 32)  # ORI
                elif funct3 == 0b111:
                    result = sext(<uint32_t>registers[rs1] & <uint32_t>imm, 32)  # ANDI
                elif funct3 == 0b001 and (instraw >> 25) == 0:
                    result = sext(<uint32_t>registers[rs1] << <uint32_t>shamt, 32)  # SLLI
                elif funct3 == 0b101 and (instraw >> 25) == 0:
                    result = sext(<uint32_t>registers[rs1] >> <uint32_t>shamt, 32)  # SRLI
                elif funct3 == 0b101 and (instraw >> 25) == 0x20:
                    result = sra(<uint32_t>registers[rs1], <uint32_t>shamt)      # SRAI
                else:
                    break                             # illegal funct3 / imm[11:5] -> stop

                if rd != 0:
                    registers[rd] = result

            elif opcode == 0b0000011:            # LOAD : I-type
                funct3 = (instraw >> 12) & 0x7
                rd     = (instraw >> 7) & 0x1f
                rs1    = (instraw >> 15) & 0x1f
                addr   = <uint32_t>registers[rs1] + <uint32_t>sext(instraw >> 20, 12)

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
                imm    = sext(<uint32_t>imm, 12)
                addr   = <uint32_t>registers[rs1] + <uint32_t>imm

                if funct3 == 0b000:
                    mem_write(memory, addr, <uint32_t>registers[rs2], 1)         # SB
                elif funct3 == 0b001:
                    mem_write(memory, addr, <uint32_t>registers[rs2], 2)         # SH
                elif funct3 == 0b010:
                    mem_write(memory, addr, <uint32_t>registers[rs2], 4)         # SW
                else:
                    break

            elif opcode == 0b0110111:            # LUI : U-type
                rd   = (instraw >> 7) & 0x1f
                imm  = sext(instraw & 0xfffff000, 32)
                if rd != 0:
                    registers[rd] = imm

            elif opcode == 0b0010111:            # AUIPC : U-type
                rd   = (instraw >> 7) & 0x1f
                imm  = sext(instraw & 0xfffff000, 32)
                if rd != 0:
                    registers[rd] = sext(pc + <uint32_t>imm, 32)

            elif opcode == 0b1101111:            # JAL : J-type
                rd  = (instraw >> 7) & 0x1f
                uimm = ((instraw >> 31) & 0x1) << 20
                uimm |= ((instraw >> 12) & 0xff) << 12
                uimm |= ((instraw >> 20) & 0x1) << 11
                uimm |= ((instraw >> 21) & 0x3ff) << 1
                imm = sext(uimm, 21)
                if rd != 0:
                    registers[rd] = sext(pc + 4, 32)
                next_pc = pc + <uint32_t>imm
                if next_pc >= code_len:
                    break                             # target out of range -> stop

            elif opcode == 0b1100111:            # JALR : I-type
                funct3 = (instraw >> 12) & 0x7
                if funct3 != 0b000:
                    break                          # illegal funct3
                rd   = (instraw >> 7) & 0x1f
                rs1  = (instraw >> 15) & 0x1f
                imm  = sext(instraw >> 20, 12)
                next_pc = (<uint32_t>registers[rs1] + <uint32_t>imm) & 0xfffffffe
                if next_pc >= code_len:
                    break                          # target out of range -> stop
                if rd != 0:
                    registers[rd] = sext(pc + 4, 32)

            elif opcode == 0b1100011:            # BRANCH : B-type
                funct3 = (instraw >> 12) & 0x7
                rs1    = (instraw >> 15) & 0x1f
                rs2    = (instraw >> 20) & 0x1f
                uimm = ((instraw >> 31) & 0x1) << 12
                uimm |= ((instraw >> 7) & 0x1) << 11
                uimm |= ((instraw >> 25) & 0x3f) << 5
                uimm |= ((instraw >> 8) & 0xf) << 1
                imm = sext(uimm, 13)
                next_pc = pc + 4

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
                    next_pc = pc + <uint32_t>imm
                    if next_pc >= code_len:
                        break                       # target out of range -> stop

            elif opcode == 0b0001111:            # MISC-MEM : FENCE (no-op)
                pass

            elif opcode == 0b1110011:            # SYSTEM : ECALL
                if instraw != 0x00000073:
                    break                          # EBREAK or illegal SYSTEM

                for i in range(64):
                    buff[i] = <uint8_t>mem_read(memory, <uint32_t>registers[14] + i, 1, 0)
                input_bytes = PyBytes_FromStringAndSize(<char*>buff, 64)
                out_buf, resu = systemcall(registers[10], registers[11], registers[12], registers[13], input_bytes)
                if out_buf is not None:
                    response = out_buf if isinstance(out_buf, bytes) else bytes(out_buf)
                    copy_len = <uint32_t>len(response)
                    if copy_len > 64:
                        copy_len = 64
                    for i in range(copy_len):
                        mem_write(memory, <uint32_t>registers[14] + i, <uint32_t>response[i], 1)
                resu32 = resu & 0xffffffff
                registers[10] = sext(<uint32_t>resu32, 32)

            else:
                break                             # illegal instruction -> stop

            pc = next_pc

        if normal_exit:
            return (<int32_t>registers[10], gas)
        return (None, gas)
    finally:
        free(memory)
