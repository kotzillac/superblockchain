.section .init
.globl _start

_start:
    .cfi_startproc
    
    la sp, _stack_top

    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop

    jal jalr, main