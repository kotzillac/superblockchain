/* SPDX-License-Identifier: GPL-3.0-or-later */

OUTPUT_ARCH( "riscv" )
ENTRY( _start )

MEMORY
{
  RAM (xrw) : ORIGIN = 0x00000000, LENGTH = 4M
}

SECTIONS
{
  .text : {
    . = ALIGN(4);
    *(.init)
    *(.text*)
    . = ALIGN(4);
  } > RAM

  .rodata : {
    . = ALIGN(4);
    *(.rodata*)
    . = ALIGN(4);
  } > RAM

  .data : {
    . = ALIGN(4);
    *(.data*)
    . = ALIGN(4);
  } > RAM

  .bss (NOLOAD) : {
    *(.bss*)
    *(COMMON)
    . = ALIGN(4);
  } > RAM
  
  _stack_top = ORIGIN(RAM) + LENGTH(RAM);
}
