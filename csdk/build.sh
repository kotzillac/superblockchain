riscv64-unknown-elf-gcc -Oz -fno-builtin -nostdlib -fno-exceptions -fno-asynchronous-unwind-tables -march=rv32i -mabi=ilp32 -nostartfiles -T linker.ld \
  -I./ \
  boot.S main.c libdch.c \
  -o program.elf
riscv64-unknown-elf-objcopy -O binary program.elf program.bin
rm program.elf