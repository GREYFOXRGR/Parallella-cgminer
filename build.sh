#!/bin/bash

ESDK=${EPIPHANY_HOME}
ELDF=${ESDK}/bsps/current/fast.ldf

if [ $1 = "--asm" ]; then
# Build DEVICE side program with asm routines
e-gcc -mfp-mode=int -ggdb -Os -T ${ELDF} epiphany-scrypt.c epiphany-salsa20_8.S -o epiphany-scrypt.elf -le-lib -DEPIPHANY_ASM
else
# Build DEVICE side program without asm routines
e-gcc -mfp-mode=int -ggdb -Os -T ${ELDF} epiphany-scrypt.c -o epiphany-scrypt.elf -le-lib
fi

# Convert ebinary to SREC file
e-objcopy --srec-forceS3 --output-target srec epiphany-scrypt.elf epiphany-scrypt.srec
