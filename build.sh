#!/bin/bash

ESDK=${EPIPHANY_HOME}
ELDF=${ESDK}/bsps/current/fast.ldf

# Build DEVICE side program
e-gcc -ggdb -Os -T ${ELDF} epiphany-scrypt.c epiphany-salsa20_8.S -o epiphany-scrypt.elf -le-lib

# Convert ebinary to SREC file
e-objcopy --srec-forceS3 --output-target srec epiphany-scrypt.elf epiphany-scrypt.srec
