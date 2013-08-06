#!/bin/bash

ESDK=${EPIPHANY_HOME}
ELDF=${ESDK}/bsps/current/internal.ldf

# Build DEVICE side program
e-gcc -Os -T ${ELDF} epiphany-scrypt.c -o epiphany-scrypt.elf -le-lib

# Convert ebinary to SREC file
e-objcopy --srec-forceS3 --output-target srec epiphany-scrypt.elf epiphany-scrypt.srec

