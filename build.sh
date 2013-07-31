#!/bin/bash

ESDK=${EPIPHANY_HOME}
ELDF=${ESDK}/bsps/current/internal.ldf

# Build DEVICE side program
e-gcc -Os -T ${ELDF} parallella-scrypt.c -o parallella-scrypt.elf -le-lib

# Convert ebinary to SREC file
e-objcopy --srec-forceS3 --output-target srec parallella-scrypt.elf parallella-scrypt.srec

