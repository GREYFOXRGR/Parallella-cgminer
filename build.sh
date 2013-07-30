#!/bin/bash

ESDK=${EPIPHANY_HOME}
ELDF=${ESDK}/bsps/current/fast.ldf

# Build DEVICE side program
e-gcc -Os -T ${ELDF} crypto_scrypt-ref.c scrypt_platform.h sha256.c sha256.h sysendian.h -o crypto_scrypt-ref.elf -le-lib

# Convert ebinary to SREC file
e-objcopy --srec-forceS3 --output-target srec crypto_scrypt-ref.elf crypto_scrypt-ref.srec

