#!/bin/bash

ESDK=${EPIPHANY_HOME}
ELDF=${ESDK}/bsps/current/fast.ldf

asm=0

for param in "$@"; do
  if [ $param = "--asm" ]; then
    asm="yes"
  fi
done

if [ $asm = "yes" ]; then
  # Build DEVICE side program with asm routines
  echo "Compiling Epiphany binary with asm routines"
  e-gcc -mfp-mode=int -ggdb -Os -T ${ELDF} epiphany-scrypt.c epiphany-salsa208.S -o epiphany-scrypt.elf -le-lib -DEPIPHANY_ASM
else
  # Build DEVICE side program without asm routines
  echo "Compiling Epiphany binary withiout asm routines"
  e-gcc -mfp-mode=int -ggdb -Os -T ${ELDF} epiphany-scrypt.c -o epiphany-scrypt.elf -le-lib
fi

# Convert ebinary to SREC file
e-objcopy --srec-forceS3 --output-target srec epiphany-scrypt.elf epiphany-scrypt.srec

exit 0
