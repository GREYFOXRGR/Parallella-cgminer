#!/bin/bash

set -e

ESDK=${EPIPHANY_HOME}
ELIBS=${ESDK}/tools/host/lib:${LD_LIBRARY_PATH}
EHDF=${EPIPHANY_HDF}

LD_LIBRARY_PATH=${ELIBS} EPIPHANY_HDF=${EHDF} ./cgminer -o mining.eu.hypernova.pw:3333 --scrypt -u lordrafa.lordrafa -p 123456 -D -T
