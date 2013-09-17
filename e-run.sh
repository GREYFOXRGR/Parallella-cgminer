#!/bin/bash

set -e

ESDK=${EPIPHANY_HOME}
ELIBS=${ESDK}/tools/host/lib:${LD_LIBRARY_PATH}
EHDF=${EPIPHANY_HDF}

LD_LIBRARY_PATH=${ELIBS} EPIPHANY_HDF=${EHDF} ./cgminer --scrypt $@

exit 0

