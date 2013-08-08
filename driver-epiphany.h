#ifndef __DEVICE_CPU_H__
#define __DEVICE_CPU_H__

#include <stdbool.h>
#include <e-hal.h>

#include "miner.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>

#include <sys/stat.h>
#include <sys/types.h>

#ifndef WIN32
#include <sys/wait.h>
#include <sys/resource.h>
#endif
#include <libgen.h>

#include "compat.h"
#include "miner.h"
#include "bench_block.h"

#if defined(unix)
	#include <errno.h>
	#include <fcntl.h>
#endif

#include "epiphany_mailbox.h"

#ifdef WANT_EPIPHANYMINING

#define _BufOffset (0x01000000)

extern struct device_drv epiphany_drv;

#endif

#endif /* __DEVICE_CPU_H__ */
