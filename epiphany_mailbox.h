#ifndef __EPIPHANY_MAILBOX_H__
#define __EPIPHANY_MAILBOX_H__

typedef struct {
	uint32_t data[20];
	uint32_t ostate = 0;
	uint32_t go = 0;
} shared_buf_t;

#endif
