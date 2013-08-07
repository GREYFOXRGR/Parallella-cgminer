#ifndef __EPIPHANY_MAILBOX_H__
#define __EPIPHANY_MAILBOX_H__

typedef struct {
	uint32_t data[20];
	uint32_t ostate;
	uint32_t go;
} shared_buf_t;

#endif
