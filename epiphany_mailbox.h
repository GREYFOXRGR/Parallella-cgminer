#ifndef __EPIPHANY_MAILBOX_H__
#define __EPIPHANY_MAILBOX_H__

typedef struct {
	uint32_t data[20];
	uint32_t ostate;
	uint8_t go;
	uint8_t working;
} shared_buf_t;

#endif
