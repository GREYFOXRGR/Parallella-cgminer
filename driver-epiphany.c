/*
 * Copyright 2011-2012 Con Kolivas
 * Copyright 2011-2012 Luke Dashjr
 * Copyright 2010 Jeff Garzik
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "driver-epiphany.h"

/* TODO: resolve externals */
extern void submit_work_async(const struct work *work_in, struct timeval *tv);
extern char *set_int_range(const char *arg, int *i, int min, int max);
extern int dev_from_id(int thr_id);


#ifdef HAS_EPIPHANY
static void epiphany_detect()
{
	int i,j;
	e_platform_t platform;
	e_mem_t emem;
	e_mem_t dev;
	unsigned rows;
	unsigned cols;

	if (e_init(NULL) == E_ERR)
		return;

	if (e_reset_system() == E_ERR)
		return;

	if (e_get_platform_info(&platform) == E_ERR)
		return;

	rows = platform.rows;
	cols = platform.cols;

	if (e_alloc(&emem, _BufOffset, rows * cols * sizeof(shared_buf_t)) == E_ERR)
		return false;

	if (e_open(&dev, 0, 0, rows, cols) == E_ERR)
		return false;

	struct cgpu_info *epiphany_cores = calloc(rows * cols, sizeof(struct cgpu_info));

	if (unlikely(!epiphany_cores))
		quit(1, "Failed to malloc epiphany");

	cgpu_info *core;

	for (i = 0; i < rows; i++) {
		for (j = 0; j < cols; j++) {
			core = &epiphany_cores[i * cols + j];
			core->api = &epiphany_api;
			core->deven = DEV_ENABLED;
			core->threads = 1;
			core->epiphany_dev = dev;
			core->epiphany_emem = emem;
			core->epiphany_row = i;
			core->epiphany_col = j;
			core->epiphany_core_n = i*platform.cols+j;
			core->kname = "Epiphany Scrypt";
			add_cgpu(core);
		}
	}

}

static bool epiphany_thread_prepare(struct thr_info *thr)
{
	e_epiphany_t *dev = &thr->cgpu->epiphany_dev;
	e_mem_t *emem = &thr->cgpu->epiphany_emem;
	unsigned row = thr->cgpu->epiphany_row;
	unsigned col = thr->cgpu->epiphany_col;


	// Load programs on cores.
	if (e_load("epiphany-scrypt.srec", dev, row, col, E_FALSE) == E_ERR)
	{
		return false;
	}

	if (e_start(dev, row, col) == E_ERR)
	{
		return false;
	}

	thread_reportin(thr);

	return true;
}


bool epiphany_scrypt(struct thr_info *thr, const unsigned char __maybe_unused *pmidstate,
		     unsigned char *pdata, unsigned char __maybe_unused *phash1,
		     unsigned char __maybe_unused *phash, const unsigned char *ptarget,
		     uint32_t max_nonce, uint32_t *last_nonce, uint32_t n)
{

	e_epiphany_t *dev = &thr->cgpu->epiphany_dev;
	e_mem_t *emem = &thr->cgpu->epiphany_emem;
	unsigned core_n = &thr->cgpu->epiphany_core_n;

	uint32_t ostate;

	uint32_t *nonce = (uint32_t *)(pdata + 76);

	uint32_t data[20];
	const uint32_t go = 1;

	uint32_t tmp_hash7;
	uint32_t Htarg = ((const uint32_t *)ptarget)[7];
	bool ret = false;

	be32enc_vect(data, (const uint32_t *)pdata, 19);

	off_t offdata = _BufOffset + core_n * offsetof(shared_buf_t, data);
	off_t offostate = _BufOffset + core_n * offsetof(shared_buf_t, ostate);
	off_t offgo = _BufOffset + core_n * offsetof(shared_buf_t, go);

	while(1) {

		*nonce = ++n;
		data[19] = n;
		ostate = 0;

		e_write(&emem, 0, 0, offdata, (void *) &data, sizeof(data));
		e_write(&emem, 0, 0, offostate, (void *) &(ostate), sizeof(ostate));
		e_write(&emem, 0, 0, offgo, (void *) &go, sizeof(uint32_t));


		do {
			usleep(10);
			e_read(&emem, 0, 0, offostate, (void *) &(ostate), sizeof(ostate));
		} while (!ostate);

		tmp_hash7 = be32toh(ostate);

		if (unlikely(tmp_hash7 <= Htarg)) {
			((uint32_t *)pdata)[19] = htobe32(n);
			*last_nonce = n;
			ret = true;
			break;
		}

		if (unlikely((n >= max_nonce) || thr->work_restart)) {
			*last_nonce = n;
			break;
		}
	}

	return ret;
}

static int64_t epiphany_scanhash(struct thr_info *thr, struct work *work, int64_t max_nonce)
{
	const int thr_id = thr->id;
	unsigned char hash1[64];
	uint32_t first_nonce = work->blk.nonce;
	uint32_t last_nonce;
	bool rc;

	hex2bin(hash1, "00000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000010000", 64);
EPIPHANYSearch:
	last_nonce = first_nonce;
	rc = false;

	/* scan nonces for a proof-of-work hash */
	{
		rc = epiphany_scrypt(
			thr,
			work->midstate,
			work->data,
			hash1,
			work->hash,
			work->target,
			max_nonce,
			&last_nonce,
			work->blk.nonce
		);
	}

	/* if nonce found, submit work */
	if (unlikely(rc)) {
		applog(LOG_DEBUG, "EPIPHANY %d found something?", dev_from_id(thr_id));
		submit_work_async(work, NULL);
		work->blk.nonce = last_nonce + 1;
		goto EPIPHANYSearch;
	}
	else
	if (unlikely(last_nonce == first_nonce))
		return 0;

	work->blk.nonce = last_nonce + 1;
	return last_nonce - first_nonce + 1;
}

/*void epiphany_shutdown (struct thr_info *thr)
{
	e_close(&thr->cgpu->epiphany_dev);
	e_free(&thr->cgpu->epiphany_emem);
	e_finalize();
}*/

struct device_api epiphany_api = {
	.dname = "epiphany",
	.name = "EPIPHANY",
	.api_detect = epiphany_detect,
	.thread_prepare = epiphany_thread_prepare,
	.scanhash = epiphany_scanhash,
	.thread_shutdown = epiphany_shutdown,
};
#endif



