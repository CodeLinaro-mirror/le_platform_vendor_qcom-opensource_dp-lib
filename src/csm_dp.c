/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#define _GNU_SOURCE
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sched.h>
#include <pcap.h>
#include <pcap/dlt.h>
#include <syslog.h>
#include <limits.h>
#include "csm_dp_api.h"
#include "csm_dp_priv.h"

#define DEVICE_NODE_DEFAULT_NAME	"/dev/csm0-dp0"
#define DEFAULT_UL_BUFCNT	1024
#define DEFAULT_UL_BUFSZ	2048
#define SIZE_1K			1024
#define SIZE_1M			(SIZE_1K * 1024)

#define DP_PCAP_DEF_CAPTURE_LEN	(64 * SIZE_1K)
#define DP_PCAP_DEF_FILE_SIZE   (10 * SIZE_1M)
#define DP_PCAP_DEF_FILE_NUM    10

#define DP_LINK_HDR_SIZE        sizeof(struct dp_link_hdr)
#define DP_PCAP_HDR_SIZE        sizeof(struct dp_pcap_hdr)

// default capture file path
#define DP_PCAP_DEFAULT_DIR	"/mnt/ramfs"

#define TRUE_BUF_SIZE(memhdl) (memhdl->bufsz + memhdl->buf_overhead_sz)

enum csm_dp_direction
{
	CSM_DP_DIR_DL,
	CSM_DP_DIR_UL
};

struct pcaprec_hdr
{
	uint32_t ts_sec;
	uint32_t ts_usec;
	uint32_t caplen;
	uint32_t len;
} __attribute__((packed));

struct dp_link_hdr
{
	uint8_t direction;
	uint8_t channel;
	uint8_t reserved[2];
} __attribute__((packed));

struct dp_pcap_hdr
{
	struct pcaprec_hdr pcap_hdr;
	struct dp_link_hdr link_hdr;
} __attribute__((packed));

struct dp_cap_default_cbdata {
	struct csm_dp_cap_defcfg cfg;
	FILE *fp;
	size_t bytes;
	unsigned int file_idx;
};

/* static data */

bool lib_data_initialized;

static struct csm_dp_lib_data
	__libData[CSM_DP_MAX_BUS][CSM_DP_MAX_VF];

static const struct csm_dp_cap_defcfg __default_cap_cfg = {
	.file_name = DP_PCAP_DEFAULT_DIR"/csm_dp.pcap",
	.file_sz   = DP_PCAP_DEF_FILE_SIZE,
	.file_num  = DP_PCAP_DEF_FILE_NUM,
	.snap_len  = DP_PCAP_DEF_CAPTURE_LEN,
	.file_no_fflush = 1
};

/* declare */
static int __ring_get_element(uint16_t, struct csm_dp_ring_hdl *,
				csm_dp_ring_element_data_t *);
static int __ring_put_element(uint16_t, struct csm_dp_ring_hdl *,
				csm_dp_ring_element_data_t);

static int __csm_dp_rtx_hook(
	uint16_t handle,
	struct iovec *iov,
	unsigned int iovcnt,
	unsigned int event_id,
	enum csm_dp_channel ch);
static void *__capture_thread_main(void *);
static int __config_cap_hdl_default(uint16_t handle, struct csm_dp_cap_hdl *caphdl,
				    const struct csm_dp_cap_defcfg *cfg);

/* inlines */
static inline bool csm_dp_log_output_is_valid(int output)
{
	return (output < 0 || output > CSM_DP_LOG_OUTPUT_SYSLOG) ? false : true;
}

static inline bool csm_dp_log_level_is_valid(int level)
{
	return (level < 0 || level > LOG_DEBUG) ? false : true;
}

static inline bool csm_dp_log_cfg_is_valid(const struct csm_dp_log_cfg *cfg)
{
	return (csm_dp_log_output_is_valid(cfg->output) && csm_dp_log_level_is_valid(cfg->level));
}

static inline int is_offset_in_range(unsigned long offset, unsigned long start, unsigned long end)
{
	return (offset >= start && offset < end) ? 1 : 0;
}

static inline bool csm_dp_capture_max_event_is_valid(unsigned int max_event)
{
	return (max_event > CSM_DP_CAPTURE_MAX_EVENT) ? false : true;
}

static inline size_t get_offset(void *addr, void* base)
{
	return ((size_t)addr - (size_t)base);
}

unsigned int csm_dp_get_bus_index(uint16_t handle)
{
	unsigned int bus = handle & 0xF;
	if (bus >= CSM_DP_MAX_BUS)
		return INVALID_HANDLE;

	return bus;
}

unsigned int csm_dp_get_vf_index(uint16_t handle)
{
	unsigned int vf = (handle & 0xF0) >> 4;
	if (vf >= CSM_DP_MAX_VF)
		return INVALID_HANDLE;

	return vf;
}

uint16_t csm_dp_get_handle(int fd) {
	int bus_index, vf_index;
	uint16_t handle = INVALID_HANDLE;

	if (fd < 0)
		return handle;

	for (bus_index = 0; bus_index < CSM_DP_MAX_BUS; bus_index++) {
		for (vf_index = 0; vf_index < CSM_DP_MAX_VF; vf_index++) {
			if (__libData[bus_index][vf_index].fd == fd) {
				handle = bus_index | (vf_index << 4);
				return handle;
			}
		}
	}
	return handle;
}

static inline bool csm_dp_is_inited(uint16_t handle)
{
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);

	return (__libData[bus][vf].flag & LIB_FLAG_INITED);
}

static inline unsigned int ptr_to_buf_index(struct csm_dp_mem_hdl *memhdl,
					void *bufptr)
{
	size_t offset = get_offset(bufptr, memhdl->base);
	unsigned int cluster;
	unsigned int c_offset;

	cluster = offset / memhdl->cluster_size;
	c_offset = offset % memhdl->cluster_size;

	return ((c_offset / TRUE_BUF_SIZE(memhdl)) +
				(cluster * memhdl->buf_per_cluster));
}

/* ptr to start of buffer user space */
static inline void *buf_index_to_ptr(struct csm_dp_mem_hdl *memhdl,
					unsigned int index)
{
	unsigned int cluster;
	unsigned long offset;

	cluster = index / memhdl->buf_per_cluster;
	offset = (index % memhdl->buf_per_cluster) * TRUE_BUF_SIZE(memhdl);
	offset += cluster * memhdl->cluster_size;
	offset += memhdl->buf_overhead_sz; /* pass overhead */

	return ((char *) memhdl->base + offset);
}


static inline struct csm_dp_bufobj *ptr_to_bufobj(struct csm_dp_mem_hdl *memhdl, void *bufptr)
{
	unsigned int idx = ptr_to_buf_index(memhdl, bufptr);

	if (unlikely(idx >= memhdl->bufcnt))
		return NULL;
	return memhdl->buf_objs + idx;
}

/*
 * get aligned offset within base of a memory pool
 * It returns offset pointing to beginning of a buffer
 * which is the control area of the buffer.
 */
static inline size_t get_aligned_offset(struct csm_dp_mem_hdl *memhdl, void *bufptr)
{
	size_t offset = get_offset(bufptr, memhdl->base);
	unsigned int c_offset =  offset % memhdl->cluster_size;
	unsigned int n = c_offset % TRUE_BUF_SIZE(memhdl);

	return (offset - n);
}

static inline void init_mem_loc(struct csm_dp_mem_loc *loc, void *base, unsigned long length, bool mmap)
{
	loc->base = base;
	loc->length = length;
	loc->mmap = mmap;
}

static inline void cleanup_mem_loc(struct csm_dp_mem_loc *loc)
{
	if (loc->base) {
		if (loc->mmap)
			munmap(loc->base, loc->length);
		else
			free(loc->base);
	}
}

static inline bool csm_dp_cap_defcfg_is_valid(const struct csm_dp_cap_defcfg *cfg)
{
	size_t len;
	if (!cfg->file_num)
		return false;
	if (!cfg->file_sz)
		return false;
	len = strnlen(cfg->file_name, sizeof(cfg->file_name));
	if (!len || len >= sizeof(cfg->file_name))
		return false;

	return true;
}

static inline unsigned int calc_ring_size(unsigned int elements)
{
	unsigned int size = 1, shift = 0;

	for (shift = 0; (shift < (sizeof(unsigned int) * 8 - 1)); shift++) {
		if (size >= elements)
			return size;
		size <<= 1;
	}
	return 0;
}

/* get buffer overhead, ptr: pointing to beginning of user data or recv msg */
static inline struct csm_dp_buf_cntrl *csm_dp_get_buf_overhead(const void *ptr)
{

	return (struct csm_dp_buf_cntrl *)
				(((uint8_t *) (ptr)) - CSM_DP_L1_CACHE_BYTES);
}

/* To find mempool handler that the buffer belongs to */
static struct csm_dp_mempool_hdl *__find_mempool(uint16_t handle, const void *ptr)
{
	struct csm_dp_buf_cntrl *buf_cntrl = csm_dp_get_buf_overhead(ptr);
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return NULL;

	if (buf_cntrl->mem_type >= CSM_DP_MEM_TYPE_LAST)
		return NULL;

	return __libData[bus][vf].hdl[buf_cntrl->mem_type];
}

/* To increase reference number of bufobj which is associated with given address */
static inline void __mempool_hold_buf(struct csm_dp_mempool_hdl *hdl, void *bufptr)
{
	struct csm_dp_bufobj *bufobj = ptr_to_bufobj(&hdl->mem_hdl, bufptr);

	if (likely(bufobj))
		atomic_inc(&bufobj->refcnt);
}

/* To decrease reference number of bufobj. Free the buffer if it reaches zero */
static inline void __mempool_put_buf(uint16_t handle,
				     struct csm_dp_mempool_hdl *hdl,
				     void *bufptr)
{
	struct csm_dp_bufobj *bufobj = ptr_to_bufobj(&hdl->mem_hdl, bufptr);

	if (likely(bufobj)) {
		int refcnt = atomic_dec_if_positive(&bufobj->refcnt);

		if (refcnt == 1) {
			bufobj->handle = 0xdeadbeef;
			if (hdl->ops.free_buf)
				hdl->ops.free_buf(handle, hdl, bufptr);
		}
		else if (refcnt <= 0) {
			DP_LOG_ERR(handle, "buffer already freed, addr=%p\n", bufptr);
		}
	}
}

/* To free all the buffers which are hold by user */
static void __mempool_release_all_bufs(uint16_t handle, struct csm_dp_mempool_hdl *hdl)
{
	struct csm_dp_mem_hdl *memhdl = &hdl->mem_hdl;

	if (memhdl->buf_objs) {
		struct csm_dp_bufobj *bufobj = memhdl->buf_objs;
		unsigned int i;

		for (i = 0; i < memhdl->bufcnt; i++) {
			char *buf = buf_index_to_ptr(memhdl, i);

			if (atomic_read(&bufobj[i].refcnt) > 0) {
				if (hdl->ops.free_buf)
					hdl->ops.free_buf(handle, hdl, buf);

			}
		}
	}
}

#ifdef DRIVER_API_DEBUG
static void __mempool_cfg_dump(uint16_t handle, struct csm_dp_mempool_cfg *cfg)
{
	DP_LOG_DEBUG(handle, "Type:                %u\n", cfg->type);
	DP_LOG_DEBUG(handle, "MEM:\n");
	DP_LOG_DEBUG(handle, "   size:             %u\n", cfg->mem.mmap.length);
	DP_LOG_DEBUG(handle, "   mmap_cookie:      %08x\n", cfg->mem.mmap.cookie);
	DP_LOG_DEBUG(handle, "   mmap_offset:      %08x\n", cfg->mem.mmap.offset);
	DP_LOG_DEBUG(handle, "   bufSize:          %u\n", cfg->mem.buf_sz);
	DP_LOG_DEBUG(handle, "   bufCount:         %u\n", cfg->mem.buf_cnt);
	DP_LOG_DEBUG(handle, "   bufOverhead:      %u\n", cfg->mem.buf_overhead_sz);
	DP_LOG_DEBUG(handle, "RING:\n");
	DP_LOG_DEBUG(handle, "   memSize:          %u\n", cfg->ring.mmap.length);
	DP_LOG_DEBUG(handle, "   mmap_cookie:      %08x\n", cfg->ring.mmap.cookie);
	DP_LOG_DEBUG(handle, "   mmap_offset:      %08x\n", cfg->ring.mmap.offset);
	DP_LOG_DEBUG(handle, "   ringSize:         %u\n", cfg->ring.size);
	DP_LOG_DEBUG(handle, "   ProdHdrOffset:    %08x\n", cfg->ring.prod_head_off);
	DP_LOG_DEBUG(handle, "   ProdTailOffset:   %08x\n", cfg->ring.prod_tail_off);
	DP_LOG_DEBUG(handle, "   ConsHdrOffset:    %08x\n", cfg->ring.cons_head_off);
	DP_LOG_DEBUG(handle, "   ConsTailOffset:   %08x\n", cfg->ring.cons_tail_off);
	DP_LOG_DEBUG(handle, "   RingBufOffset:    %08x\n", cfg->ring.ringbuf_off);
}
#endif

/* Default buffer allocator */
static void *__default_alloc_buf(uint16_t handle, struct csm_dp_mempool_hdl *hdl)
{
	struct csm_dp_mem_hdl *mem_hdl = &hdl->mem_hdl;
	csm_dp_ring_element_data_t offset;
	char *buf = NULL;
	struct csm_dp_buf_cntrl *p;

	while (!__ring_get_element(handle, &hdl->ring_hdl, &offset)) {
		/* Ring contains offset */
		if (is_offset_in_range(offset, 0, mem_hdl->size) &&
		    is_offset_in_range(offset + mem_hdl->bufsz - 1, 0, mem_hdl->size)) {
			buf = (char *)mem_hdl->base + offset;
			break;
		}
		DP_LOG_ERR(handle, "Got invalid data from ring, data=0x%lx\n", offset);
	}

	if (!buf) {
		DP_LOG_ERR(handle, "No data in ring!\n");
		return NULL;
	}


	p = csm_dp_get_buf_overhead(buf);
#ifdef CSM_DP_BUFFER_FENCING
	if (p->fence != CSM_DP_BUFFER_FENCE_SIG ||
			p->signature != CSM_DP_BUFFER_SIG) {
		DP_LOG_ERR(handle,
			"%s: mem handle %p buffer corrupted,"
			" offset 0x%lx, fence 0x%x, expect 0x%x,"
			" signature 0x%x, expect 0x%x,"
			" buffer is lost\n",
			__func__, mem_hdl, offset, p->fence, CSM_DP_BUFFER_FENCE_SIG,
			p->signature, CSM_DP_BUFFER_SIG);
		buf = NULL; /* buffer is lost */
	} else
#endif
		p->state = CSM_DP_BUF_STATE_USER_ALLOC;
	return buf;
}

/* Default buffer deallocator */
static void __default_free_buf(uint16_t handle, struct csm_dp_mempool_hdl *hdl, void *buf)
{
	struct csm_dp_buf_cntrl *p;

	/* Note ring entry is pointing to a buffer after control overhead */
	csm_dp_ring_element_data_t offset =
		get_aligned_offset(&hdl->mem_hdl, buf) +
			hdl->mem_hdl.buf_overhead_sz;
	buf = (char *)hdl->mem_hdl.base + offset;
	p = csm_dp_get_buf_overhead(buf);
#ifdef CSM_DP_BUFFER_FENCING
	if (p->fence != CSM_DP_BUFFER_FENCE_SIG ||
			p->signature != CSM_DP_BUFFER_SIG) {
		DP_LOG_ERR(handle,
			"%s: mem handle %p buffer corrupted,"
			" offset 0x%lx, fence 0x%x, expect 0x%x,"
			" signature 0x%x, expect 0x%x,"
			" buffer is lost\n",
			__func__, &hdl->mem_hdl, offset, p->fence, CSM_DP_BUFFER_FENCE_SIG,
			p->signature, CSM_DP_BUFFER_SIG);
		/* buffer is lost */
	} else {
#else
	{
#endif

		/*
		 * Add a check pf->state to make sure kernel xmit is complete -
		 * CSM_DP_BUF_STATE_KERNEL_XMIT_DMA_COMP?
		 * If not, give a warning.
		 */
		p->state = CSM_DP_BUF_STATE_USER_FREE;
		if (__ring_put_element(handle, &hdl->ring_hdl, offset))
			DP_LOG_ERR(handle, "Failed to put data into ring, data=0x%lx\n", offset);
	}
}

/* Default mempool release */
static void __default_release(uint16_t handle, struct csm_dp_mempool_hdl *hdl)
{
	__mempool_release_all_bufs(handle, hdl);
}

/*
 * Initialize ring handler with the following procedures
 * - mmap the ring buffer into user space
 * - initialize the ring cons/prod pointer
*/
static int __init_ring_hdl(uint16_t handle,
			   struct csm_dp_ring_hdl *hdl,
			   struct csm_dp_ring_cfg *cfg)
{
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);
	struct csm_dp_mmap_cfg *mmap_cfg = &cfg->mmap;
	char *ptr;

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return -EINVAL;

	ptr = mmap(NULL, mmap_cfg->length, PROT_READ | PROT_WRITE, MAP_SHARED,
		   __libData[bus][vf].fd, mmap_cfg->cookie);
	if (ptr == MAP_FAILED) {
		DP_LOG_ERR(handle, "Failed to mmap ring memory, length=%llu cookie=0x%x\n",
			mmap_cfg->length, mmap_cfg->cookie);
		return -EAGAIN;
	}
	hdl->loc.base = ptr;
	hdl->loc.length = mmap_cfg->length;
	hdl->loc.mmap = true;

	hdl->ring_sz = cfg->size;
	hdl->cons_head = (csm_dp_ring_index_t *)(ptr + cfg->cons_head_off);
	hdl->cons_tail = (csm_dp_ring_index_t *)(ptr + cfg->cons_tail_off);
	hdl->prod_head = (csm_dp_ring_index_t *)(ptr + cfg->prod_head_off);
	hdl->prod_tail = (csm_dp_ring_index_t *)(ptr + cfg->prod_tail_off);
	hdl->ringbuf = (csm_dp_ring_element_t *)(ptr + cfg->ringbuf_off);

	DP_LOG_DEBUG(handle, "Ring is mapped, addr=%p length=0x%lx cons_head=%p cons_tail=%p "
		  "prod_head=%p prod_tail=%p ringbuf=%p\n",
		  hdl->loc.base, hdl->loc.length, hdl->cons_head, hdl->cons_tail,
		  hdl->prod_head, hdl->prod_tail, hdl->ringbuf);
	return 0;
}

/* To cleanup ring handler by unmapping the ring */
static void __cleanup_ring_hdl(struct csm_dp_ring_hdl *hdl)
{
	if (hdl->loc.base) {
		cleanup_mem_loc(&hdl->loc);
		memset(hdl, 0, sizeof(*hdl));
	}
}

static int __ring_hdl_alloc_ring(uint16_t handle,
				 struct csm_dp_ring_hdl *hdl,
				 unsigned int elements)
{
	unsigned int ring_sz = calc_ring_size(elements);
	unsigned int alloc_sz = ring_sz * sizeof(csm_dp_ring_element_t);
	char *ptr;

	if (!ring_sz)
		return -EINVAL;

	alloc_sz += 4 * CSM_DP_L1_CACHE_BYTES;
	ptr = (char *)aligned_alloc(CSM_DP_L1_CACHE_BYTES, alloc_sz);
	if (!ptr) {
		DP_LOG_ERR(handle, "Failed to allocate memory\n");
		return -ENOMEM;
	}

	init_mem_loc(&hdl->loc, ptr, alloc_sz, false);
	hdl->prod_head = (csm_dp_ring_index_t *)ptr;
	*hdl->prod_head = 0;
	ptr += CSM_DP_L1_CACHE_BYTES;
	hdl->prod_tail = (csm_dp_ring_index_t *)ptr;
	*hdl->prod_tail = 0;
	ptr += CSM_DP_L1_CACHE_BYTES;
	hdl->cons_head = (csm_dp_ring_index_t *)ptr;
	*hdl->cons_head = 0;
	ptr += CSM_DP_L1_CACHE_BYTES;
	hdl->cons_tail = (csm_dp_ring_index_t *)ptr;
	*hdl->cons_tail = 0;
	ptr += CSM_DP_L1_CACHE_BYTES;
	hdl->ringbuf = (csm_dp_ring_element_t *)ptr;
	hdl->ring_sz = ring_sz;
	return 0;
}

/* To read one element from ring buffer */
static int __ring_get_element(uint16_t handle,
			      struct csm_dp_ring_hdl *hdl,
			      csm_dp_ring_element_data_t *pdata)
{
	register csm_dp_ring_index_t cons_head, cons_next;
	register csm_dp_ring_index_t prod_tail, mask;
	csm_dp_ring_element_data_t data;

	if (!hdl || !pdata) {
		DP_LOG_ERR(handle, "%s: null pointer!\n", __func__);
		return -EINVAL;
	}

	mask = hdl->ring_sz - 1;

again:
	cons_head = *hdl->cons_head;
	prod_tail = *hdl->prod_tail;
	rmb();

	if ((cons_head & mask) == (prod_tail & mask)) {
		rmb();
		if (cons_head == *hdl->cons_head && prod_tail == *hdl->prod_tail) {
			atomic_inc(&hdl->opstats.read_empty);
			return -EAGAIN;
		}
		goto again;
	}
	cons_next = cons_head + 1;
	if (atomic_cmpxchg(hdl->cons_head,
			   cons_head,
			   cons_next) != cons_head)
		goto again;

	/* Read the ring */
	data = hdl->ringbuf[(cons_head & mask)].element_data;
	rmb();

	if (pdata)
		*pdata = data;

	atomic_inc(&hdl->opstats.read_ok);

	/* Potential two consumer is updating */
	while(atomic_cmpxchg(hdl->cons_tail,
			   cons_head,
			   cons_next) != cons_head);

	return 0;
}

/* To put one element into ring buffer */
static int __ring_put_element(uint16_t handle,
			      struct csm_dp_ring_hdl *hdl,
			      csm_dp_ring_element_data_t data)
{
	register csm_dp_ring_index_t prod_head, prod_next;
	register csm_dp_ring_index_t cons_tail, mask;

	if (!hdl) {
		DP_LOG_ERR(handle, "%s: null pointer!\n", __func__);
		return -EINVAL;
	}

	mask = hdl->ring_sz - 1;

again:
	prod_head = *hdl->prod_head;
	cons_tail = *hdl->cons_tail;
	rmb();
	prod_next = prod_head + 1;
	if ((prod_next & mask) == (cons_tail & mask)) {
		rmb();
		if (prod_head == *hdl->prod_head && cons_tail == *hdl->cons_tail) {
			atomic_inc(&hdl->opstats.write_full);
			return -EAGAIN;
		}
		goto again;
	}
	if (atomic_cmpxchg(hdl->prod_head,
			   prod_head,
			   prod_next) != prod_head)
		goto again;

	hdl->ringbuf[(prod_head & mask)].element_data = data;
	wmb();

	atomic_inc(&hdl->opstats.write_ok);

	/* Potential two producer is updating */
	while(atomic_cmpxchg(hdl->prod_tail,
			   prod_head,
			   prod_next) != prod_head);

	return 0;
}

/*
 * Initialize the memory handler with the following procedure
 * - mmap DP memory into user space
 * - initialize the handler
 * - allocate bufobj to track the buffer usage
 */
static int __init_mem_hdl(uint16_t handle,
			  struct csm_dp_mem_hdl *hdl,
			  struct csm_dp_mem_cfg *cfg)
{
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);
	struct csm_dp_mmap_cfg *mmap_cfg = &cfg->mmap;
	void *ptr;

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return -EINVAL;

	ptr = mmap(NULL, mmap_cfg->length, PROT_READ | PROT_WRITE, MAP_SHARED,
		   __libData[bus][vf].fd, mmap_cfg->cookie);
	if (ptr == MAP_FAILED) {
		DP_LOG_ERR(handle, "Failed to mmap buffer memory, length=%llu cookie=0x%x\n",
			mmap_cfg->length, mmap_cfg->cookie);
		return -EAGAIN;
	}
	hdl->loc.base = ptr;
	hdl->loc.length = mmap_cfg->length;
	hdl->loc.mmap = true;

	hdl->base = (char *)ptr;
	hdl->bufcnt = cfg->buf_cnt;
	hdl->bufsz = cfg->buf_sz;
	hdl->buf_headroom_sz = 0;
	hdl->buf_overhead_sz = cfg->buf_overhead_sz;
	hdl->cluster_size = cfg->cluster_size;
	hdl->num_cluster = cfg->num_cluster;
	hdl->size = ((long)cfg->num_cluster * cfg->cluster_size) +
			(cfg->buf_cnt % cfg->buf_per_cluster) *
				(cfg->buf_sz + cfg->buf_overhead_sz);
	hdl->buf_per_cluster = cfg->buf_per_cluster;

	hdl->buf_objs = calloc(hdl->bufcnt, sizeof(*hdl->buf_objs));
	if (!hdl->buf_objs) {
		DP_LOG_ERR(handle, "Failed to allocate buffer object\n");
		return -ENOMEM;
	}

	DP_LOG_DEBUG(handle, "Map memory into user space, mmap_retaddr=%p mmap_len=0x%lx base=%p size=0x%lx\n",
		  hdl->loc.base, hdl->loc.length, hdl->base, hdl->size);
	return 0;
}

/*
 * To cleanup memory handler
 * - unmap DP memory
 * - free the memory allocated from bufobj
 */
static void __cleanup_mem_hdl(struct csm_dp_mem_hdl *hdl)
{
	if (hdl->loc.base)
		cleanup_mem_loc(&hdl->loc);

	if (hdl->buf_objs)
		free(hdl->buf_objs);

	memset(hdl, 0, sizeof(*hdl));
}

/* To create mempool handler */
static struct csm_dp_mempool_hdl *__create_mempool_hdl(uint16_t handle,
						       enum csm_dp_mem_type type)
{
	struct csm_dp_mempool_hdl *hdl;

	hdl = malloc(sizeof(*hdl));
	if (!hdl) {
		DP_LOG_ERR(handle, "Failed to allocate handler!\n");
		return NULL;
	}

	memset(hdl, 0, sizeof(*hdl));

	if (csm_dp_mem_type_is_dl(type)) {
		/* For DL, the ring is fully controlled by library */
		hdl->ops.alloc_buf = __default_alloc_buf;
		hdl->ops.free_buf = __default_free_buf;
		hdl->ops.release = __default_release;
	} else if (csm_dp_mem_type_is_ul(type)) {
		/* For UL, no allocation. The buffer is returned by csm_dp_receive API */
		hdl->ops.free_buf = __default_free_buf;
		hdl->ops.release = __default_release;
	}

	hdl->type = type;
	return hdl;
}

void __sync_rx_ring_hdl(uint16_t handle,
			enum csm_dp_rx_type type,
			struct csm_dp_ring_hdl *hdl)
{
	if (*hdl->cons_head != *hdl->cons_tail) {
		DP_LOG_ERR(handle,
			"%s: rx_ring type %d, consumer head %d "
			"does not match consumer tail %d\n",
			__func__, type, *hdl->cons_head, *hdl->cons_tail);

		*hdl->cons_tail = *hdl->cons_head;
		wmb();
	}
}

/*
 * To initialize mempool handler
 * - use ioctl to let driver allocate memory pool
 * - initialize memory handler
 * - initialize ring handler
 */
static int __init_mempool_hdl(uint16_t handle,
	struct csm_dp_mempool_hdl *hdl,
	unsigned int bufsz,
	unsigned int bufcnt)
{
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);
	struct csm_dp_ioctl_mempool_alloc req;
	struct csm_dp_mempool_cfg cfg;
	int ret;

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return -EINVAL;

	req.type = hdl->type;
	req.buf_num = bufcnt;
	req.buf_sz = bufsz;
	req.cfg = &cfg;

	/* Let kernel allocate memory */
	ret = ioctl(__libData[bus][vf].fd,
		    CSM_DP_IOCTL_MEMPOOL_ALLOC, &req);
	if (ret) {
		DP_LOG_ERR(handle, "CSM_DP_IOCTL_MEM_ALLOC ioctl failed, err=%d\n", ret);
		return ret;
	}

#ifdef DRIVER_API_CHECK
	if (cfg.mem.buf_sz < bufsz) {
		DP_LOG_ERR(handle, "API-CHECK: failed, buf_sz %u, expect %u\n", cfg.mem.buf_sz, req.buf_sz);
		return -EINVAL;
	}
	if (cfg.mem.buf_cnt < bufcnt) {
		DP_LOG_ERR(handle, "API-CHECK: failed, buf_cnt %u, expect %u\n", cfg.mem.buf_cnt, bufCnt);
		return -EINVAL;
	}
	if (cfg.type != hdl->type) {
		DP_LOG_ERR(handle, "API-CHECK: failed, type %u, expect %u\n", cfg.type, hdl->type);
		return -EINVAL;
	}
#endif

#ifdef DRIVER_API_DEBUG
	__mempool_cfg_dump(&cfg, handle);
#endif

	/* mmap buffer memory */
	if (__init_mem_hdl(handle, &hdl->mem_hdl, &cfg.mem)) {
		DP_LOG_ERR(handle, "Failed to initialize memory handler!\n");
		return -EAGAIN;
	}

	if (__init_ring_hdl(handle, &hdl->ring_hdl, &cfg.ring)) {
		DP_LOG_ERR(handle, "Failed to initialize ring handler!\n");
		return -EAGAIN;
	}


	return 0;
}

/*
 * To free mempool handler
 * - invoke release callback
 * - cleanup ring handler
 * - cleanup memory handler
 * - free mempool handler
*/
static void __free_mempool_hdl(uint16_t handle, struct csm_dp_mempool_hdl *hdl)
{
	if (hdl) {
		if (hdl->ops.release)
			hdl->ops.release(handle, hdl);
		__cleanup_ring_hdl(&hdl->ring_hdl);
		__cleanup_mem_hdl(&hdl->mem_hdl);
		free(hdl);
	}
}

/*
 * To allocate rx handler
 */
static struct csm_dp_rx_hdl *__create_rx_hdl(uint16_t handle,
					     enum csm_dp_mmap_type type)
{
	struct csm_dp_rx_hdl *rxhdl;

	rxhdl = malloc(sizeof(*rxhdl));
	if (!rxhdl) {
		DP_LOG_ERR(handle, "%s: memory allocation failed!\n", __func__);
		return NULL;
	}

	rxhdl->type = (enum csm_dp_rx_type)type;
	return rxhdl;
}

/*
 * To initialize rx handler
 * - get RX ring config from kernel
 * - map RX ring into user space
*/
static int __init_rx_hdl(uint16_t handle,
			 struct csm_dp_rx_hdl *hdl)
{
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);
	struct csm_dp_ring_cfg cfg;
	struct csm_dp_ioctl_getcfg req;
	int ret;

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return -EINVAL;

	memset(&cfg, 0, sizeof(cfg));
	req.type = hdl->type;
	req.cfg = &cfg;

	ret = ioctl(__libData[bus][vf].fd,
		    CSM_DP_IOCTL_RX_GET_CONFIG,
		    &req);
	if (ret) {
		DP_LOG_ERR(handle, "CSM_DP_IOCTL_RX_GET_CONFIG failed, err=%d\n", ret);
		return ret;
	}

	ret = __init_ring_hdl(handle, &hdl->ring_hdl, &cfg);
	if (ret) {
		DP_LOG_ERR(handle, "Failed to initalize rx ring handler!\n");
		return ret;
	}

	__sync_rx_ring_hdl(handle, hdl->type, &hdl->ring_hdl);
	DP_LOG_DEBUG(handle, "Initialized rx handler, rx_type=%u\n", hdl->type);

	return 0;
}

/* Free rx handler */
static void __free_rx_hdl(struct csm_dp_rx_hdl *hdl)
{
	__cleanup_ring_hdl(&hdl->ring_hdl);
	free(hdl);
}

/* Initialize capture event handler */
static int __init_cap_event_hdl(uint16_t handle,
				struct csm_dp_cap_event_hdl *hdl,
				unsigned int event_cnt)
{
	struct csm_dp_cap_event *event;
	int ret = 0;
	unsigned int i;

	event = malloc(event_cnt * sizeof(struct csm_dp_cap_event));
	if (!event) {
		DP_LOG_ERR(handle, "Failed to allocate memory for capture event\n");
		return -ENOMEM;
	}

	ret = __ring_hdl_alloc_ring(handle, &hdl->event_ring, event_cnt);
	if (ret) {
		DP_LOG_ERR(handle, "Failed to allocate event ring\n");
		free(event);
		return ret;
	}

	ret = __ring_hdl_alloc_ring(handle, &hdl->free_ring, event_cnt);
	if (ret) {
		DP_LOG_ERR(handle, "Failed to allocate free ring\n");
		__cleanup_ring_hdl(&hdl->event_ring);
		free(event);
		return ret;
	}

	for (i = 0; i < event_cnt; i++)
		__ring_put_element(handle, &hdl->free_ring, (csm_dp_ring_element_data_t)&event[i]);

	hdl->event_mem = event;
	return 0;
}

/* Cleanup capture event handler */
static void __cleanup_cap_event_hdl(struct csm_dp_cap_event_hdl *hdl)
{
	if (hdl->event_mem) {
		__cleanup_ring_hdl(&hdl->free_ring);
		__cleanup_ring_hdl(&hdl->event_ring);
		free(hdl->event_mem);
		memset(hdl, 0, sizeof(*hdl));
	}
}

/* Initialize capture handler
 * - allocate and initialize event handler
 * - install callback function
 * - start capture pthread
 */
static int __init_cap_hdl(uint16_t handle,
	struct csm_dp_cap_hdl *hdl,
	const struct csm_dp_cap_cb_ops *cb_ops,
	void *cookie,
	unsigned int event_num)
{
	int ret;
	char thread_name[30] = {0x00};
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return -EINVAL;

	hdl->handle = handle;

	ret = __init_cap_event_hdl(handle, &hdl->event_hdl, event_num);
	if (ret) {
		DP_LOG_ERR(handle, "Failed to initialize cap_event handler\n");
		return ret;
	}
	if (cb_ops) {
		hdl->priv_data = cookie;
		memcpy(&hdl->ops, cb_ops, sizeof(hdl->ops));
	} else if ((ret = __config_cap_hdl_default(handle, hdl, cookie))) {
		DP_LOG_ERR(handle, "Failed to config default cap handling\n");
		return ret;
	}

	ret = sem_init(&hdl->sem, 0, 0);
	if (ret) {
		DP_LOG_ERR(handle, "Failed to initialize semaphore\n");
		return ret;
	}
	ret = pthread_create(&hdl->pid, NULL, __capture_thread_main, hdl);
	snprintf(thread_name, sizeof(thread_name), "CAPTURE_%u_%u",
		bus, vf);
	pthread_setname_np(hdl->pid, thread_name);

	return ret;
}


static void __cleanup_cap_hdl(struct csm_dp_cap_hdl *hdl)
{
	__cleanup_cap_event_hdl(&hdl->event_hdl);
	if (hdl->priv_data && hdl->free_priv)
		free(hdl->priv_data);
	sem_destroy(&hdl->sem);
}

static inline struct csm_dp_cap_event *__ring_get_cap_event(uint16_t handle,
							    struct csm_dp_ring_hdl *hdl)
{
	struct csm_dp_cap_event *event;

	if (__ring_get_element(handle, hdl, (csm_dp_ring_element_data_t *)&event))
		return NULL;
	return event;
}

static inline void __ring_put_cap_event(uint16_t handle,
					struct csm_dp_ring_hdl *hdl,
					struct csm_dp_cap_event *event)
{
	if (event)
		__ring_put_element(handle, hdl, (csm_dp_ring_element_data_t)event);
}

static int __init_dp_log(const struct csm_dp_log_cfg *cfg)
{
	switch (cfg->output) {
	case CSM_DP_LOG_OUTPUT_SYSLOG:
		openlog("csm_dp_lib", LOG_CONS | LOG_NDELAY | LOG_PID, LOG_USER);
		break;
	default:
		break;
	}
	return 0;
}

void csm_dp_log(uint16_t handle, int level, const char *fmt, ...)
{
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);
	struct csm_dp_log_cfg *logcfg;
	va_list args;

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF) {
		printf("%s failed \n", __func__);
		return;
	}

	logcfg = &__libData[bus][vf].logcfg;

	if (unlikely(!csm_dp_is_inited(handle)))
		return;
	if (level > logcfg->level)
		return;

	switch (logcfg->output) {
	case CSM_DP_LOG_OUTPUT_CONSOLE:
		va_start(args, fmt);
		vprintf(fmt, args);
		va_end(args);
		break;
	case CSM_DP_LOG_OUTPUT_SYSLOG:
		va_start(args, fmt);
		vsyslog(level, fmt, args);
		va_end(args);
		break;
	default:
		break;
	}
}

static int __cleanup_dp_log(struct csm_dp_log_cfg *cfg)
{
	switch (cfg->output) {
	case CSM_DP_LOG_OUTPUT_SYSLOG:
		closelog();
		break;
	default:
		break;
	}
	memset(cfg, 0, sizeof(*cfg));
	return 0;
}

/*
 * To create and initialize DP memory pool. Mutex is locked
*/
static int __csm_dp_init_mem(
	uint16_t handle,
	enum csm_dp_mem_type type,
	unsigned int bufsz,
	unsigned int bufcnt)
{
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);
	struct csm_dp_mempool_hdl *hdl = NULL;
	int ret = 0;

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return -EINVAL;

	if (__libData[bus][vf].hdl[type]) {
		DP_LOG_WARN(handle, "mempool handler created!\n");
		return -EBUSY;
	}
	hdl = __create_mempool_hdl(handle, type);
	if (hdl == NULL) {
		DP_LOG_ERR(handle, "Failed to create mempool_hdl, type=%u, bufCnt=%u\n", type, bufcnt);
		return -ENOMEM;
	}
	ret = __init_mempool_hdl(handle, hdl, bufsz, bufcnt);
	if (ret) {
		DP_LOG_ERR(handle, "Failed to initialize memhdl!\n");
		__free_mempool_hdl(handle, hdl);
		return ret;
	}

	__libData[bus][vf].hdl[type] = hdl;

	return 0;
}

/**
 * @brief
 * Initialize the library with a user provide device node name.
 * See csm_dp_init for more details.
 *
 * @param dev_name - device node name, e.g. "/dev/csm0-dp1"
 * @param logcfg - pointer to the structure which contains the
 *      	library logging configuration
 *
 * @return On success, it returns file descriptor of DP device
 *         If it fails, it returns negative value
 */
int csm_dp_init_ex(const char *dev_name,
		   const struct csm_dp_log_cfg *logcfg)
{
	int fd, ret;
	char *ptr = NULL, *base = NULL;
	unsigned int bus_num, vf_num, handle = 0;
	unsigned int bus_index, vf_index;

	if (dev_name == NULL)
		return -EINVAL;

	base = strstr(dev_name, "csm");
	if(!base)
		return -EINVAL;

	bus_num = strtoul(base + 3, &ptr, 0);
	if (bus_num >= CSM_DP_MAX_BUS)
		return -EINVAL;

	base = strstr(dev_name, "-dp");
	if(!base)
		return -EINVAL;

	vf_num = strtoul(base + 3, &ptr, 0);
	if (vf_num >= CSM_DP_MAX_VF)
		return -EINVAL;

	if (!lib_data_initialized) {
		memset(&__libData, 0, sizeof(__libData));
		for (bus_index = 0; bus_index < CSM_DP_MAX_BUS; bus_index++) {
			for (vf_index = 0; vf_index < CSM_DP_MAX_VF; vf_index++) {
				__libData[bus_index][vf_index].fd = -1;
			}
		}
		lib_data_initialized = true;
	}

	handle = CREATE_HANDLE(bus_num, vf_num);

	if (csm_dp_is_inited(handle)) {
		DP_LOG_DEBUG(handle, "Lib already initialized!\n");
		return __libData[bus_num][vf_num].fd;
	}

	fd = open(dev_name, O_RDWR);
	if (fd < 0) {
		DP_LOG_ERR(handle, "Failed to open device file!\n");
		return -ENODEV;
	}

	if (logcfg) {
		if (!csm_dp_log_cfg_is_valid(logcfg)) {
			DP_LOG_ERR(handle, "Invalid log configuration\n");
			return -EINVAL;
		}
		memcpy(&__libData[bus_num][vf_num].logcfg,
		       logcfg, sizeof(*logcfg));
	}
	if ((ret = __init_dp_log(&__libData[bus_num][vf_num].logcfg))) {
		close(fd);
		return ret;
	}

	pthread_mutex_init(&__libData[bus_num][vf_num].mutex, NULL);
	pthread_mutex_init(&__libData[bus_num][vf_num].tx_mutex, NULL);
	pthread_mutex_init(&__libData[bus_num][vf_num].rx_c_mutex, NULL);
	pthread_mutex_init(&__libData[bus_num][vf_num].rx_d_mutex, NULL);
	atexit(csm_dp_cleanup);
	__libData[bus_num][vf_num].fd = fd;
	__libData[bus_num][vf_num].flag |= LIB_FLAG_INITED;

	DP_LOG_DEBUG(handle, "%s: dev_name %s fd %d\n", __func__, dev_name, fd);

	return fd;
}

/**
 * @brief
 * Initialize the library with the default device node name (/dev/csm0-dp0).
 * It must be called before using library API.
 *
 * The logcfg argument can be specified as NULL. In this case,
 * the library will use default setting to output logging to
 * syslog with log level set to LOG_DEBUG.
 *
 * @param logcfg - pointer to the structure which contains the
 *      	library logging configuration
 * @return On success, it returns file descriptor of DP device
 *         If it fails, it returns negative value
 */
int csm_dp_init(const struct csm_dp_log_cfg *logcfg)
{
	return csm_dp_init_ex(DEVICE_NODE_DEFAULT_NAME, logcfg);
}

/**
 * @brief
 * Cleanup the library using vf. After it returns, the file descriptor is
 * closed and all the mmaped DP memory areas are unmapped. Any
 * attempt to access those memory regions will cause page fault.
 *
 * @param handle - Handle for a csm_dp instance
 * @return None
 */
void csm_dp_cleanup_vf(uint16_t handle)
{
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);
	int type;

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return;

	if (__libData[bus][vf].fd == -1) {
		DP_LOG_DEBUG(handle, "%s: invalid fd for bus:%u vf:%u\n",
				__func__, bus, vf);
		return;
	}
	printf("%s: called for bus:%u vf:%u\n", __func__, bus, vf);

	if (!csm_dp_is_inited(handle))
		return;

	DP_LOG_DEBUG(handle, "%s: start\n", __func__);

	for (type = 0; type < CSM_DP_RX_TYPE_LAST; type++) {
		if (__libData[bus][vf].rxhdl[type]) {
			__free_rx_hdl(__libData[bus][vf].rxhdl[type]);
			__libData[bus][vf].rxhdl[type] = NULL;
		}
	}

	for (type = 0; type < CSM_DP_MEM_TYPE_LAST; type++) {
		if (__libData[bus][vf].hdl[type]) {
			__free_mempool_hdl(handle, __libData[bus][vf].hdl[type]);
			__libData[bus][vf].hdl[type] = NULL;
		}
	}

	pthread_mutex_destroy(&__libData[bus][vf].mutex);
	DP_LOG_DEBUG(handle, "%s: closing fd\n", __func__);
	close(__libData[bus][vf].fd);
	__cleanup_dp_log(&__libData[bus][vf].logcfg);
	__libData[bus][vf].flag &= ~LIB_FLAG_INITED;
}

/**
 * @brief
 * Cleanup the library. After it returns, the file descriptor is
 * closed and all the mmaped DP memory areas are unmapped. Any
 * attempt to access those memory regions will cause page fault.
 *
 * @return None
 */
void csm_dp_cleanup(void)
{
	int type, bus, vf;
	uint16_t handle;

	for (bus = 0; bus < CSM_DP_MAX_BUS; bus++) {

		for (vf = 0; vf < CSM_DP_MAX_VF; vf++) {

			if (__libData[bus][vf].fd == -1)
				continue;

			handle = CREATE_HANDLE(bus, vf);

			if (!csm_dp_is_inited(handle))
				return;

			DP_LOG_DEBUG(handle, "%s: start\n", __func__);

			for (type = 0; type < CSM_DP_RX_TYPE_LAST; type++) {
				if (__libData[bus][vf].rxhdl[type]) {
					__free_rx_hdl(__libData[bus][vf].rxhdl[type]);
					__libData[bus][vf].rxhdl[type] = NULL;
				}
			}

			for (type = 0; type < CSM_DP_MEM_TYPE_LAST; type++) {
				if (__libData[bus][vf].hdl[type]) {
					__free_mempool_hdl(handle, __libData[bus][vf].hdl[type]);
					__libData[bus][vf].hdl[type] = NULL;
				}
			}

			pthread_mutex_destroy(&__libData[bus][vf].mutex);
			DP_LOG_DEBUG(handle, "%s: closing fd\n", __func__);
			close(__libData[bus][vf].fd);
			__cleanup_dp_log(&__libData[bus][vf].logcfg);
			__libData[bus][vf].flag &= ~LIB_FLAG_INITED;
		}
	}
}

/**
 * @brief
 * Initialize the memory access to specific DP memory region
 *
 * The following procedures are used in library
 * - instruct DP driver to allocate contiguous DP memory
 * - mmap the DP memory into user space
 * - mmap ring buffer for buffer management into user space
 *
 * DP API uses fixed-size(2K) buffer for messaging. Each data
 * path has its own memory region. For DL, DP memory region is
 * created by API and shared between processes. For UL, UL DP
 * memory region is created by kernel and shared by all UL data
 * path.
 *
 * The ring buffer is shared between kernel and API for buffer
 * management.
 *
 * @param type - type of DP memory region
 * @param buf_sz - size of buffer in bytes.
 * @param buf_num - size of DP memory region in number of
 *      	  fixed-size buffer
 * @param handle - Handle for a csm_dp instance
 *
 * @return On success - 0, otherwise failed
 */
int csm_dp_init_mem(
	uint16_t handle,
	enum csm_dp_mem_type type,
	unsigned int buf_sz,
	unsigned int buf_num)
{
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);
	int ret = 0;

	DP_LOG_DEBUG(handle, "%s: type %d buf_sz %d buf_num %d\n", __func__, type, buf_sz, buf_num);

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return -EINVAL;


	if (!csm_dp_is_inited(handle)) {
		DP_LOG_ERR(handle, "Library is not intialized!\n");
		return -EAGAIN;
	}

	if (!csm_dp_mem_type_is_valid(type)) {
		DP_LOG_ERR(handle, "Invalid memory type %d\n", type);
		return -EINVAL;
	}
	if (!buf_num) {
		DP_LOG_ERR(handle, "Invalid buffer counter(%u)\n", buf_num);
		return -EINVAL;
	}
	if (!buf_sz || buf_sz > CSM_DP_MAX_DL_MSG_LEN) {
		DP_LOG_ERR(handle, "Buffer size(%u) exceeds limit %d\n",
			buf_sz, CSM_DP_MAX_DL_MSG_LEN);
		return -EINVAL;
	}

	pthread_mutex_lock(&__libData[bus][vf].mutex);
	ret = __csm_dp_init_mem(handle, type, buf_sz, buf_num);
	pthread_mutex_unlock(&__libData[bus][vf].mutex);

	DP_LOG_DEBUG(handle, "%s: end\n", __func__);

	return ret;
}

/**
 * @brief
 * Cleanup before stop accessing DP memory region
 *
 * The DP memory region and the associated ring buffer will be
 * unmapped. On return of this api, any attempt to access this
 * DP memory region will cause page fault.
 *
 * @param handle - Handle for a csm_dp instance
 * @param type - type of DP memory region to cleanup
 *
 * @return None
 */
void csm_dp_cleanup_mem(uint16_t handle, enum csm_dp_mem_type type)
{
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return;

	DP_LOG_DEBUG(handle, "%s: type %d\n", __func__, type);

	if (csm_dp_is_inited(handle) && csm_dp_mem_type_is_valid(type)) {
		struct csm_dp_mempool_hdl *hdl = __libData[bus][vf].hdl[type];

		if (hdl) {
			pthread_mutex_lock(&__libData[bus][vf].mutex);
			__free_mempool_hdl(handle, hdl);
			__libData[bus][vf].hdl[type] = NULL;
			pthread_mutex_unlock(&__libData[bus][vf].mutex);
		}
	}

	DP_LOG_DEBUG(handle, "%s: end\n", __func__);
}

/**
 * @brief
 * Initialize UL for receiving data.
 *
 * There is currently one type of UL datapath: CSM_DP_RX_TYPE_FAPI
 *
 * The following procedures are used in library for UL
 * datapath
 * - get UL DP memory region details from driver
 * - mmap UL DP memory into user space
 * - mmap ring buffer for buffer management into user space
 * - mmap ring buffer for receiving queue into user space
 *
 * @param handle - Handle for a csm_dp instance
 *
 * @return On success - 0, otherwise failed
 */
int csm_dp_init_rx(uint16_t handle)
{
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);
	struct csm_dp_rx_hdl *rxhdl;
	int ret = 0;
	enum csm_dp_rx_type type = CSM_DP_RX_TYPE_FAPI;

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return -EINVAL;

	DP_LOG_DEBUG(handle, "%s: start\n", __func__);

	if (!csm_dp_is_inited(handle)) {
		DP_LOG_ERR(handle, "Library is not intialized!\n");
		return -EAGAIN;
	}
	if (!csm_dp_rx_type_is_valid(type)) {
		DP_LOG_ERR(handle, "Invalid rx type(%d)\n", type);
		return -EINVAL;
	}

	pthread_mutex_lock(&__libData[bus][vf].mutex);
	if (__libData[bus][vf].rxhdl[type]) {
		rxhdl = __libData[bus][vf].rxhdl[type];
		if (rxhdl->type != type) {
			DP_LOG_ERR(handle, "Can't reintialize RX to different type!\n");
			ret = -EBUSY;
		}
		pthread_mutex_unlock(&__libData[bus][vf].mutex);
		return ret;
	}

	if ((__libData[bus][vf].hdl[CSM_DP_MEM_TYPE_UL_CONTROL] == NULL)) {

		ret = __csm_dp_init_mem(handle,
					CSM_DP_MEM_TYPE_UL_CONTROL,
					DEFAULT_UL_BUFSZ,
					DEFAULT_UL_BUFCNT);
		if (ret) {
			DP_LOG_ERR(handle, "Failed to initialize UL_CONTROL memory!\n");
			pthread_mutex_unlock(&__libData[bus][vf].mutex);
			return ret;
		}
	}

	if ((__libData[bus][vf].hdl[CSM_DP_MEM_TYPE_UL_DATA] == NULL)) {
		ret = __csm_dp_init_mem(handle,
					CSM_DP_MEM_TYPE_UL_DATA,
					DEFAULT_UL_BUFSZ,
					DEFAULT_UL_BUFCNT);
		if (ret) {
			DP_LOG_ERR(handle, "Failed to initialize UL_DATA memory!\n");
			pthread_mutex_unlock(&__libData[bus][vf].mutex);
			return ret;
		}
	}

	rxhdl = __create_rx_hdl(handle, (enum csm_dp_mmap_type)type);
	if (rxhdl == NULL) {
		DP_LOG_ERR(handle, "Failed to allocate rx handler\n");
		pthread_mutex_unlock(&__libData[bus][vf].mutex);
		return -ENOMEM;
	}

	ret = __init_rx_hdl(handle, rxhdl);
	if (ret) {
		DP_LOG_ERR(handle, "Failed to initialize rx handler\n");
		__free_rx_hdl(rxhdl);
		pthread_mutex_unlock(&__libData[bus][vf].mutex);
		return ret;
	}

	__libData[bus][vf].rxhdl[type] = rxhdl;
	pthread_mutex_unlock(&__libData[bus][vf].mutex);

	DP_LOG_DEBUG(handle, "%s: end\n", __func__);

	return 0;
}

/**
 * @brief
 * Allocate DL buffer for TX
 *
 * The library preserves the headroom for message header. It
 * returns the buffer pointer which points to the starting of
 * message payload
 *
 * @param dev_handle - Handle for a csm_dp instance
 * @param type - type of DP memory region
 * @param length - length of buffer for message payload
 *
 * @return The buffer pointer or NULL if it fails.
 */
static void *__csm_dp_ealloc_txbuf(uint16_t dev_handle,
				   enum csm_dp_mem_type type,
				   unsigned int length,
				   unsigned int *handle)
{
	unsigned int bus = csm_dp_get_bus_index(dev_handle);
	unsigned int vf = csm_dp_get_vf_index(dev_handle);
	struct csm_dp_mempool_hdl *hdl;
	char *p = NULL;
	char *busy_buf = NULL;
	char *buf = NULL;

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return NULL;

	if (!csm_dp_mem_type_is_valid(type)) {
		DP_LOG_ERR(dev_handle, "Cannot allocate buffer, invalid memory type %d!\n", type);
		return NULL;
	}

	hdl = __libData[bus][vf].hdl[type];
	if (hdl && hdl->ops.alloc_buf && hdl->ops.free_buf) {
		struct csm_dp_mem_hdl *memhdl = &hdl->mem_hdl;

		if (memhdl->bufsz < (length + memhdl->buf_headroom_sz)) {
			DP_LOG_ERR(dev_handle, "buffer length(%u) is out of range (%u)!\n",
					length, memhdl->bufsz - memhdl->buf_headroom_sz);
			return NULL;
		}
again:
		p = hdl->ops.alloc_buf(dev_handle, hdl);
		if (p) {
			struct csm_dp_bufobj *bufobj;
			struct csm_dp_buf_cntrl *pcntrl;

			if (p == busy_buf) {
				hdl->ops.free_buf(dev_handle, hdl, p);
				return NULL;
			}
			pcntrl = csm_dp_get_buf_overhead(p);
			if (pcntrl->xmit_status == CSM_DP_XMIT_IN_PROGRESS) {
				pthread_mutex_lock(&__libData[bus][vf].tx_mutex);
				if (type == CSM_DP_MEM_TYPE_DL_CONTROL)
					__libData[bus][vf].tx_buf_inprogress[CSM_DP_CH_CONTROL]++;
				else
					__libData[bus][vf].tx_buf_inprogress[CSM_DP_CH_DATA]++;
				pthread_mutex_unlock(&__libData[bus][vf].tx_mutex);

				if (!busy_buf)
					busy_buf = p;
				hdl->ops.free_buf(dev_handle, hdl, p);
				goto again;
			}
			bufobj = ptr_to_bufobj(memhdl, p);
			bufobj->handle = rand();
			if (handle)
				*handle = bufobj->handle;
			__mempool_hold_buf(hdl, p);
			buf = p + memhdl->buf_headroom_sz;
		} else
			return NULL;
	}
	return buf;
}

void *csm_dp_alloc_txbuf(uint16_t dev_handle,
			 enum csm_dp_mem_type type,
			 unsigned int length)
{
	return __csm_dp_ealloc_txbuf(dev_handle, type, length, NULL);
}
void *csm_dp_ealloc_txbuf(uint16_t dev_handle,
			  enum csm_dp_mem_type type,
			  unsigned int length,
			  unsigned int *handle)
{
	return __csm_dp_ealloc_txbuf(dev_handle, type, length, handle);
}

/**
 * @brief
 * Free a DL buffer
 *
 * If it is no longer used, the user application must use this
 * API to free the buffer. Otherwise, it will cause buffer
 * allocation failure. After freeing the buffer, the handle from the
 * associated csm_dp_tx_buf() is destroyed. Next time, the same buffer
 * is returned by csm_dp_ealloc_txbuf(), it will be associated with
 * a different handle.
 *
 * @param handle - Handle for a csm_dp instance
 * @param bufptr - buffer pointer. It must be returned by a
 *      	 previous call to csm_dp_alloc_tx()
 *
 * @return None
 */
static inline void __csm_dp_free_txbuf(uint16_t handle,
				       struct csm_dp_mempool_hdl *hdl,
				       void *bufptr)
{

	__mempool_put_buf(handle, hdl, bufptr);
}

static void csm_dp_free_txbuf(uint16_t handle, void *bufptr)
{
	struct csm_dp_mempool_hdl *hdl;

	if (!bufptr) {
		DP_LOG_WARN(handle, "Cannot free buffer with Null pointer\n");
		return;
	}
	hdl = __find_mempool(handle, bufptr);
	if (!hdl) {
		DP_LOG_WARN(handle, "Cannot find mempool\n");
		return;
	}
	__csm_dp_free_txbuf(handle, hdl, bufptr);
}

void csm_dp_free_unsent_txbuf(uint16_t handle, void *bufptr)
{
	csm_dp_free_txbuf(handle, bufptr);
}

/**
 * @brief
 * To send DL messages
 *
 * The iovec array should be prepared in the following way
 *
 * - To send multiple messages
 * With CSM_DP_TX_FLAG_SG bit cleared in flag parameter, each
 * entry of iovec array should contain the pointer to message
 * payload and payload length
 *
 * - To send single message in scatter-gather
 * With CSM_DP_TX_FLAG_SG bit set in flag parameter, the iovec
 * array should contain the scatter-gather list of message
 * payload. The maximum number of entries in the list is defined
 * by CSM_DP_MAX_SG_IOV_SIZE macro.
 *
 * The library takes care of freeing the Tx buffers.
 *
 * @param handle - Handle for a csm_dp instance
 * @param ch - channel to send on (CONTROL or DATA)
 * @param iov - pointer to any array of iovec structure
 * @param iovcnt - number of iovec structure in array
 * @param flag - flag. The bitmap is defined by
 *             CSM_DP_TX_FLAG_xxxx macros
 *
 * @return Number of messages which were sent, or negative value
 */
int csm_dp_send(uint16_t handle,
		enum csm_dp_channel ch,
		struct iovec *iov,
		unsigned int iovcnt,
		unsigned int flag)
{
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);
	struct csm_dp_ioctl_tx req = {0};
	int ret;
	unsigned int n, event_id;

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return -EINVAL;

	if (!csm_dp_is_inited(handle)) {
		DP_LOG_ERR(handle, "Library is not intialized!\n");
		return -EAGAIN;
	}
	if (!iov) {
		DP_LOG_ERR(handle, "NULL pointer!\n");
		return -EINVAL;
	}
	if (iovcnt > CSM_DP_MAX_IOV_SIZE || !iovcnt) {
		DP_LOG_DEBUG(handle, "Invalid iov counter %u\n", iovcnt);
		return -EINVAL;
	}

	pthread_mutex_lock(&__libData[bus][vf].tx_mutex);
	req.ch = ch;
	req.iov.iov_base = iov;
	req.iov.iov_len = iovcnt;
	if (flag & CSM_DP_TX_FLAG_MIRROR) {
		req.flags |= CSM_DP_IOCTL_TX_FLAG_MIRROR;
	}
	ret = ioctl(__libData[bus][vf].fd,
		    (flag & CSM_DP_TX_FLAG_SG) ? CSM_DP_IOCTL_SG_TX : CSM_DP_IOCTL_TX,
		    &req);
	if (ret < 0) {
		DP_LOG_DEBUG(handle, "Failed to send messages\n");
	} else {
		event_id = (flag & CSM_DP_TX_FLAG_SG) ? DP_CAP_EVENT_DL_SG_MSG : DP_CAP_EVENT_DL_MSGS;
		__csm_dp_rtx_hook(handle, iov, ret, event_id, ch);
	}

	if (!(flag & CSM_DP_TX_FLAG_DONT_FREE))
	{
		for (n = 0; n < iovcnt; n++)
			csm_dp_free_txbuf(handle, iov[n].iov_base);
	}

	pthread_mutex_unlock(&__libData[bus][vf].tx_mutex);
	return ret;
}


static int __csm_dp_recv(
	uint16_t handle,
	struct csm_dp_rx_hdl *rxhdl,
	struct iovec *iov,
	unsigned int iovcnt)
{
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);
	struct csm_dp_mem_hdl *memhdl;
	struct csm_dp_mempool_hdl *hdl;
	csm_dp_ring_element_data_t val;
	unsigned int n = 0, packet_start = 0, packet_iovcnt = 0, remain = iovcnt;
	int ret;
	struct csm_dp_buf_cntrl *p;

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return -EINVAL;

	hdl = __libData[bus][vf].hdl[CSM_DP_MEM_TYPE_UL_CONTROL];
	memhdl = &hdl->mem_hdl;

	while (n < iovcnt) {
		char *addr;

		ret = __ring_get_element(handle, &rxhdl->ring_hdl, &val);
		if (ret)
			break;

		if (!is_offset_in_range(val, 0, memhdl->size) ||
		    !is_offset_in_range(val + memhdl->bufsz - 1, 0, memhdl->size)) {
			DP_LOG_ERR(handle, "Read invalid offset from ring, offset=0x%lx, memsize=0x%lx\n",
				val, memhdl->size);
			continue;
		}

		addr = (char *)memhdl->base + val;

		// each ring element is a linked list of buffers, linked by next_buf_index
		// the resulting iov array may contain a mix of single buffer packets with SG packets. Single buffer packet has
		// iov_len > 0 while SG packet is composed of one or more iov entries with iov_len = 0 followed by one iov
		// entry with iov_len > 0.

		p = csm_dp_get_buf_overhead(addr);
		if (p->buf_count > remain) {
			if (remain == iovcnt)
				return -EINVAL; /* provided iov is too short even for 1st packet */
			/* no more room in iov, we're done */
			// TODO: ring element val is lost???
			break;
		}

		while (1) {
#ifdef CSM_DP_BUFFER_FENCING
			if (p->fence != CSM_DP_BUFFER_FENCE_SIG ||
					p->signature != CSM_DP_BUFFER_SIG) {
				DP_LOG_ERR(handle,
					"%s: mem handle %p buffer corrupted,"
					" offset 0x%lx, fence 0x%x, expect 0x%x,"
					" signature 0x%x, expect 0x%x,"
					" buffer is lost\n",
					__func__, memhdl, val, p->fence, CSM_DP_BUFFER_FENCE_SIG,
					p->signature, CSM_DP_BUFFER_SIG);
				continue;
			}
#endif
			p->state = CSM_DP_BUF_STATE_USER_RECV;

			iov[n].iov_base = addr;
			iov[n].iov_len = p->len;	/* p->len is zero in non-last buffer of SG packet */
			__mempool_hold_buf(hdl, addr);
			n++;
			remain--;
			packet_iovcnt++;
			if (p->next_buf_index == CSM_DP_INVALID_BUF_INDEX) {
				unsigned int event_id = (packet_iovcnt > 1) ? DP_CAP_EVENT_UL_SG_MSG : DP_CAP_EVENT_UL_MSGS;

				__csm_dp_rtx_hook(handle, &iov[packet_start], packet_iovcnt, event_id, CSM_DP_CH_CONTROL);
				packet_start = n;
				packet_iovcnt = 0;
				break;
			} else {
				addr = buf_index_to_ptr(memhdl, p->next_buf_index);
			}

			p = csm_dp_get_buf_overhead(addr);
		}
	}
	return n;
}

/**
 * @brief
 * To receive UL messages from CONTROL channel.
 *
 * In order to receive UL messages, RX initialization must be
 * done before calling this API.
 *
 * It is a non-blocking API. For blocking receive, user should
 * do select before calling ths API.
 *
 * @param handle - Handle for a csm_dp instance
 * @param iov - pointer to any array of iovec structure
 * @param iovcnt - number of iovec structure in array
 *
 * @return Number of received packets, or negative value if it
 *     failed.
 *
 * On success, the iov structure will be updated with the
 * message pointer and message length information
 */
int csm_dp_recv(uint16_t handle, struct iovec *iov, unsigned int iovcnt)
{
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);
	int n = 0, i, f;

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return -EINVAL;

	if (!iov || !iovcnt || iovcnt > CSM_DP_MAX_IOV_SIZE)
		return -EINVAL;

	if (!csm_dp_is_inited(handle)) {
		DP_LOG_ERR(handle, "Library is not intialized!\n");
		return -EPERM;
	}

	pthread_mutex_lock(&__libData[bus][vf].rx_c_mutex);
	for (i = 0, f = 1; i < CSM_DP_RX_TYPE_LAST; i++, f <<= 1) {
		int ret;

		if (!__libData[bus][vf].rxhdl[i])
			continue;
		ret = __csm_dp_recv(handle, __libData[bus][vf].rxhdl[i], &iov[n], iovcnt - n);
		if (ret < 0)
			break;
		n += ret;
		if (n == (int)iovcnt)
			break;
	}
	pthread_mutex_unlock(&__libData[bus][vf].rx_c_mutex);
	return n;
}

/**
 * @brief
 * Poll for Rx (UL) packets on the DATA channel
 *
 * DATA channels are used in polling mode. The application must periodically
 * call csm_dp_rx_poll to fetch received UL packets. Failing to poll at the
 * appropriate rate will result in out of Rx buffers.
 *
 * @param handle - Handle for a csm_dp instance
 * @param iov - pointer to any array of iovec structure
 * @param iovcnt - number of iovec structure in array
 *
 * @return Number of received packets, or negative value if it failed.
 *
 * On success, the iov structure will be updated with the
 * message pointer and message length information
 */
int csm_dp_rx_poll(uint16_t handle, struct iovec *iov, unsigned int iovcnt)
{
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);
	struct iovec req;
	int ret, i;
	struct csm_dp_mem_hdl *memhdl;
	struct csm_dp_mempool_hdl *hdl;
	unsigned int packet_start = 0, packet_iovcnt = 0;

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return -EINVAL;

	pthread_mutex_lock(&__libData[bus][vf].rx_d_mutex);
	hdl = __libData[bus][vf].hdl[CSM_DP_MEM_TYPE_UL_DATA];
	memhdl = &hdl->mem_hdl;

	if (!csm_dp_is_inited(handle)) {
		DP_LOG_ERR(handle, "Library is not intialized!\n");
		pthread_mutex_unlock(&__libData[bus][vf].rx_d_mutex);
		return -EPERM;
	}

	req.iov_base = iov;
	req.iov_len = iovcnt;
	ret = ioctl(__libData[bus][vf].fd, CSM_DP_IOCTL_RX_POLL, &req);
	if (ret < 0) {
		DP_LOG_DEBUG(handle, "CSM_DP_IOCTL_RX_POLL failed %d\n", ret);
		pthread_mutex_unlock(&__libData[bus][vf].rx_d_mutex);
		return ret;
	}

	// translate offset into app memory space address
	for (i = 0; i < ret; i++) {
		unsigned long offset = (unsigned long)iov[i].iov_base;
		struct csm_dp_buf_cntrl *p;

		if (!is_offset_in_range(offset, 0, memhdl->size) ||
		    !is_offset_in_range(offset + memhdl->bufsz - 1, 0, memhdl->size)) {
			DP_LOG_ERR(handle, "Got invalid offset from rx_poll, offset=0x%lx, memsize=0x%lx\n", offset, memhdl->size);
			pthread_mutex_unlock(&__libData[bus][vf].rx_d_mutex);
			return -EINVAL;
		}

		iov[i].iov_base = (char *)iov[i].iov_base + (long)memhdl->base;
		p = csm_dp_get_buf_overhead(iov[i].iov_base);
		p->state = CSM_DP_BUF_STATE_USER_RECV;
		__mempool_hold_buf(hdl, iov[i].iov_base);
	}

	for (i = 0; i < ret; i++) {
		unsigned int event_id;

		packet_iovcnt++;

		if (iov[i].iov_len > 0) {
			event_id = (packet_iovcnt > 1) ? DP_CAP_EVENT_UL_SG_MSG : DP_CAP_EVENT_UL_MSGS;
			__csm_dp_rtx_hook(handle, &iov[packet_start], packet_iovcnt, event_id, CSM_DP_CH_DATA);
			packet_start = i + 1;
			packet_iovcnt = 0;
		}
	}
	pthread_mutex_unlock(&__libData[bus][vf].rx_d_mutex);
	return ret;
}

/**
 * @brief
 * To free RX buffer
 *
 * After UL message is processed, the user application must use
 * this API to free the RX buffer.
 *
 * @param handle - Handle for a csm_dp instance
 * @param bufptr - buffer pointer. It must have been returned in
 *      	 iov_base field of iovec structure by
 *      	 csm_dp_receive or csm_dp_receive_lbrsp API.
 * @return None
 */
void csm_dp_free_rxbuf(uint16_t handle, void *bufptr)
{
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);

	struct csm_dp_buf_cntrl *buf_cntrl;
	enum csm_dp_mem_type mem_type;

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return;

	if (!csm_dp_is_inited(handle))
		return;

	buf_cntrl = csm_dp_get_buf_overhead(bufptr);
	mem_type = buf_cntrl->mem_type;

	if (mem_type != CSM_DP_MEM_TYPE_UL_DATA && mem_type != CSM_DP_MEM_TYPE_UL_CONTROL)
		// invalid mem_type
		return;

	__mempool_put_buf(handle, __libData[bus][vf].hdl[mem_type], bufptr);
}

/**
 * @brief
 * To hold buffer by increasing reference counter
 *
 * In API to free the buffer, it decreases the reference counter and
 * free the buffer if the counter reaches zero.
 *
 * @param handle - Handle for a csm_dp instance
 * @param bufptr - buffer pointer.
 *
 * @return None
 */
static void csm_dp_hold_buf(uint16_t handle, void *bufptr)
{
	if (csm_dp_is_inited(handle)) {
		struct csm_dp_mempool_hdl *hdl = __find_mempool(handle, bufptr);

		if (hdl)
			__mempool_hold_buf(hdl, bufptr);
	}
}

/**
 * @brief
 * To initialize traffic capture
 *
 * The library spawns a dedicate thread to offload traffic
 * capture. The callback function will be invoked from that
 * thread for each packet received/transmitted using library
 * API.
 *
 * @param handle - Handle for a csm_dp instance
 * @param callback_ops - callback function. Set to NULL to use
 *      	   default callback in library which writes
 *      	   message into file.
 * @param cb_cookie - cookie for callback function. For default
 *      	    callback, it expects the pointer to
 *      	    configuration.
 * @param max_event - maximum number of pending capture event
 *              (must be less than or equal to CSM_DP_CAPTURE_MAX_EVENT)
 *
 * @return On success - 0, otherwise failed
 *
 */
int csm_dp_init_capture(
	uint16_t handle,
	const struct csm_dp_cap_cb_ops *callback_ops,
	void *cb_cookie,
	unsigned int max_event)
{
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);
	struct csm_dp_cap_hdl *caphdl;
	int ret;

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return -EINVAL;

	if (!csm_dp_is_inited(handle)) {
		DP_LOG_ERR(handle, "Library is not intialized!\n");
		return -EPERM;
	}

	if (!(csm_dp_capture_max_event_is_valid(max_event))) {
		DP_LOG_ERR(handle, "Input parameter: max_event is not valid!\n");
		return -EINVAL;
	}

	pthread_mutex_lock(&__libData[bus][vf].mutex);
	if (__libData[bus][vf].caphdl) {
		DP_LOG_ERR(handle, "Capture thread already started!\n");
		pthread_mutex_unlock(&__libData[bus][vf].mutex);
		return 0;
	}

	caphdl = calloc(1, sizeof(*caphdl));
	if (!caphdl) {
		DP_LOG_ERR(handle, "Failed to allocate memory!\n");
		pthread_mutex_unlock(&__libData[bus][vf].mutex);
		return -ENOMEM;
	}

	ret = __init_cap_hdl(handle, caphdl, callback_ops, cb_cookie, max_event);
	if (ret) {
		DP_LOG_ERR(handle, "Failed to intialize capture handler\n");
		pthread_mutex_unlock(&__libData[bus][vf].mutex);
		__cleanup_cap_hdl(caphdl);
		return ret;

	}

	__libData[bus][vf].caphdl = caphdl;
	pthread_mutex_unlock(&__libData[bus][vf].mutex);
	return 0;
}

/**
 * @brief
 * To stop traffic capture and streaming.
 *
 * @param handle - Handle for a csm_dp instance
 *
 * @return None
 */
void csm_dp_cleanup_capture(uint16_t handle)
{
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);
	struct csm_dp_cap_hdl *caphdl;

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return;

	printf("%s running\n", __func__);
	if (!csm_dp_is_inited(handle))
		return;

	pthread_mutex_lock(&__libData[bus][vf].mutex);
	caphdl = __libData[bus][vf].caphdl;
	__libData[bus][vf].caphdl = NULL;
	pthread_mutex_unlock(&__libData[bus][vf].mutex);

	if (caphdl) {
		struct csm_dp_cap_event_hdl *event_hdl = &caphdl->event_hdl;
		struct csm_dp_cap_event *event;

		while (!(event=__ring_get_cap_event(handle, &event_hdl->free_ring)))
			sched_yield();

		event->id = DP_CAP_EVENT_STOP;
		__ring_put_cap_event(handle, &event_hdl->event_ring, event);
		sem_post(&caphdl->sem);
		pthread_join(caphdl->pid, NULL);
		__cleanup_cap_hdl(caphdl);
	}
}

/**
 * @brief
 * To enable traffic capture on a specific channel
 *
 * @param ch - channel for capture
 * @param handle - Handle for a csm_dp instance
 *
 * @return On success - 0, otherwise failed
 */
int csm_dp_enable_capture(uint16_t handle,
			  enum csm_dp_channel ch)
{
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);
	int ret = 0;

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return -EINVAL;

	if (!csm_dp_is_inited(handle))
		return -EAGAIN;

	if (ch != CSM_DP_CH_CONTROL && ch != CSM_DP_CH_DATA)
		return -EINVAL;

	pthread_mutex_lock(&__libData[bus][vf].mutex);
	if (__libData[bus][vf].caphdl)
		__libData[bus][vf].caphdl->enable[ch] = true;
	else
		ret = -EAGAIN;
	pthread_mutex_unlock(&__libData[bus][vf].mutex);

	return ret;
}

/**
 * @brief
 * To disable traffic capture on a specific channel
 *
 * @param handle - Handle for a csm_dp instance
 * @param ch - channel for capture
 *
 * @return On success - 0, otherwise failed
 */
int csm_dp_disable_capture(uint16_t handle, enum csm_dp_channel ch)
{
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);
	int ret = 0;

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return -EINVAL;

	if (!csm_dp_is_inited(handle))
		return -EAGAIN;

	if (ch != CSM_DP_CH_CONTROL && ch != CSM_DP_CH_DATA)
		return -EINVAL;

	pthread_mutex_lock(&__libData[bus][vf].mutex);
	if (__libData[bus][vf].caphdl)
		__libData[bus][vf].caphdl->enable[ch] = false;
	else
		ret = -EAGAIN;
	pthread_mutex_unlock(&__libData[bus][vf].mutex);

	return ret;
}

/**
 * @brief
 * To get thread id of the thread created by csm_dp_init_capture
 * API
 *
 * @param handle - Handle for a csm_dp instance
 * @param tid - pointer to store the thread id
 *
 * @return On success - 0, otherwise failed
 */
int csm_dp_get_capture_thread_tid(uint16_t handle, pthread_t *tid)
{
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);
	int ret = 0;

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return -EINVAL;

	if (!csm_dp_is_inited(handle))
		return -EAGAIN;

	pthread_mutex_lock(&__libData[bus][vf].mutex);
	if (!__libData[bus][vf].caphdl)
		ret = -EAGAIN;
	else if (tid)
		*tid = __libData[bus][vf].caphdl->pid;
	pthread_mutex_unlock(&__libData[bus][vf].mutex);

	return ret;
}

/**
 * @brief
 * Set the loglevel. The value of log level is defined in
 * syslog.h.
 *
 * @param handle - Handle for a csm_dp instance
 * @param loglevel - log level.
 *
 * @return On success - 0, otherwise failed
 */
int csm_dp_set_loglevel(uint16_t handle, int loglevel)
{
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return -EINVAL;

	struct csm_dp_log_cfg *cfg = &__libData[bus][vf].logcfg;

	if (unlikely(!csm_dp_is_inited(handle)))
		return -EAGAIN;
	if (!csm_dp_log_level_is_valid(loglevel))
		return -EINVAL;

	if (loglevel != cfg->level)
		cfg->level = loglevel;

	return 0;
}

/* Hook to RX/TX API */
static int __csm_dp_rtx_hook(
	uint16_t handle,
	struct iovec *iov,
	unsigned int iovcnt,
	unsigned int event_id,
	enum csm_dp_channel ch)
{
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);
	struct csm_dp_cap_event *event = NULL;
	unsigned int n, sg_len = 0;

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return -EINVAL;

	struct csm_dp_cap_hdl *caphdl = __libData[bus][vf].caphdl;

	if (!caphdl || caphdl->state == DP_CAP_STATE_TERM)
		return 0;

	if (!caphdl->enable[ch]) {
		return 0;
	}

	event = __ring_get_cap_event(handle, &caphdl->event_hdl.free_ring);
	if (!event)
		return -EBUSY;

	event->id = event_id;
	event->channel = ch;
	event->msgs.iovec_cnt = iovcnt;
	clock_gettime(CLOCK_REALTIME, &event->msgs.timestamp);
	for (n = 0; n < iovcnt; n++) {
		event->msgs.iovec[n].iov_base = iov[n].iov_base;
		event->msgs.iovec[n].iov_len = iov[n].iov_len;

		if (event_id == DP_CAP_EVENT_UL_SG_MSG) {
			if (iov[n].iov_len == 0) {
				sg_len += CSM_DP_DEFAULT_UL_BUF_SIZE;
				event->msgs.iovec[n].iov_len = CSM_DP_DEFAULT_UL_BUF_SIZE;
			} else {
				if (event->msgs.iovec[n].iov_len > sg_len)
					event->msgs.iovec[n].iov_len -= sg_len;
				sg_len = 0;
			}
		}

		csm_dp_hold_buf(handle, iov[n].iov_base);
	}
	__ring_put_cap_event(handle, &caphdl->event_hdl.event_ring, event);

	if (caphdl->state == DP_CAP_STATE_WAIT)
		sem_post(&caphdl->sem);

	return 0;
}

/* TODO: Use DLT_USER0 until an official FAPI WTAP linktype is reserved
 *       via https://www.tcpdump.org/linktypes.html.
 */
#define DLT_SCF_FAPI DLT_USER0

static const struct pcap_file_header __pcap_file_hdr = {
	.magic = 0xA1B2C3D4,
	.version_major = PCAP_VERSION_MAJOR,
	.version_minor = PCAP_VERSION_MINOR,
	.thiszone = 0,
	.sigfigs  = 0,
	.snaplen  = 2 * SIZE_1M,
	.linktype = DLT_SCF_FAPI
};

/* returns whether new file created or not */
static bool __default_dp_cap_fopen(
	uint16_t handle,
	struct dp_cap_default_cbdata *cb_data,
	size_t size_to_write)
{
	if (cb_data->fp) {
		/* file exist, check if reached size limit */
		if (cb_data->cfg.file_sz < (size_to_write + cb_data->bytes)) {
			fclose(cb_data->fp);
			cb_data->fp = NULL;
			cb_data->bytes = 0;
		}
	}
	if (!cb_data->fp) {
		FILE *fp;
		char name[256];
		int ret;

		if (cb_data->file_idx == 0) {
			snprintf(name, sizeof(name), "%s.%s",
				cb_data->cfg.file_name, "init");
			cb_data->file_idx++;
                } else {
			snprintf(name, sizeof(name), "%s.%u",
				cb_data->cfg.file_name, cb_data->file_idx++);
		}
		fp = fopen(name, "w+");
		if (!fp) {
			DP_LOG_ERR(handle, "Failed to open file\n");
			return false;
		}

		/* symlink */
		remove(cb_data->cfg.file_name);
		ret = symlink(name, cb_data->cfg.file_name);
		if (ret)
			perror("cannot create pcap symlink");

		cb_data->fp = fp;
		if (cb_data->file_idx > cb_data->cfg.file_num)
			cb_data->file_idx = 1;

		return true;
	}

	return false;
}

static int __default_dp_cap_msg_cb(
	uint16_t handle,
	void *cookie,
	const struct timespec *timestamp,
	const char *buf,
	size_t len,
	bool is_dl,
	enum csm_dp_channel ch)
{
	struct dp_cap_default_cbdata *cb_data = cookie;

	size_t payload_size = (cb_data->cfg.snap_len > len) ? len : cb_data->cfg.snap_len;
	size_t size = DP_PCAP_HDR_SIZE + payload_size;
	size_t n = 0;

	if (__default_dp_cap_fopen(handle, cb_data, size)) {
		/* new file created - add file hdr */
		size += sizeof(__pcap_file_hdr);
		n = fwrite(&__pcap_file_hdr, 1, sizeof(__pcap_file_hdr), cb_data->fp);
	}

	const struct dp_pcap_hdr hdr = {
		.pcap_hdr = {
			.ts_sec  = timestamp->tv_sec,
			.ts_usec = timestamp->tv_nsec / 1000,
			.caplen  = DP_LINK_HDR_SIZE + payload_size,
			.len     = DP_LINK_HDR_SIZE + len},
		.link_hdr = {
			.direction = is_dl ? CSM_DP_DIR_DL : CSM_DP_DIR_UL,
			.channel   = ch}};

	n += fwrite(&hdr, 1, sizeof(hdr), cb_data->fp);
	n += fwrite(buf, 1, payload_size, cb_data->fp);
	if (n != size) {
		DP_LOG_ERR(handle, "Failed to write msg capture into file\n");
		return -EIO;
	}
	cb_data->bytes += n;

	if (!cb_data->cfg.file_no_fflush)
		fflush(cb_data->fp);
	return 0;
}

static int __default_dp_cap_sg_msg_cb(
	uint16_t handle,
	void *cookie,
	const struct iovec *iovec,
	unsigned int iovcnt,
	const struct timespec *timestamp,
	bool is_dl,
	enum csm_dp_channel ch,
	size_t total_len)
{
	struct dp_cap_default_cbdata *cb_data = cookie;
	size_t payload_size;
	size_t size;
	size_t n = 0;
	unsigned int i;

	payload_size = (cb_data->cfg.snap_len > total_len) ? total_len : cb_data->cfg.snap_len;
	size = DP_PCAP_HDR_SIZE + payload_size;
	if (__default_dp_cap_fopen(handle, cb_data, size)) {
		/* new file created - add file hdr */
		size += sizeof(__pcap_file_hdr);
		n = fwrite(&__pcap_file_hdr, 1, sizeof(__pcap_file_hdr), cb_data->fp);
	}

	const struct dp_pcap_hdr hdr = {
		.pcap_hdr = {
			.ts_sec  = timestamp->tv_sec,
			.ts_usec = timestamp->tv_nsec / 1000,
			.caplen  = DP_LINK_HDR_SIZE + payload_size,
			.len     = DP_LINK_HDR_SIZE + total_len},
		.link_hdr = {
			.direction = is_dl ? CSM_DP_DIR_DL : CSM_DP_DIR_UL,
			.channel   = ch}};

	n += fwrite(&hdr, 1, sizeof(hdr), cb_data->fp);
	for (i = 0; i < iovcnt; i++) {
		unsigned int segsize;

		if (iovec[i].iov_len > payload_size)
			segsize = payload_size;
		else
			segsize = iovec[i].iov_len;
		n += fwrite(iovec[i].iov_base, 1, segsize, cb_data->fp);
		payload_size -= segsize;
	}
	if (n != size) {
		DP_LOG_ERR(handle, "Failed to write msg capture into file\n");
		return -EIO;
	}
	cb_data->bytes += n;

	if (!cb_data->cfg.file_no_fflush)
		fflush(cb_data->fp);
	return 0;
}

static const struct csm_dp_cap_cb_ops __default_dp_cap_cb_ops = {
	.msg_cb = __default_dp_cap_msg_cb,
	.sg_cb =  __default_dp_cap_sg_msg_cb,
};

/* Setup capture handler as default */
static int __config_cap_hdl_default(uint16_t handle,
				    struct csm_dp_cap_hdl *caphdl,
				    const struct csm_dp_cap_defcfg *cfg)
{
	const struct csm_dp_cap_defcfg *conf = (cfg) ? cfg : &__default_cap_cfg;
	struct dp_cap_default_cbdata *cb_data;

	if (!csm_dp_cap_defcfg_is_valid(conf))
		return -EINVAL;

	cb_data = calloc(1, sizeof(*cb_data));
	if (!cb_data) {
		DP_LOG_ERR(handle, "Failed to allocate memory for cb data\n");
		return -ENOMEM;
	}
	memcpy(&cb_data->cfg, conf, sizeof(cb_data->cfg));
	memcpy(&caphdl->ops, &__default_dp_cap_cb_ops, sizeof(caphdl->ops));
	caphdl->priv_data = cb_data;
	caphdl->free_priv = true;
	return 0;
}

static int __proc_cap_event(
	uint16_t handle,
	struct csm_dp_cap_hdl *hdl,
	struct csm_dp_cap_event *event)
{
	size_t len;
	int ret = 0;
	unsigned int i;

	switch (event->id) {
	case DP_CAP_EVENT_DL_MSGS:
	case DP_CAP_EVENT_UL_MSGS:
		if (hdl->ops.msg_cb) {
			for (i = 0; i < event->msgs.iovec_cnt; i++) {
				if (!event->msgs.iovec[i].iov_base ||
				    !event->msgs.iovec[i].iov_len) {
					DP_LOG_ERR(handle, "Invalid message iovec!\n");
					continue;
				}

				ret = hdl->ops.msg_cb(handle,
					hdl->priv_data,
					&event->msgs.timestamp,
					event->msgs.iovec[i].iov_base,
					event->msgs.iovec[i].iov_len,
					event->id == DP_CAP_EVENT_DL_MSGS,
					event->channel);
				if (ret < 0)
					break;
			}
		}
		for (i = 0; i < event->msgs.iovec_cnt; i++) {
			if (event->id == DP_CAP_EVENT_DL_MSGS)
				csm_dp_free_txbuf(handle, event->msgs.iovec[i].iov_base);
			else
				csm_dp_free_rxbuf(handle, event->msgs.iovec[i].iov_base);
		}
		break;
	case DP_CAP_EVENT_DL_SG_MSG:
	case DP_CAP_EVENT_UL_SG_MSG:
		if (hdl->ops.sg_cb) {
			for (i = 0, len = 0; i < event->msgs.iovec_cnt; i++) {
				if (!event->msgs.iovec[i].iov_base ||
				    !event->msgs.iovec[i].iov_len) {
					DP_LOG_ERR(handle, "Invalid scatter-gather list!\n");
					len = 0;
					break;
				}
				len += event->msgs.iovec[i].iov_len;
			}
			if (len)
				ret = hdl->ops.sg_cb(handle,
					hdl->priv_data,
					event->msgs.iovec,
					event->msgs.iovec_cnt,
					&event->msgs.timestamp,
					event->id == DP_CAP_EVENT_DL_SG_MSG,
					event->channel,
					len);
		}
		for (i = 0; i < event->msgs.iovec_cnt; i++) {
			if (event->id == DP_CAP_EVENT_DL_SG_MSG)
				csm_dp_free_txbuf(handle, event->msgs.iovec[i].iov_base);
			else
				csm_dp_free_rxbuf(handle, event->msgs.iovec[i].iov_base);
		}
		break;
	case DP_CAP_EVENT_STOP:
		hdl->state = DP_CAP_STATE_TERM;
		break;
	default:
		DP_LOG_ERR(handle, "Unknown event\n");
		break;
	}
	return ret;
}

static void *__capture_thread_main(void *arg)
{
	struct csm_dp_cap_hdl *caphdl = arg;
	uint16_t handle = caphdl->handle;

	struct csm_dp_cap_event_hdl *event_hdl = &caphdl->event_hdl;
	struct csm_dp_cap_event *event;
	bool done = false;
	int ret;

	caphdl->state = DP_CAP_STATE_RUN;
	while (!done) {
		while ((event = __ring_get_cap_event(handle, &event_hdl->event_ring))) {
			ret = __proc_cap_event(handle, caphdl, event);
			if (ret < 0 || caphdl->state == DP_CAP_STATE_TERM) {
				done = true;
				break;
			}
			__ring_put_cap_event(handle, &event_hdl->free_ring, event);
		}
		if (!done) {
			caphdl->state = DP_CAP_STATE_WAIT;
			sem_wait(&caphdl->sem);
			caphdl->state = DP_CAP_STATE_RUN;
		}
	}
	return NULL;
}

#ifdef CSM_DP_BUFFER_FENCING
csm_dp_txbuf_status_e
csm_dp_query_txbuf_status(uint16_t dev_handle,
			  unsigned int handle,
			  void *bufptr,
			  int *err)
{
	struct csm_dp_mempool_hdl *hdl;
	struct csm_dp_bufobj *bufobj;
	int ref_cnt;
	struct csm_dp_buf_cntrl *p;
	csm_dp_ring_element_data_t offset;
	csm_dp_txbuf_status_e ret = CSM_DP_TX_BUF_STATUS_TX_QUERY_ERR;

	if (bufptr == NULL)
		return ret;
	hdl = __find_mempool(dev_handle, bufptr);
	if (!hdl) {
		DP_LOG_WARN(dev_handle, "Cannot find mempool\n");
		return ret;
	}
	offset = get_aligned_offset(&hdl->mem_hdl, bufptr) +
			hdl->mem_hdl.buf_overhead_sz;

	p = csm_dp_get_buf_overhead((char *)hdl->mem_hdl.base + offset);
	bufobj = ptr_to_bufobj(&hdl->mem_hdl, bufptr);
	if (!bufobj)
		return ret;
	if (handle != bufobj->handle)
		return ret;
	ref_cnt = atomic_read(&bufobj->refcnt);
	if (p->fence != CSM_DP_BUFFER_FENCE_SIG ||
			p->signature != CSM_DP_BUFFER_SIG) {
		DP_LOG_ERR(dev_handle,
			"buffer %p corrupted,"
			" fence 0x%x, expect 0x%x,"
			" signature 0x%x, expect 0x%x,"
			" buffer is lost\n",
			bufptr, p->fence, CSM_DP_BUFFER_FENCE_SIG,
			p->signature, CSM_DP_BUFFER_SIG);
		return ret;
	}
	if (err)
		*err = 0;
	if (p->xmit_status == CSM_DP_XMIT_OK) {
		if (ref_cnt == 1)
			ret = CSM_DP_TX_BUF_STATUS_TX_OK;
		else
			ret =  CSM_DP_TX_BUF_STATUS_TX_OK_BUSY;
	}
	if (p->xmit_status == CSM_DP_XMIT_IN_PROGRESS)
		ret =  CSM_DP_TX_BUF_STATUS_TX_IN_PROGRESS;
	if (p->xmit_status < 0) {
		if (err)
			*err = p->xmit_status;
		if (ref_cnt == 1)
			ret = CSM_DP_TX_BUF_STATUS_TX_ERR;
		else
			ret = CSM_DP_TX_BUF_STATUS_TX_ERR_BUSY;
	}
	return ret;
}
#else
csm_dp_txbuf_status_e
csm_dp_query_txbuf_status(uint16_t dev_handle,
			  unsigned int handle,
			  void *bufptr,
			  int *err)
{

	return CSM_DP_TX_BUF_STATUS_UNAVAIL;
}
#endif

unsigned int
csm_dp_num_alloc_txbuf_tx_in_progress(uint16_t handle,
					enum csm_dp_channel mode)
{
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return INVALID_HANDLE;

	return __libData[bus][vf].tx_buf_inprogress[mode];
}

/**
 * @brief
 * Get driver layer statistics.
 *
 * @param handle - Handle for a csm_dp instance
 * @param stats - statistics placeholder.
 *
 * @return On success - 0, otherwise failed
 */
int csm_dp_get_stats(uint16_t handle, struct csm_dp_ioctl_getstats *stats)
{
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);
	int ret;

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return -EINVAL;

	if (!csm_dp_is_inited(handle))
		return -EAGAIN;

	ret = ioctl(__libData[bus][vf].fd, CSM_DP_IOCTL_GET_STATS, stats);
	if (ret)
		DP_LOG_ERR(handle, "CSM_DP_IOCTL_GET_STATS failed, err=%d (%s)\n", ret, strerror(errno));

	return ret;
}
