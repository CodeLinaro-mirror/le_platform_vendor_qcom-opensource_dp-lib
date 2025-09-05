/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef CSM_DP_PRIV_H
#define CSM_DP_PRIV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>
#include <semaphore.h>
#include <linux/csm_dp_ioctl.h>

#include "csm_dp_arch.h"

#define DEFAULT_BUFFER_SIZE	2048

#define DP_LOG_DEBUG(handle,...) csm_dp_log(handle, LOG_DEBUG, __VA_ARGS__)
#define DP_LOG_INFO(handle,...) csm_dp_log(handle, LOG_INFO, __VA_ARGS__)
#define DP_LOG_WARN(handle,...) csm_dp_log(handle, LOG_WARNING, __VA_ARGS__)
#define DP_LOG_ERR(handle,...) csm_dp_log(handle, LOG_ERR, __VA_ARGS__)
#define DP_LOG_CRIT(handle,...) csm_dp_log(handle, LOG_CRIT, __VA_ARGS__)

struct csm_dp_mempool_hdl;

/** @brief structure for memory location
 *  @param base - base address
 *  @param length - length of memory
 *  @param mmap - indicate if the memory location is mmapped or
 *      	locally allocated
 */
struct csm_dp_mem_loc {
	void *base;
	unsigned long length;
	bool mmap;
};

/** @brief structure for mempool ops
 *  @param alloc_buf - function to allocate buffer
 *  @param free_buf - function to free buffer. The buffer is
 *      	    ensured within the range.
 *  @param release - callback function when the mempool is
 *      	   released
 */
struct csm_dp_mempool_ops {
	void *(*alloc_buf)(uint16_t, struct csm_dp_mempool_hdl *);
	void (*free_buf)(uint16_t, struct csm_dp_mempool_hdl *, void *);
	void (*release)(uint16_t, struct csm_dp_mempool_hdl *);
};

/** @brief debug statistics for ring operation */
struct csm_dp_ring_opstats {
	csm_dp_atomic_t read_ok;
	csm_dp_atomic_t read_empty;

	csm_dp_atomic_t write_ok;
	csm_dp_atomic_t write_full;
};

/** @brief ring buffer handler */
struct csm_dp_ring_hdl {
	struct csm_dp_mem_loc loc;
	unsigned int ring_sz;

	volatile csm_dp_ring_index_t *cons_head;	/* consumer index header */
	volatile csm_dp_ring_index_t *cons_tail;	/* consumer index tail */
	volatile csm_dp_ring_index_t *prod_head;	/* producer index header */
	volatile csm_dp_ring_index_t *prod_tail;	/* producer index tail */
	volatile csm_dp_ring_element_t *ringbuf;	/* ring element */
	struct csm_dp_ring_opstats opstats;
};

/** @brief object for buffer tracking */
struct csm_dp_bufobj {
	csm_dp_atomic_t refcnt;
	unsigned int handle;
};

/** @brief DP memory handler */
struct csm_dp_mem_hdl {
	struct csm_dp_mem_loc loc;
	void *base;			/* memory starting address */
	unsigned long size;		/* size of memory */
	unsigned int bufcnt;		/* number of fixed-size buffer */
	unsigned int bufsz;		/* size of buffer */

	unsigned int buf_headroom_sz;	/*
					 * a buf user data starts with headroom
					 * with size of buf_headroom_sz, 0 for now.
					 */

	unsigned int buf_overhead_sz;	/*
					 * buffer overhead size.
					 * buffer overhead is right at
					 * the beginning of a buffer.
					 * User data starts after
					 * buf_overhead_sz. The overhead
					 * area may include buffer
					 * control information.
					 */
	unsigned int cluster_size;      /* cluster size in bytes.*/
	unsigned int num_cluster;       /* number of cluster */
	unsigned int buf_per_cluster;   /* number of buffers per cluster  */
	struct csm_dp_bufobj *buf_objs;
};

/** @brief DP memory pool handler */
struct csm_dp_mempool_hdl {
	enum csm_dp_mem_type type;
	struct csm_dp_mem_hdl mem_hdl;
	struct csm_dp_ring_hdl ring_hdl;
	struct csm_dp_mempool_ops ops;
};

/** @brief DP UL RX handler
 *
 *  @param type - type of UL datapath
 *  @param ring_hdl - ring handler for receiving queue
 */
struct csm_dp_rx_hdl {
	enum csm_dp_rx_type type;
	struct csm_dp_ring_hdl ring_hdl;
};

/** @brief enum for traffic capture thread state */
enum csm_dp_cap_state {
	DP_CAP_STATE_READY,
	DP_CAP_STATE_RUN,
	DP_CAP_STATE_WAIT,
	DP_CAP_STATE_TERM,
};

/** @brief enum for traffic capture event */
enum {
	DP_CAP_EVENT_DL_MSGS,
	DP_CAP_EVENT_UL_MSGS,
	DP_CAP_EVENT_DL_SG_MSG,
	DP_CAP_EVENT_UL_SG_MSG,
	DP_CAP_EVENT_STOP,
};

/** @brief structure passing information of captured
 *         messages
 *
 *  @param timestamp - timestamp when the messages is captured
 *  @param iovec_cnt - number of valid entry in iovec array
 *  @param iovec - iovec array. Each entry contains the message
 *      	 pointer and message length.
 */
struct csm_dp_cap_msgs {
	struct timespec timestamp;
	unsigned int iovec_cnt;
	struct iovec iovec[CSM_DP_MAX_IOV_SIZE];
};

/** @brief traffic capture event structure
 *
 *  @param id - event ID
 *  @param channel - Channel the message were captured on.
 *  @param msgs - captured messages information
 */
struct csm_dp_cap_event {
	unsigned int id;	/* DP_CAP_EVENT_xxx */
	enum csm_dp_channel channel;
	struct csm_dp_cap_msgs msgs;
};

/** @brief traffic capture event handler
 *
 *  @param free_ring - ring buffer which contains the pointer to
 *      	     unused event structure
 *  @param event_ring - ring buffer which contains active events
 *  @param event_mem - memory allocated for event structure
 */
struct csm_dp_cap_event_hdl {
	struct csm_dp_ring_hdl free_ring;
	struct csm_dp_ring_hdl event_ring;
	void *event_mem;
};

/** @brief traffic capture handler
 *
 *  @param pid - pthread id of traffic capture thread
 *  @param handle - Handle for a csm_dp instance
 *  @param event_hdl - event handler
 *  @param priv_data - private data to store user-provided
 *      	     cookie
 *  @param ops - callback ops provided by user
 *  @param sem - semaphore
 *  @param state - running state of capture thread
 */
struct csm_dp_cap_hdl {
	pthread_t pid;
	uint16_t handle;
	struct csm_dp_cap_event_hdl event_hdl;
	void *priv_data;
	struct csm_dp_cap_cb_ops ops;
	bool free_priv;
	sem_t sem;
	bool enable[2];	/* CONTROL & DATA */
	volatile enum csm_dp_cap_state state;
};

#define LIB_FLAG_INITED	1

/** @brief library structure for private data
 *
 *  @param fd - DP device file descriptor
 *  @param flag - bitmap is defined by LIB_FLAG_XX macro
 *  @param tx_buf_inprogress - tx buffer transmission progress
 *  @param logcfg - log configuration
 *  @param mutex - mutex for data protection
 *  @param tx_mutex - tx mutex
 *  @param rx_c_mutex - rx control mutex
 *  @param rx_d_mutex - rx data mutex
 *  @param hdl - mempool handler
 *  @param rxhdl - UL RX handler
 *  @param caphdl - capture handler
 *  @param cap_enable - capture setting
*/
struct csm_dp_lib_data {
	int fd;
	int flag;
	unsigned int tx_buf_inprogress[CSM_DP_CH_DATA + 1];
	struct csm_dp_log_cfg logcfg;
	pthread_mutex_t mutex;
	pthread_mutex_t tx_mutex;
	pthread_mutex_t rx_c_mutex;
	pthread_mutex_t rx_d_mutex;
	struct csm_dp_mempool_hdl *hdl[CSM_DP_MEM_TYPE_LAST];
	struct csm_dp_rx_hdl *rxhdl[CSM_DP_RX_TYPE_LAST];
	struct csm_dp_cap_hdl *caphdl;
};

/** @brief library logging */
void csm_dp_log(uint16_t handle, int level, const char *fmt, ...);

#ifdef __cplusplus
};
#endif

#endif /* CSM_DP_PRIV_H */
