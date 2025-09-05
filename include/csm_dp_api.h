/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef CSM_DP_API_H
#define CSM_DP_API_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <limits.h>
#include <linux/csm_dp_ioctl.h>

/** @brief macro for default buffer size */
#define CSM_DP_DEFAULT_CONTROL_BUFSZ	(4 * 1024)
#define CSM_DP_DEFAULT_DATA_BUFSZ		(64 * 1024)
#define CSM_DP_CAPTURE_MAX_EVENT		(1024)

#define CSM_DP_MAX_VF 4
#define CSM_DP_MAX_BUS 4
#define INVALID_HANDLE 0xFFFF
#define CREATE_HANDLE(x, y) (x | (y << 4))

/** @brief enum for library log output */
enum {
	CSM_DP_LOG_OUTPUT_NONE,
	CSM_DP_LOG_OUTPUT_CONSOLE,
	CSM_DP_LOG_OUTPUT_SYSLOG,
};

/** @brief Structure for library log control
 *  @param level - log level following log-level definition of
 *      	 syslog
 *  @param output - log output
 */
struct csm_dp_log_cfg {
	int level;
	int output;
};

/** @brief message capture callback function
 *  @param handle - Handle for a csm_dp instance
 *  @param cookie - cookie provided by user
 *  @param timestamp - message timestamp
 *  @param buf - message to capture
 *  @param len - message len
 *  @param is_dl - true for downlink message
 *  @param ch - Channel the message was captured on
 */
typedef int (*csm_dp_cap_msg_cb)(
	uint16_t handle,
	void *cookie,
	const struct timespec *timestamp,
	const char *buf,
	size_t len,
	bool is_dl,
	enum csm_dp_channel ch);

/** @brief scatter-gather message capture callback function
 *  @param handle - Handle for a csm_dp instance
 *  @param cookie - cookie provided by user
 *  @param iov - scatter-gather iovec list
 *  @param iovcnt - number of iovec in list
 *  @param timestamp - message timestamp
 *  @param is_dl - true for downlink message
 *  @param ch - Channel the message was captured on
 *  @param total_len - total length of all iov buffers
 */
typedef int (*csm_dp_cap_sg_msg_cb)(
	uint16_t handle,
	void *cookie,
	const struct iovec *iov,
	unsigned int iovcnt,
	const struct timespec *timestamp,
	bool is_dl,
	enum csm_dp_channel ch,
	size_t total_len);

/** @brief bitmap definition of flag in TX API
 *  @param CSM_DP_TX_FLAG_SG - indicate it is scatter-gather
 *  @param CSM_DP_TX_FLAG_DONT_FREE - the library shouldn't free the Tx buffers. The application
 *     must free the buffers later by either re-sending them with the flag cleared or by
 *     using csm_dp_free_unsent_txbuf().
 *  @param CSM_DP_TX_FLAG_MIRROR - request device to mirror the buffers into debug interface
 */
#define CSM_DP_TX_FLAG_SG	0x10
#define CSM_DP_TX_FLAG_DONT_FREE 0x20
#define CSM_DP_TX_FLAG_MIRROR	0x40

/** @brief bitmap definition of flag in RX API
 *  @param CSM_DP_RX_FLAG_ALL - to receive all messages
 */
#define CSM_DP_RX_FLAG_ALL	((1 << CSM_DP_RX_TYPE_LAST) - 1)
#define CSM_DP_MAX_FILE_NAME       (128)
/**
 * @brief
 * Data structure for default configuration of traffic capture
 *
 * @param file_name - base filename of output capture data file.
 * @param file_sz - maximum size of output file
 * @param file_num - number of output file.
 * @param snap_len - length of message payload saved into data
 *      	   file
 * @param file_no_fflush - don't fflush for each capture write
 */
struct csm_dp_cap_defcfg {
	char file_name[CSM_DP_MAX_FILE_NAME];
	unsigned int file_sz;
	unsigned int file_num;
	unsigned int snap_len;
	unsigned int file_no_fflush;
};

/**
 * @brief
 * Data structure for traffic capture callback operation
 *
 * @param msg_cb - message callback
 * @param sg_cb - scatter-gather message callback
 */
struct csm_dp_cap_cb_ops {
	csm_dp_cap_msg_cb msg_cb;
	csm_dp_cap_sg_msg_cb sg_cb;
};

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
int csm_dp_init(const struct csm_dp_log_cfg *logcfg);

/**
 * @brief
 * Initialize the library with a user provide device node name.
 * See csm_dp_init for more details.
 *
 * @param dev_name - device node name, e.g. "/dev/csm0-dp1"
 * @param logcfg - pointer to the structure which contains the
 *      	library logging configuration
 * @return On success, it returns file descriptor of DP device
 *         If it fails, it returns negative value
 */
int csm_dp_init_ex(const char *dev_name,
		   const struct csm_dp_log_cfg *logcfg);

/**
 * @brief
 * Cleanup the library. After it returns, all the mmapped DP
 * memory areas are unmapped. Any attempt to access those memory
 * regions will cause page fault.
 *
 * @return None
 */
void csm_dp_cleanup(void);
/**
 * @brief
 * Cleanup the library based on vf. After it returns, all the
 * mmapped DP memory areas are unmapped. Any attempt to access
 * those memory regions will cause page fault.
 *
 * @param handle - Handle for a csm_dp instance
 * @return None
 */
void csm_dp_cleanup_vf(uint16_t handle);

/**
 * @brief
 * Initialize the memory access to specific DP memory region
 *
 * The following procedures are used in library
 * - instruct DP driver to allocate contiguous DP memory
 * - mmap the DP memory into user space
 * - mmap ring buffer for buffer management into user space
 *
 * DP API uses fixed-size buffer for messaging. Each data path
 * has its own memory region. For DL, DP memory region is
 * created by API and shared between processes. For UL, UL DP
 * memory region is created by kernel.
 *
 * The ring buffer is shared between kernel and API for buffer
 * management.
 *
 * @param handle - Handle for a csm_dp instance
 * @param type - type of DP memory region
 * @param buf_sz - size of buffer in bytes. It must be the
 *      	 multiples of 1K(1024)
 * @param buf_num - size of DP memory region in number of
 *      	  fixed-size buffers
 *
 * @return On success - 0, otherwise failed
 */
int csm_dp_init_mem(
	uint16_t handle,
	enum csm_dp_mem_type type,
	unsigned int buf_sz,
	unsigned int buf_num);

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
void csm_dp_cleanup_mem(uint16_t handle, enum csm_dp_mem_type type);

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
 * @return On success - 0, otherwise failed
 */
int csm_dp_init_rx(uint16_t handle);

/**
 * @brief
 * Allocate DL buffer for TX
 *
 * The library preserves headroom for the message header. It
 * returns a buffer pointer that points to the starting of
 * message payload
 *
 * @param handle - Handle for a csm_dp instance
 * @param type - type of DP memory region
 * @param length - length of buffer
 *
 * @return The buffer pointer or NULL if it fails.
 */
void *csm_dp_alloc_txbuf(uint16_t handle,
			 enum csm_dp_mem_type type,
			 unsigned int length);

/**
 * @brief
 * Enhanced Allocate DL buffer for TX
 *
 * The library preserves headroom for the message header. It
 * returns a buffer pointer that points to the starting of
 * message payload. A unique *handle is returned for further use
 * to query buffer status.
 *
 * @param dev_handle - Handle for a csm_dp instance
 * @param type - type of DP memory region
 * @param length - length of buffer
 * @param *handle  - pointer to the *handle
 *
 * @return The buffer pointer or NULL if it fails.
 */
void *csm_dp_ealloc_txbuf(uint16_t dev_handle, enum csm_dp_mem_type type,
			  unsigned int length, unsigned int *handle);


/** @brief enum for query tx buffer status */
typedef enum {
	CSM_DP_TX_BUF_STATUS_TX_OK,	/*
					 * Buffer xmit is complete with success.
					 * It is available for reuse.
					 */
	CSM_DP_TX_BUF_STATUS_TX_OK_BUSY,
					/*
					 * Buffer xmit is complete with success.
					 * Its traffic capture is in progress.
					 */
	CSM_DP_TX_BUF_STATUS_TX_QUERY_ERR,
					/*
					 * Query error. Unknown buffer *handle.
					 * User may have freed buffer.
					 */
	CSM_DP_TX_BUF_STATUS_TX_ERR,	/*
					 * Buffer xmit is complete with error.
					 * It is available for reuse.
					 * The error code is returned from
					 * the queury API.
					 */

	CSM_DP_TX_BUF_STATUS_TX_ERR_BUSY,/*
					  * Buffer xmit is complete with error.
					  * The error code is returned from
					  * the queury API.
					  * Its traffic capture is in progress.
					  */
	CSM_DP_TX_BUF_STATUS_TX_IN_PROGRESS,
					/*
					 * Buffer xmit is in progress.
					 */
	CSM_DP_TX_BUF_STATUS_UNAVAIL,
					/*
					 * Buffer xmit status unavailable
					 */
	CSM_DP_TX_BUF_STATUS_LAST,
} csm_dp_txbuf_status_e;

/**
 * @brief
 * Query DL buffer tx status
 *
 * API to query the tx buffer status.
 * If the return status indicates transmit is still in progress
 * or internal busy, user should not reuse the buffer. If the buffer
 * transmission is still in progress, and user chooses not to wait but
 * free the buffer, the same buffer will not be allocated, until
 * transmission is complete.
 *
 * @param dev_handle - Handle for a csm_dp instance
 * @param bufptr - buffer pointer. The buffer must have
 *               been allocated by csm_dp_ealloc_tx API.
 * @param handle - buffer handle. The buffer handle must have
 *               been allocated by csm_dp_ealloc_tx API.
 * @err -        retrned error code , if TX err.
 *               The Tx may fail with EAGAIN err code, if the low
 *		 level transport is busy. User should handle
 *		 the error condition.
 *
 * @return status of specified transmit buffer. The status is one
 *         of the emums represented by csm_dp_txbuf_status.
 */
csm_dp_txbuf_status_e
csm_dp_query_txbuf_status(uint16_t dev_handle, unsigned int handle,
			  void *bufptr, int *err);

/**
 * @brief
 * tx allocate xmit busy counts
 *
 * A buffer trasnsmitted may still be in progress after
 * user frees it.
 * If that is the case during the next allocation,
 * the buffer is not allocated and skipped.
 * Such counts are maintained by the library.
 *
 * @param handle - Handle for a csm_dp instance
 * @return number of instances when this happens.
 */
unsigned int csm_dp_num_alloc_txbuf_tx_in_progress(uint16_t handle,
						   enum csm_dp_channel mode);

/**
 * @brief
 * Free a DL buffer that wasn't sent
 *
 * In case a buffer was allocated and for some reason application cannot send
 * it (e.g. failure to encode the message into the allocated buffer), the
 * application must use this API to free it.
 * Note that in normal use case, Tx buffer is freed by the library as part of
 * send operation (see csm_dp_send).
 *
 * After freeing the buffer, the *handle from the associated
 * csm_dp_ealloc_txbuf() is destroyed. Next time, the same buffer is
 * returned by csm_dp_ealloc_txbuf(), it will be associated with a
 * different handle.
 *
 * @param handle - Handle for a csm_dp instance
 * @param bufptr - buffer pointer. The returned buffer must have
 *      	 been allocated by csm_dp_alloc_tx API.
 *
 * @return None
 */
void csm_dp_free_unsent_txbuf(uint16_t handle, void *bufptr);

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
 * The library takes care of freeing the Tx buffers, unless CSM_DP_TX_FLAG_DONT_FREE is set.
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
int csm_dp_send(uint16_t handle, enum csm_dp_channel ch, struct iovec *iov,
		unsigned int iovcnt, unsigned int flag);

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
int csm_dp_rx_poll(uint16_t handle,
		   struct iovec *iov,
		   unsigned int iovcnt);
/**
 * @brief
 * Inline API to send a single message
 *
 * @param handle - Handle for a csm_dp instance
 * @param ch - channel to send on (CONTROL or DATA)
 * @param msg - pointer to the message payload
 * @param msglen - length of message payload
 * @param flag - the same flag definition as csm_dp_send
 */
static inline int csm_dp_send_single_msg(
	uint16_t handle,
	enum csm_dp_channel ch,
	void *msg,
	unsigned int msglen,
	unsigned int flag)
{
	struct iovec iov;

	iov.iov_base = msg;
	iov.iov_len = msglen;
	return csm_dp_send(handle, ch, &iov, 1, flag);
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
int csm_dp_recv(uint16_t handle,
		struct iovec *iov,
		unsigned int iovcnt);

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
 *      	 csm_dp_recv API.
 * @return None
 */
void csm_dp_free_rxbuf(uint16_t handle, void *bufptr);

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
 * @param callback_ops - callback ops. Set to NULL to use
 *      	   default callback in library which writes
 *      	   message into file.
 * @param cb_cookie - cookie for callback function. For default
 *      	    callback, it expects the pointer to
 *      	    configuration.
 * @param max_event - maximum number of pending capture event
 *
 * @return On success - 0, otherwise failed
 *
 */
int csm_dp_init_capture(uint16_t handle,
	const struct csm_dp_cap_cb_ops *cb_ops,
	void *cb_cookie,
	unsigned int max_event);

/**
 * @brief
 * To stop traffic capture and streaming.
 *
 * @param handle - Handle for a csm_dp instance
 *
 * @return None
 */
void csm_dp_cleanup_capture(uint16_t handle);

/**
 * @brief
 * To enable traffic capture on a specific channel
 *
 * @param handle - Handle for a csm_dp instance
 * @param ch - channel for capture
 *
 * @return On success - 0, otherwise failed
 */
int csm_dp_enable_capture(uint16_t handle, enum csm_dp_channel ch);

/**
 * @brief
 * To disable traffic capture on a specific channel
 *
 * @param handle - Handle for a csm_dp instance
 * @param ch - channel for capture
 *
 * @return On success - 0, otherwise failed
 */
int csm_dp_disable_capture(uint16_t handle, enum csm_dp_channel ch);

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
int csm_dp_get_capture_thread_tid(uint16_t handle, pthread_t *tid);

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
int csm_dp_set_loglevel(uint16_t handle, int loglevel);

/**
 * @brief
 * Get driver layer statistics.
 *
 * @param handle - Handle for a csm_dp instance
 * @param stats - statistics placeholder.
 *
 * @return On success - 0, otherwise failed
 */
int csm_dp_get_stats(uint16_t handle, struct csm_dp_ioctl_getstats *stats);

/**
 * @brief
 * Get device info handle.
 *
 * @param fd - file descriptor for vf.
 *
 * @return valid handle On success, otherwise INVALID_HANDLE returned
 */
uint16_t csm_dp_get_handle(int fd);

/**
 * @brief
 * Get bus index based on the handle.
 *
 * @param handle - Handle for a csm_dp instance
 *
 * @return valid bus id On success, otherwise INVALID_HANDLE returned
 */
unsigned int csm_dp_get_bus_index(uint16_t handle);

/**
 * @brief
 * Get vf index based on the handle.
 *
 * @param handle - Handle for a csm_dp instance
 *
 * @return valid vf id On success, otherwise INVALID_HANDLE returned
 */
unsigned int csm_dp_get_vf_index(uint16_t handle);

#ifdef __cplusplus
}
#endif

#endif /* CSM_DP_API_H */
