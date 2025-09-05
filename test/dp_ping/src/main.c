/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <syslog.h>
#include <bsd/string.h>

#include "csm_dp_api.h"

#define SIZE_1K                 1024
#define SIZE_1M			(SIZE_1K * 1024)
#define DEFAULT_TX_INTVAL	1000000U
#define	DEFAULT_TX_LENGTH	1024
#define DEFAULT_CAPTURE_EVENT_NUM       64
#define NUM_LAT_BUCKET 8

/* To align with limit on CSM */
#define	MAX_TX_LENGTH ((CSM_DP_MAX_DL_MSG_LEN < \
			CSM_DP_MAX_UL_MSG_LEN) ? \
				CSM_DP_MAX_DL_MSG_LEN : \
					CSM_DP_MAX_UL_MSG_LEN)
#define	DEFAULT_TX_BUNDLE	1

#define DEFAULT_RX_TIMEOUT	2000000U
#define DEFAULT_RX_POLL_INTVAL_US	125U
#define RX_TIMEOUT_GUARD (DEFAULT_RX_TIMEOUT - DEFAULT_TX_INTVAL)

#define DEFAULT_DL_BUFCNT	4096

#define DEFAULT_RESULT_INTVAL		1000
#define DEFAULT_RESULT_FIFO_DEPTH	100000
#define DEFAULT_RESULT_REPORT_PERIOD 10

enum {
	RX_THREAD,
	TX_THREAD,
	RESULT_THREAD,
	NUM_OF_THREAD,
};

struct cmd_option {
	unsigned int tx_length;
	unsigned int tx_bundle;
	float tx_intval_us;
	unsigned int tx_count;
	unsigned int rx_timeout;
	unsigned int result_intval;
	unsigned int result_fifo_depth;
	unsigned int flag;
	unsigned int verify;
	unsigned int verbose;
	unsigned int report_period;
	unsigned int random;
	unsigned int latency_stat;
	unsigned int tx_status;
	unsigned int tx_sg;
	unsigned int tx_capture;
	unsigned int poll_mode;
	unsigned int bus_num;
	unsigned int vf_num;
	unsigned int rx_affinity;
	unsigned int tx_affinity;
	unsigned int mem_pool_buf_size;
	unsigned int mem_pool_buf_count;
	unsigned int tx_mirror;
	unsigned int syslog;
	unsigned int rx_poll_inteval_us;
	unsigned int num_vf;
	bool run_both;
};

struct dp_ping_pkt_hdr {
	unsigned int magic;
	unsigned int seq;
	struct timespec ts;
	uint32_t magic_1;
	unsigned long dummy[4];  /* round it up to 64 bytes */
	uint32_t checksum;
} __attribute__((packed));

struct ping_result {
	unsigned int seq;
	struct timespec ts;
};

struct ping_result_fifo {
	unsigned int depth;
	unsigned int head;
	unsigned int tail;
	struct ping_result *result;
};

struct packet_stats {
	uint32_t _num_bad_checksum;
	uint32_t _num_good_checksum;
	uint32_t _num_ill_packet;
	uint32_t _this_report_num_rcv;
	uint32_t _num_rcv;
	uint32_t _num_tx;
	uint32_t _num_tx_drop;
	uint32_t _num_tx_ok;
	uint32_t _num_tx_err;
	uint32_t _num_tx_in_prog;
	uint32_t _num_tx_others;
	uint32_t _num_out_seq;
	uint32_t _num_report;
	uint64_t _total_latency;
	uint64_t _max_latency;
	uint64_t _min_latency;
	uint32_t print_time;
	bool first_result;
	unsigned int __ping_sequence;
	unsigned int __ping_count;
	unsigned int mem_pool_buf_size;
	uint64_t last_driver_stats_tx_acked;
	uint32_t latency_bucket[NUM_LAT_BUCKET];
	unsigned int __exp_seq;
	struct timespec report_start_ts;
	struct timespec report_end_ts;
};

struct csm_dp_app_data {
	int fd;
	enum csm_dp_channel mode;
	volatile bool __done;
	pthread_t tid[NUM_OF_THREAD];
	char _sg_tx_buf[MAX_TX_LENGTH * CSM_DP_MAX_SG_IOV_SIZE];
	char _sg_rx_buf[MAX_TX_LENGTH * CSM_DP_MAX_SG_IOV_SIZE];
	struct packet_stats stats;
	struct ping_result_fifo __result_fifo;
	struct csm_dp_cap_defcfg capcfg;
	unsigned int rx_affinity;
	unsigned int tx_affinity;
};

static struct cmd_option cmdline_option = {
	.tx_length = DEFAULT_TX_LENGTH,
	.tx_bundle = DEFAULT_TX_BUNDLE,
	.tx_intval_us = DEFAULT_TX_INTVAL,
	.tx_count  = 0,
	.rx_timeout = DEFAULT_RX_TIMEOUT,
	.result_intval = DEFAULT_RESULT_INTVAL,
	.result_fifo_depth = DEFAULT_RESULT_FIFO_DEPTH,
	.verbose = 0,
	.random = 0,
	.verify = 0,
	.report_period = DEFAULT_RESULT_REPORT_PERIOD,
	.latency_stat = 0,
	.tx_status = 0,
	.tx_sg = 0,
	.tx_capture = 0,
	.rx_affinity = 0,
	.tx_affinity = 0,
	.mem_pool_buf_size = 0,
	.mem_pool_buf_count = DEFAULT_DL_BUFCNT,
	.tx_mirror = 0,
	.syslog = 0,
	.rx_poll_inteval_us = DEFAULT_RX_POLL_INTVAL_US,
	.num_vf = 1,
	.run_both = 0,
};

struct csm_dp_cap_defcfg capcfg = {
	.file_name = "/tmp/dp_ping.pcap",
	.file_sz = SIZE_1M * 16,
	.file_num = 4,
	.snap_len = 128,
	.file_no_fflush = 1,
};


static pthread_t result_tid;
static struct csm_dp_app_data dp_app_control[CSM_DP_MAX_BUS][CSM_DP_MAX_VF];
static struct csm_dp_app_data dp_app_data[CSM_DP_MAX_BUS][CSM_DP_MAX_VF];
static uint32_t latency_bucket_time[NUM_LAT_BUCKET] = {125, 250, 500, 750, 1000, 1500, 2000, 4000};

static unsigned int rx_affinity = 5;
static unsigned int tx_affinity = 16;
static bool app_initialized_data;
static bool app_initialized_control;
void dump_pkt(char *pkt, unsigned int len)
{
	unsigned int i;

	printf("dump_pkt %p %d \n", pkt, len);
	for (i = 0; i < len;) {
		printf("%x ", *((unsigned int *) pkt));
		pkt += sizeof(unsigned int);
		i += sizeof(unsigned int);
		if ((i & 0x1f) == 0)
			printf("\n");
	}
	printf("\n\n\n");
}

static const char __usage[] = \
"dp_ping <option>\n"
"option:\n"
"TX option:\n"
"   -b number of packets in one burst (1..64), default 1\n"
"   -c packet counter, default infinite\n"
"   -i TX interval in us (fractional values (>=0) allowed), default 1,000,000 (1 second)\n"
"   -l TX packet length in bytes, default 1K, max ~2MB\n"
"   -m enable TX packet mirroring\n"
"   -C enable TX packet data capture\n"
"   -G send packet in scatter gather\n"
"   --buf_size TX memory pool buffer size, default 2K bytes\n"
"   --buf_count TX memory pool buffer count, default 4096 buffers\n"
"   --tx_affinity enable CPU affinity (1..number of available cores) for Tx thread\n"
"RX option:\n"
"   -t timeout in ms, default 2,000\n"
"   --rx_poll_interval Rx poll interval in us, relevant only with -P, default 125\n"
"   --rx_affinity enable CPU affinity (1..number of available cores) for Rx thread\n"
"REPORT option:\n"
"   -d max pending result\n"
"   -p report period in seconds, default 10\n"
"   -r interval to report in ms\n"
"   -s use syslog for logging (instead of printf)\n"
"   -S report tx status statistics\n"
"General option:\n"
"   -v enable verbose logging\n"
"   -x enable checksum verification\n"
"   -B bus number, default 0\n"
"   -D obsolete, see -V\n"
"   -L print latency statistics for this report period\n"
"   -P polling mode (Tx/Rx over DATA channel)\n"
"   -R fill packet payload from randon number generator\n"
"   -V Virtual function (VF0..3), default 0\n"
"   -n No of Virtual functions to be run(1..4), default 1\n"
"   -N run both channels, 0 for one channel, 1 for control & data, default 0\n";

static inline void __getopt_val(const char *opt, unsigned int *p)
{
	char *ptr = NULL;
	unsigned int val = strtoul(opt, &ptr, 0);

	if (!ptr || *ptr) {
		printf("invalid number\n");
		exit(-1);
	}
	*p = val;
}

static inline float __getopt_float(const char *opt)
{
	char *ptr = NULL;
	float val = strtof(opt, &ptr);

	if (!ptr || *ptr) {
		printf("invalid number\n");
		exit(-1);
	}
	return val;
}

static int thread_set_affinity(pthread_t thread, uint16_t affinity)
{
	cpu_set_t set;
	int i;
	int numcores = sysconf(_SC_NPROCESSORS_ONLN);
	uint64_t affinity_mask = 1 << affinity;

	if (!(affinity_mask & (((uint64_t)1 << numcores) - 1)))
		return 0;

	__CPU_ZERO_S(sizeof(set), &set);
	for (i = 0; i < numcores; i++) {
		if (affinity_mask & ((uint64_t)1 << i))
			__CPU_SET_S(i, sizeof(set), &set);
	}
	return pthread_setaffinity_np(thread, sizeof(set), &set);
}

static int thread_get_affinity(pthread_t thread)
{
	cpu_set_t set;
	int numcores = sysconf(_SC_NPROCESSORS_ONLN);
	int core_id, ret;

	/* Clear the CPU set */
	__CPU_ZERO_S(sizeof(set), &set);

	/* Get the current CPU affinity mask for the thread */
	ret = pthread_getaffinity_np(thread, sizeof(set), &set);
	if (ret) {
		printf("%s failed\n", __func__);
		return -1;
	}

	for (core_id = 0; core_id < numcores; core_id++) {
		if (__CPU_ISSET_S(core_id, sizeof(set), &set))
			return core_id;
	}

	return -1;
}

static void __parse_cmdline(int argc, char *argv[]) {
	int c;
	unsigned int v;
	/* getopt_long stores the option index here. */
	int option_index = 0;
	unsigned int numcores = sysconf(_SC_NPROCESSORS_ONLN);

	enum {
		LONG_OPTION_INDEX_BUF_SIZE = 0,
		LONG_OPTION_INDEX_BUF_COUNT = 1,
		LONG_OPTION_INDEX_RX_POLL_INTERVAL = 2,
		LONG_OPTION_INDEX_CPU_AFFINITY_TX = 3,
		LONG_OPTION_INDEX_CPU_AFFINITY_RX = 4,
	};

	struct option long_options[] = {
		{"buf_size",  required_argument, NULL, LONG_OPTION_INDEX_BUF_SIZE},
		{"buf_count", required_argument, NULL, LONG_OPTION_INDEX_BUF_COUNT},
		{"rx_poll_interval", required_argument, NULL, LONG_OPTION_INDEX_RX_POLL_INTERVAL},
		{"tx_affinity", required_argument, NULL, LONG_OPTION_INDEX_CPU_AFFINITY_TX},
		{"rx_affinity", required_argument, NULL, LONG_OPTION_INDEX_CPU_AFFINITY_RX},
		{0, 0, 0, 0}
	};

	while ((c = getopt_long(argc, argv, "l:n:c:t:i:b:r:d:p:B:D:V:svxhmRLSGCPNA:", long_options, &option_index)) != EOF) {
		switch (c) {
		// short options
		case 'l':
			__getopt_val(optarg, &v);
			if (v >= sizeof(struct dp_ping_pkt_hdr))
				cmdline_option.tx_length = v;
			break;
		case 'n':
			__getopt_val(optarg, &v);
			if (v > CSM_DP_MAX_VF) {
				printf("%s\n", __usage);
				exit(0);
			}
				cmdline_option.num_vf = v;
			break;
		case 'c':
			__getopt_val(optarg,  &cmdline_option.tx_count);
			break;
		case 'i':
			cmdline_option.tx_intval_us = __getopt_float(optarg);
			if (cmdline_option.tx_intval_us < 0) {
				printf("Invalid Tx interval, ignoring\nSetting the Tx interval to default value %.3fus\n",(float)DEFAULT_TX_INTVAL);
				cmdline_option.tx_intval_us = (float)DEFAULT_TX_INTVAL;
			}
			break;
		case 'b':
			__getopt_val(optarg, &v);
			if (!v) {
				printf("Invalid Tx burst, ignoring\n");
				break;
			}
			if (v > CSM_DP_MAX_IOV_SIZE) {
				printf("Tx burst: %d > %d, setting Tx burst to %d\n",
					v, CSM_DP_MAX_IOV_SIZE, CSM_DP_MAX_IOV_SIZE);
				v = CSM_DP_MAX_IOV_SIZE;
			}
			cmdline_option.tx_bundle = v;
			break;
		case 't':
			__getopt_val(optarg, &v);
			if (v)
				cmdline_option.rx_timeout = v * 1000;
			break;
		case 'P':
			cmdline_option.poll_mode = 1;
			break;
		case 'r':
			__getopt_val(optarg, &v);
			if (v)
				cmdline_option.result_intval = v * 1000;
			break;
		case 'd':
			__getopt_val(optarg, &v);
			if (v)
				cmdline_option.result_fifo_depth = v;
			break;
		case 'h':
			printf("%s\n", __usage);
			exit(0);
		case 'm':
			cmdline_option.tx_mirror = 1;
			break;
		case 's':
			cmdline_option.syslog = 1;
			break;
		case 'v':
			cmdline_option.verbose = 1;
			break;
		case 'x':
			cmdline_option.verify = 1;
			break;
		case 'p':
			__getopt_val(optarg, &v);
			if (v)
				cmdline_option.report_period = v;
			break;
		case 'R':
			cmdline_option.random = 1;
			break;
		case 'L':
			cmdline_option.latency_stat = 1;
			break;
		case 'S':
			cmdline_option.tx_status = 1;
			break;
		case 'G':
			cmdline_option.tx_sg = 1;
			break;
		case 'C':
			cmdline_option.tx_capture = 1;
			break;
		case 'B':
			__getopt_val(optarg, &v);
			if (v)
				cmdline_option.bus_num = v;
			break;
		case 'D':
		case 'V':
			__getopt_val(optarg, &v);
			if (v)
				cmdline_option.vf_num = v;
			break;
		case 'N':
			cmdline_option.run_both = 1;
			break;
		// long options
		case LONG_OPTION_INDEX_BUF_SIZE:
			__getopt_val(optarg, &v);
			cmdline_option.mem_pool_buf_size = v;
			break;
		case LONG_OPTION_INDEX_BUF_COUNT:
			__getopt_val(optarg, &v);
			cmdline_option.mem_pool_buf_count = v;
			break;
		case LONG_OPTION_INDEX_RX_POLL_INTERVAL:
			__getopt_val(optarg, &v);
			cmdline_option.rx_poll_inteval_us = v;
			break;
		case LONG_OPTION_INDEX_CPU_AFFINITY_TX:
			__getopt_val(optarg, &v);
			if(v >= 1 &&  v <= numcores) {
				cmdline_option.tx_affinity = v;
			} else {
				printf("Invalid Tx Affinity, exiting..\n");
				exit(-1);
			}
			break;
		case LONG_OPTION_INDEX_CPU_AFFINITY_RX:
			__getopt_val(optarg, &v);
			if(v >= 1 &&  v <= numcores) {
				cmdline_option.rx_affinity = v;
			} else {
				printf("Invalid Rx Affinity, exiting..\n");
				exit(-1);
			}
			break;
		default:
			printf("%s\n", __usage);
			exit(-1);
		}
	}
}

static uint32_t fcstab_32[256] = {
      0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
      0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
      0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
      0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
      0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
      0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
      0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
      0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
      0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
      0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
      0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
      0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
      0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
      0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
      0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
      0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
      0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
      0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
      0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
      0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
      0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
      0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
      0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
      0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
      0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
      0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
      0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
      0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
      0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
      0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
      0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
      0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
      0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
      0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
      0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
      0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
      0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
      0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
      0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
      0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
      0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
      0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
      0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
      0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
      0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
      0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
      0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
      0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
      0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
      0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
      0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
      0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
      0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
      0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
      0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
      0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
      0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
      0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
      0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
      0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
      0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
      0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
      0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
      0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

/*
 * Calculate 32 bit CRC
 */
static u_int32_t pkgen_crc32(unsigned char *cp, int len)
{
	u_int32_t fcs = 0xffffffff;

	while (len--)
		fcs = (((fcs) >> 8) ^ fcstab_32[((fcs) ^ (*cp++)) & 0xff]);
	return (fcs ^ 0xffffffff);
}


static int __ping_result_add(struct ping_result_fifo *fifo, struct ping_result *result)
{
	unsigned int head_next = (fifo->head == fifo->depth -1) ? 0 : fifo->head+1;
	if (head_next == fifo->tail)
		return -1;

	memcpy(&fifo->result[fifo->head], result, sizeof(*result));
	fifo->head = head_next;
	return 0;
}

static int __ping_result_get(struct ping_result_fifo *fifo, struct ping_result *result)
{
	if (fifo->tail == fifo->head)
		return -1;
	memcpy(result, &fifo->result[fifo->tail], sizeof(*result));
	fifo->tail = (fifo->tail == fifo->depth -1) ? 0 : fifo->tail+1;
	return 0;
}

static int __ping_result_fifo_init(struct ping_result_fifo *fifo, unsigned int depth)
{
	void *p = malloc(sizeof(struct ping_result) * depth);
	if (!p)
		return -1;
	memset(fifo, 0, sizeof(*fifo));
	fifo->depth = depth;
	fifo->result = p;
	return 0;
}

static void calc_ts_diff(struct timespec *start, struct timespec *end, struct timespec *diff)
{
	if (end->tv_nsec < start->tv_nsec) {
		end->tv_nsec += 1000000000;
		end->tv_sec--;
	}
	diff->tv_nsec = end->tv_nsec - start->tv_nsec;
	diff->tv_sec = end->tv_sec - start->tv_sec;
}

static void _ping_print_report(struct csm_dp_app_data *dp_data)
{
	int i, ret;
	struct timespec ts_diff;
	double diff_us;
	struct csm_dp_ioctl_getstats driver_stats = { 0 };
	uint64_t this_report_tx_acked = 0;

	uint16_t handle = csm_dp_get_handle(dp_data->fd);
	if (handle == INVALID_HANDLE)
		return;

	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return;


	driver_stats.ch = dp_data->mode ? CSM_DP_CH_DATA : CSM_DP_CH_CONTROL;
	ret = csm_dp_get_stats(handle, &driver_stats);
	if (!ret) {
		this_report_tx_acked = driver_stats.tx_acked - dp_data->stats.last_driver_stats_tx_acked;
		dp_data->stats.last_driver_stats_tx_acked = driver_stats.tx_acked;
	}

	calc_ts_diff(&dp_data->stats.report_start_ts, &dp_data->stats.report_end_ts, &ts_diff);
	diff_us = ts_diff.tv_sec * 1000000 + ts_diff.tv_nsec / 1000;

	printf("\n\n Bus:%d VF:%d %s Channel Report %d\n",
				bus,
				vf,
				(dp_data->mode == CSM_DP_CH_DATA) ? "DATA" : "CONTROL",
				++dp_data->stats._num_report);
	printf("  Tx Packets            :       %u\n", dp_data->stats._num_tx);
	printf("  Rx Packets            :       %u\n", dp_data->stats._num_rcv);
	printf("  Tx Throughput (Mbps)  :       %.3f\n",
		diff_us ? ((double)this_report_tx_acked * cmdline_option.tx_length * 8) / diff_us : 0);
	printf("  Rx Throughput (Mbps)  :       %.3f\n",
		diff_us ? ((double)dp_data->stats._this_report_num_rcv * cmdline_option.tx_length * 8) / diff_us : 0);
	printf("  Tx Packets Dropped    :       %u\n", dp_data->stats._num_tx_drop);
	printf("  Rx, Ill Format        :       %u\n", dp_data->stats._num_ill_packet);
	printf("  Rx, Out of Sequence   :       %u\n", dp_data->stats._num_out_seq);
	if (cmdline_option.tx_status) {
		printf("  Tx Status Done OK     :       %u\n", dp_data->stats._num_tx_ok);
		printf("  Tx Status In Prog     :       %u\n", dp_data->stats._num_tx_in_prog);
		printf("  Tx Status Err         :       %u\n", dp_data->stats._num_tx_err);
		printf("  Tx Status Others      :       %u\n", dp_data->stats._num_tx_others);
		printf("  Alloc Tx Buf Tx Busy  :       %u\n",
						csm_dp_num_alloc_txbuf_tx_in_progress(handle, dp_data->mode));
	}
	if (cmdline_option.verify) {
		printf("  Rx, Bad Checksum      :       %u\n", dp_data->stats._num_bad_checksum);
		printf("  Rx, Good Checksum     :       %u\n", dp_data->stats._num_good_checksum);
	}
	if (dp_data->stats._num_rcv && cmdline_option.latency_stat) {
		printf("Long Term Average latency  :       %ld us\n",
						 dp_data->stats._total_latency / dp_data->stats._num_rcv);
		if (dp_data->stats._this_report_num_rcv) {
			printf("Min latency@this period     :       %ld us\n",
						dp_data->stats._min_latency);
			printf("Max latency@this period     :       %ld us\n",
						dp_data->stats._max_latency);
			printf("\n\nLatency Distribution\n");
			printf("\n");
			for (i = 0; i < NUM_LAT_BUCKET; i++)
				printf("<  %6d us  ", latency_bucket_time[i]);
			printf("\n");
			for (i = 0; i < NUM_LAT_BUCKET; i++)
				printf("%6d pkt    ", dp_data->stats.latency_bucket[i]);
			printf("\n");
			memset(&dp_data->stats.latency_bucket, 0, sizeof(dp_data->stats.latency_bucket));
		}
		printf("packet receive@this period:       %u\n",
						dp_data->stats._this_report_num_rcv);
	}
	dp_data->stats._this_report_num_rcv = 0;
	dp_data->stats._min_latency = 0xffffffff;
	dp_data->stats._max_latency = 0;
}

static void __ping_result_fifo_cleanup(struct ping_result_fifo *fifo)
{
	if (fifo->result) {
		free(fifo->result);
		fifo->result = NULL;
	}
}

static int __csm_init(uint16_t handle, enum csm_dp_channel mode)
{
	int ret, fd;
	unsigned int buf_size = cmdline_option.mem_pool_buf_size;
	unsigned int buf_cnt = cmdline_option.mem_pool_buf_count;
	unsigned int seg_size = cmdline_option.tx_length;
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);
	char dev_name[20];
	int dl_mode = (mode == CSM_DP_CH_CONTROL) ? CSM_DP_MEM_TYPE_DL_CONTROL : CSM_DP_MEM_TYPE_DL_DATA;
	struct csm_dp_log_cfg log_cfg = {
		.level = LOG_INFO,
		.output = CSM_DP_LOG_OUTPUT_CONSOLE,
	};

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return -EINVAL;

	if (cmdline_option.tx_sg)
		seg_size /= CSM_DP_MAX_SG_IOV_SIZE;

	if (seg_size > MAX_TX_LENGTH) {
		if (cmdline_option.tx_sg)
			printf("Invalid segment size: %d > %d\n", seg_size, MAX_TX_LENGTH);
		else
			printf("Invalid Tx len: %d > %d\n", seg_size, MAX_TX_LENGTH);
		return -1;
	}

	if (!buf_size)
		buf_size = mode ?
			CSM_DP_DEFAULT_DATA_BUFSZ : CSM_DP_DEFAULT_CONTROL_BUFSZ;
	if (buf_size < seg_size)
		buf_size = seg_size;
	buf_size = (buf_size + CSM_DP_L1_CACHE_BYTES - 1) &
				~(CSM_DP_L1_CACHE_BYTES - 1);
	if (buf_size > CSM_DP_MAX_DL_MSG_LEN) {
		printf("request buffer size %d exceeds limit %d\n",
			buf_size, CSM_DP_MAX_DL_MSG_LEN);
		return -1;
	}

	if (cmdline_option.verbose)
		log_cfg.level = LOG_DEBUG;
	if (cmdline_option.syslog)
		log_cfg.output = CSM_DP_LOG_OUTPUT_SYSLOG;

	snprintf(dev_name, sizeof(dev_name), "/dev/csm%d-dp%d",
		bus, vf);

	printf("dp_ping packet count %d, packet length %d, interval %.3fus, device %s.\n",
		cmdline_option.tx_count, cmdline_option.tx_length, cmdline_option.tx_intval_us, dev_name);
	printf("%s channel, SG %sabled\n",
		mode ? "DATA" : "CONTROL", cmdline_option.tx_sg ? "En" : "Dis");

	fd = csm_dp_init_ex(dev_name, &log_cfg);
	if (fd < 0) {
		printf("Failed to init device \"%s\": %s\n", dev_name, strerror(errno));
		return -1;
	}

	if (cmdline_option.tx_capture) {
		strlcpy(capcfg.file_name, "/tmp/dp_ping.pcap", sizeof(capcfg.file_name));
		snprintf(capcfg.file_name + strlen(capcfg.file_name), sizeof(capcfg.file_name)-strlen(capcfg.file_name), "_BUS%d_VF%d", bus, vf);
		if (csm_dp_init_capture(handle, NULL, &capcfg,
					DEFAULT_CAPTURE_EVENT_NUM)) {
			printf("csm_dp_init_capture failed\n");
			close(fd);
			return -EIO;
		}
		printf("Packet capture enabled, file name %s\n", capcfg.file_name);
	}

	ret = csm_dp_init_mem(handle, dl_mode, buf_size, buf_cnt);
	if (ret) {
		printf("csm_dp_init_mem failed\n");
		close(fd);
		return -1;
	}

	ret = csm_dp_init_rx(handle);
	if (ret) {
		printf("csm_dp_init_rx failed\n");
		close(fd);
		return -1;
	}

	csm_dp_enable_capture(handle, CSM_DP_CH_CONTROL);
	csm_dp_enable_capture(handle, CSM_DP_CH_DATA);

	return fd;
}

static void __csm_cleanup(uint16_t handle)
{
	if (cmdline_option.tx_capture)
		csm_dp_cleanup_capture(handle);
	csm_dp_cleanup();
}

static void __csm_rx_drain(uint16_t handle, enum csm_dp_channel mode)
{
	struct iovec iov[CSM_DP_MAX_IOV_SIZE];
	int ret, i, prev_ret = -1;

	while (1) {
		if (mode == CSM_DP_CH_CONTROL)
			ret = csm_dp_recv(handle, iov, CSM_DP_MAX_IOV_SIZE);
		else
			ret = csm_dp_rx_poll(handle, iov, CSM_DP_MAX_IOV_SIZE);

		if (ret < 0) {
			break;
		} else if (ret == 0) {
			if (prev_ret == 0)
				/* two consecutive zeros => Rx queue fully drained */
				break;

			usleep(100000);
		}
		prev_ret = ret;

		for (i = 0; i < ret; i++)
			csm_dp_free_rxbuf(handle, iov[i].iov_base);
	}
}

static void __result_proc(struct csm_dp_app_data *dp_data)
{
	uint64_t latency;
	int i;

	dp_data->stats._max_latency = 0;
	dp_data->stats._min_latency = 0xffffffff;

	struct ping_result result;

	while (!__ping_result_get(&dp_data->__result_fifo, &result)) {
		if (dp_data->stats.first_result) {
			clock_gettime(CLOCK_MONOTONIC, &dp_data->stats.report_start_ts);
			dp_data->stats.first_result = false;
		}
		clock_gettime(CLOCK_MONOTONIC, &dp_data->stats.report_end_ts);

		if (result.ts.tv_sec) {
			if (cmdline_option.verbose)
				printf("%u bytes ping: seq=%u time=%lus.%luus\n",
				cmdline_option.tx_length,
				result.seq,
				result.ts.tv_sec,
				result.ts.tv_nsec / 1000);
			latency = result.ts.tv_nsec / 1000 + result.ts.tv_sec * 1000000;
		} else {
			if (cmdline_option.verbose)
				printf("%u bytes ping: seq=%u time=%luus\n",
				cmdline_option.tx_length,
				result.seq,
				result.ts.tv_nsec / 1000);
			latency = result.ts.tv_nsec / 1000;
		}
		dp_data->stats._total_latency += latency;
		if (latency > dp_data->stats._max_latency)
			dp_data->stats._max_latency = latency;
		if (latency < dp_data->stats._min_latency)
			dp_data->stats._min_latency = latency;

		for (i = 0; i < NUM_LAT_BUCKET; i++) {
			if (latency <= latency_bucket_time[i]) {
				dp_data->stats.latency_bucket[i]++;
				break;
			}
		}
		if (i == NUM_LAT_BUCKET)
			dp_data->stats.latency_bucket[i - 1]++;
	}
	usleep(cmdline_option.result_intval);
	dp_data->stats.print_time += cmdline_option.result_intval / 1000;
	if (dp_data->stats.print_time >= cmdline_option.report_period * 1000) {
		_ping_print_report(dp_data);
		dp_data->stats.print_time = 0;
		dp_data->stats.first_result = true;
	}
}

void display_ping_print_report(void)
{
	int mode = cmdline_option.poll_mode;
        int bus_index, vf_index;
        struct csm_dp_app_data (*dp_data)[CSM_DP_MAX_VF] = NULL;

	if (mode == CSM_DP_CH_CONTROL || cmdline_option.run_both) {
		dp_data = dp_app_control;
		for (bus_index = 0; bus_index < CSM_DP_MAX_BUS; bus_index++) {
			for (vf_index = 0; vf_index < CSM_DP_MAX_VF; vf_index++) {
				if (dp_data[bus_index][vf_index].fd < 0)
					continue;
				_ping_print_report(&dp_data[bus_index][vf_index]);
			}
		}
	}

	if (mode == CSM_DP_CH_DATA || cmdline_option.run_both) {
		dp_data = dp_app_data;
		for (bus_index = 0; bus_index < CSM_DP_MAX_BUS; bus_index++) {
			for (vf_index = 0; vf_index < CSM_DP_MAX_VF; vf_index++) {
				if (dp_data[bus_index][vf_index].fd < 0)
					continue;
				_ping_print_report(&dp_data[bus_index][vf_index]);
			}
		}
	}
}

static void *__result_main(__attribute__((unused)) void *arg)
{
	int mode = cmdline_option.poll_mode;
	int bus_index, vf_index, done = 0;
	struct csm_dp_app_data (*dp_data)[CSM_DP_MAX_VF] = NULL;

	while (!done) {
		if (mode == CSM_DP_CH_CONTROL || cmdline_option.run_both) {
			dp_data = dp_app_control;
			for (bus_index = 0; bus_index < CSM_DP_MAX_BUS; bus_index++) {
				for (vf_index = 0; vf_index < CSM_DP_MAX_VF; vf_index++) {
					if (dp_data[bus_index][vf_index].fd < 0)
						continue;
					__result_proc(&dp_data[bus_index][vf_index]);
					done = dp_data[bus_index][vf_index].__done;
				}
			}
		}

		if (mode == CSM_DP_CH_DATA || cmdline_option.run_both) {
			dp_data = dp_app_data;
			for (bus_index = 0; bus_index < CSM_DP_MAX_BUS; bus_index++) {
				for (vf_index = 0; vf_index < CSM_DP_MAX_VF; vf_index++) {
					if (dp_data[bus_index][vf_index].fd < 0)
						continue;
					__result_proc(&dp_data[bus_index][vf_index]);
					done = dp_data[bus_index][vf_index].__done;
				}
			}
		}
	}
	display_ping_print_report();
	return NULL;
}

static void __validate_rx_buf(struct dp_ping_pkt_hdr *hdr, struct csm_dp_app_data *dp_data)
{
	struct ping_result result;
	struct timespec now;
	uint32_t gcrc;

	if (hdr->magic != (unsigned int)dp_data->tid[1]) {
		dp_data->stats._num_ill_packet++;
		return;
	}

	clock_gettime(CLOCK_MONOTONIC, &now);
	calc_ts_diff(&hdr->ts, &now, &result.ts);
	result.seq = hdr->seq;
	if (hdr->seq != dp_data->stats.__exp_seq)
		dp_data->stats._num_out_seq++;
	dp_data->stats.__exp_seq = hdr->seq + 1;

	if (!cmdline_option.verify) {
		__ping_result_add(&dp_data->__result_fifo, &result);
		return;
	}

	gcrc = pkgen_crc32(
		(u_int8_t *)(hdr + 1),
		cmdline_option.tx_length -
		sizeof(struct dp_ping_pkt_hdr));
	if (hdr->checksum == gcrc) {
		dp_data->stats._num_good_checksum++;
		__ping_result_add(&dp_data->__result_fifo, &result);
		return;
	}

	/* bad chechsum */
	dp_data->stats._num_bad_checksum++;
	printf("bad checksum seq %x header %lx checksum %x gen %x\n",
		hdr->seq,
		sizeof(struct dp_ping_pkt_hdr),
		hdr->checksum,
		gcrc);
	dump_pkt((char *) hdr,
		cmdline_option.tx_length);
}

static int __validate_rx_sg(struct iovec *iov, int n, int start_index, struct csm_dp_app_data *dp_data)
{
	unsigned int sg_len = 0;
	uint16_t dp_handle = csm_dp_get_handle(dp_data->fd);
	int i;
	char *s = dp_data->_sg_rx_buf;

	for (i = start_index; i < n; i++) {
		if (cmdline_option.verbose)
			printf("sg recv [%d/%d]: len %ld\n", i + 1, n, iov[i].iov_len);
		if (iov[i].iov_len == 0) {
			sg_len += CSM_DP_DEFAULT_UL_BUF_SIZE;
			// for checksum verification, copy the whole packet into contiguous buffer.
			// otherwise, copy only packet header
			if (cmdline_option.verify)
				memcpy(s, iov[i].iov_base, CSM_DP_DEFAULT_UL_BUF_SIZE);
			else if (i == start_index)
				memcpy(s, iov[i].iov_base, sizeof(struct dp_ping_pkt_hdr));
			s += CSM_DP_DEFAULT_UL_BUF_SIZE;

			csm_dp_free_rxbuf(dp_handle, iov[i].iov_base);
			continue;
		}

		/* last buf of SG */
		if (iov[i].iov_len > sg_len)
			iov[i].iov_len -= sg_len;
		sg_len += iov[i].iov_len;
		if (cmdline_option.verify)
			memcpy(s, iov[i].iov_base, iov[i].iov_len);

		if (sg_len != cmdline_option.tx_length) {
			printf("sg recv length %u doesn't match expected %u\n", sg_len, cmdline_option.tx_length);
		}

		__validate_rx_buf((struct dp_ping_pkt_hdr *)dp_data->_sg_rx_buf, dp_data);

		csm_dp_free_rxbuf(dp_handle, iov[i].iov_base);
		goto out;
	}

	printf("fail to find end of sg chain\n");

out:
	return i - start_index;
}

static int __rx_proc(struct iovec *iov, int n, struct csm_dp_app_data *dp_data)
{
	int i;
	uint16_t dp_handle = csm_dp_get_handle(dp_data->fd);

	for (i = 0; i < n; i++) {
		dp_data->stats._num_rcv++;
		dp_data->stats._this_report_num_rcv++;
		if (iov[i].iov_len == 0) {
			/* start of sg chain */
			i += __validate_rx_sg(iov, n, i, dp_data);
			continue;
		}
		else if (iov[i].iov_len == cmdline_option.tx_length) {
			if (cmdline_option.verbose)
				printf("recv length %ld\n", iov[i].iov_len);
			__validate_rx_buf(iov[i].iov_base, dp_data);
		} else {
			struct dp_ping_pkt_hdr *hdr = (struct dp_ping_pkt_hdr *)iov[i].iov_base;
			printf("recv length %ld don't match %d. seq %d exp seq %d\n",
				iov[i].iov_len,
				cmdline_option.tx_length,
				hdr->seq, dp_data->stats.__exp_seq);
		}
		csm_dp_free_rxbuf(dp_handle, iov[i].iov_base);
	}

	return 0;
}

static void *__rx_main(void *arg)
{
	struct csm_dp_app_data *dp_data = (struct csm_dp_app_data *)arg;
	int fd = dp_data->fd;
	uint16_t dp_handle = csm_dp_get_handle(fd);
	int ret;

	if (dp_handle == INVALID_HANDLE)
		return NULL;

	unsigned int bus = csm_dp_get_bus_index(dp_handle);
	unsigned int vf = csm_dp_get_vf_index(dp_handle);

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return NULL;

	if (cmdline_option.rx_affinity) {
		ret = thread_set_affinity(pthread_self(), cmdline_option.rx_affinity++);
		if (ret) {
			printf("Set RX Thread affinity 0x%x failed\n", cmdline_option.rx_affinity - 1);
			return NULL;
		}
		printf("RX_CONTROL_%u_%u Thread assigned to CPU %d affinity\n",
			bus, vf, thread_get_affinity(pthread_self()));
	}
	else {
		ret = thread_set_affinity(pthread_self(), dp_data->rx_affinity);
		if (ret) {
			printf("Set RX Thread affinity 0x%x failed\n", dp_data->rx_affinity);
			return NULL;
		}
		printf("RX_CONTROL_%u_%u Thread assigned to CPU %d affinity\n",
			bus, vf, thread_get_affinity(pthread_self()));
	}

	if (cmdline_option.rx_timeout < cmdline_option.tx_intval_us + RX_TIMEOUT_GUARD) {
		cmdline_option.rx_timeout = cmdline_option.tx_intval_us + RX_TIMEOUT_GUARD;
		printf("rx_timeout adjusted to %dus\n", cmdline_option.rx_timeout);
	}

	while (! dp_data->__done) {
		struct timeval tmval;
		fd_set fds;
		int ret, n;
		struct iovec iov[CSM_DP_MAX_IOV_SIZE];

		FD_ZERO(&fds);
		FD_SET(fd, &fds);

		tmval.tv_sec = cmdline_option.rx_timeout / 1000000;
		tmval.tv_usec = cmdline_option.rx_timeout%1000000;

		ret = select(fd + 1, &fds, NULL, NULL, &tmval);

		if (dp_data->__done)
			break;

		if (ret < 0) {
			perror("select");
			continue;
		}
		if (!FD_ISSET(fd, &fds)) {
			printf("Timeout\n");
			continue;
		}

		while ((n = csm_dp_recv(dp_handle, iov, CSM_DP_MAX_IOV_SIZE)) > 0) {
			if (__rx_proc(iov, n, dp_data))
				break;
		}
	}
	return NULL;
}

static void *__rx_poll_main(void *arg)
{
	struct csm_dp_app_data *dp_data = (struct csm_dp_app_data *)arg;
	struct iovec iov[CSM_DP_MAX_IOV_SIZE];
	uint16_t dp_handle = csm_dp_get_handle(dp_data->fd);
	int ret;

	if (dp_handle == INVALID_HANDLE)
		return NULL;

	unsigned int bus = csm_dp_get_bus_index(dp_handle);
	unsigned int vf = csm_dp_get_vf_index(dp_handle);

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return NULL;

	if (cmdline_option.rx_affinity) {
		ret = thread_set_affinity(pthread_self(), cmdline_option.rx_affinity++);
		if (ret) {
			printf("Set RX Thread affinity 0x%x failed\n", cmdline_option.rx_affinity - 1);
			return NULL;
		}
		printf("RX_DATA_%u_%u Thread assigned to CPU %d affinity\n",
			bus, vf, thread_get_affinity(pthread_self()));
	}
	else {
		ret = thread_set_affinity(pthread_self(), dp_data->rx_affinity);
		if (ret) {
			printf("Set RX Thread affinity 0x%x failed\n", dp_data->rx_affinity);
			return NULL;
		}
		printf("RX_DATA_%u_%u Thread assigned to CPU %d affinity\n",
			bus, vf, thread_get_affinity(pthread_self()));
	}

	while (! dp_data->__done) {
		ret = csm_dp_rx_poll(dp_handle, iov, CSM_DP_MAX_IOV_SIZE);
		if (ret < 0) {
			continue;
		}

		if (__rx_proc(iov, ret, dp_data))
			break;

		if (ret < CSM_DP_MAX_IOV_SIZE)
			usleep(cmdline_option.rx_poll_inteval_us);
	}

	return NULL;
}

static int __create_ping_pkt(uint16_t dp_handle,
			     struct iovec *iov,
			     unsigned int iovcnt,
			     unsigned int *iohandle,
			     struct csm_dp_app_data *dp_data)
{
	unsigned int i;
	uint32_t *p;
	int num;
	int j;

	if (cmdline_option.tx_sg) {
		unsigned int len;

		iovcnt =  CSM_DP_MAX_SG_IOV_SIZE;
		len = cmdline_option.tx_length;
		for (i = 0; i < CSM_DP_MAX_SG_IOV_SIZE - 1; i++) {
			iov[i].iov_len =
				cmdline_option.tx_length /
					CSM_DP_MAX_SG_IOV_SIZE;
			len -= iov[i].iov_len;
		}
		iov[CSM_DP_MAX_SG_IOV_SIZE - 1].iov_len = len;
	}

	for (i = 0; i < iovcnt; i++) {

		struct dp_ping_pkt_hdr *hdr = NULL;

		if (!cmdline_option.tx_sg)
			iov[i].iov_len = cmdline_option.tx_length;
		iov[i].iov_base =
			csm_dp_ealloc_txbuf(dp_handle, dp_data->mode ? CSM_DP_MEM_TYPE_DL_DATA : CSM_DP_MEM_TYPE_DL_CONTROL, iov[i].iov_len, &iohandle[i]);
		if (!iov[i].iov_base) {
			printf("csm_dp_alloc_txbuf failed\n");
			return -1;
		}
		if (i == 0 || !cmdline_option.tx_sg) {
			hdr = iov[i].iov_base;
			hdr->seq = dp_data->stats.__ping_sequence++;
			hdr->magic = (unsigned int)dp_data->tid[TX_THREAD];
			clock_gettime(CLOCK_MONOTONIC, &hdr->ts);
		} else {
			memset(iov[i].iov_base, 0,  sizeof(struct dp_ping_pkt_hdr));
		}

		num = (cmdline_option.tx_length -
			sizeof(struct dp_ping_pkt_hdr)) / sizeof(uint32_t);
		if (cmdline_option.tx_sg)
			continue;  /* do with verify option later*/
		p = (uint32_t *)(hdr + 1);
		if (cmdline_option.verify) {
			for (j = 0; j < num; j++, p++)
				if (cmdline_option.random)
					*p = rand();
				else
					*p = hdr->seq + j;
			hdr->checksum = pkgen_crc32(
				(u_int8_t *)(hdr + 1),
				cmdline_option.tx_length -
					sizeof(struct dp_ping_pkt_hdr));
		}
	}

	/* do the sg verification setup */
	if (cmdline_option.verify && cmdline_option.tx_sg) {
		struct dp_ping_pkt_hdr *hdr =  iov[0].iov_base;
		char *d;
		char *s =  dp_data->_sg_tx_buf;

		p = (uint32_t *)dp_data->_sg_tx_buf;
		for (j = 0; j < num; j++, p++)
			if (cmdline_option.random)
				*p = rand();
			else
				*p = hdr->seq + j;
		hdr->checksum = pkgen_crc32(
				(u_int8_t *)(dp_data->_sg_tx_buf),
				cmdline_option.tx_length -
					sizeof(struct dp_ping_pkt_hdr));
		for (i = 0; i < iovcnt; i++) {
			if (i == 0) {
				d = (char *)(hdr + 1);
				memcpy(d, s, iov[0].iov_len - sizeof(*hdr));
				s += iov[0].iov_len - sizeof(*hdr);
			} else {
				d = iov[i].iov_base;
				memcpy(d, s, iov[i].iov_len);
				s += iov[i].iov_len;
			}
		}
	}
	return 0;
}

static int __free_ping_pkt(uint16_t dp_handle,
			   struct iovec *iov,
			   unsigned int iovcnt,
			   unsigned int *iohandle,
			   struct csm_dp_app_data *dp_data)
{
	unsigned int i;
	csm_dp_txbuf_status_e status;

	if (dp_handle == INVALID_HANDLE)
		return INVALID_HANDLE;

	for (i = 0; i < iovcnt; i++) {
		status = csm_dp_query_txbuf_status(dp_handle, iohandle[i],
						iov[i].iov_base, NULL);
		if (status == CSM_DP_TX_BUF_STATUS_TX_ERR ||
				status == CSM_DP_TX_BUF_STATUS_TX_ERR_BUSY)
			dp_data->stats._num_tx_err++;
		else if (status == CSM_DP_TX_BUF_STATUS_TX_IN_PROGRESS)
			dp_data->stats._num_tx_in_prog++;
		else if (status == CSM_DP_TX_BUF_STATUS_TX_OK ||
			status == CSM_DP_TX_BUF_STATUS_TX_OK_BUSY)
			dp_data->stats._num_tx_ok++;
		else
			dp_data->stats._num_tx_others++;
	}
	return 0;
}

static void *__tx_main(void *arg)
{
	struct csm_dp_app_data *dp_data = (struct csm_dp_app_data *)arg;
	int ret;
	uint16_t dp_handle = csm_dp_get_handle(dp_data->fd);
	struct csm_dp_ioctl_getstats driver_stats = { 0 };
	struct timespec intval = {
		(long)cmdline_option.tx_intval_us / 1000000,
		(long)(cmdline_option.tx_intval_us * 1000) % 1000000000
	};

	if (dp_handle == INVALID_HANDLE)
		return NULL;

	unsigned int bus = csm_dp_get_bus_index(dp_handle);
	unsigned int vf = csm_dp_get_vf_index(dp_handle);

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return NULL;

	if (cmdline_option.tx_affinity) {
		ret = thread_set_affinity(pthread_self(), cmdline_option.tx_affinity++);
		if (ret) {
			printf("Set TX Thread affinity 0x%x failed\n", cmdline_option.tx_affinity - 1);
			return NULL;
		}
		printf("TX_%s_%u_%u Thread assigned to CPU %d affinity\n",
			(dp_data->mode == CSM_DP_CH_DATA) ? "DATA" : "CONTROL", bus, vf,
			thread_get_affinity(pthread_self()));
	}
	else {
		ret = thread_set_affinity(pthread_self(), dp_data->tx_affinity);
		if (ret) {
			printf("Set TX Thread affinity 0x%x failed\n", dp_data->tx_affinity);
			return NULL;
		}
		printf("TX_%s_%u_%u Thread assigned to CPU %d affinity\n",
			(dp_data->mode == CSM_DP_CH_DATA) ? "DATA" : "CONTROL", bus, vf,
			thread_get_affinity(pthread_self()));
	}

	/* If packet length is less than threshold, no scatter gather */
	if (cmdline_option.tx_sg &&
			cmdline_option.tx_length <
				(sizeof(struct dp_ping_pkt_hdr) *
					CSM_DP_MAX_SG_IOV_SIZE))
		cmdline_option.tx_sg = false;

	driver_stats.ch = dp_data->mode ? CSM_DP_CH_DATA : CSM_DP_CH_CONTROL;
	ret = csm_dp_get_stats(dp_handle, &driver_stats);
	if (ret)
		/* continue without driver stats */
		printf("warning: csm_dp_get_stats failed %d\n", ret);
	else
		dp_data->stats.last_driver_stats_tx_acked = driver_stats.tx_acked;

	while (1) {
		struct iovec iov[CSM_DP_MAX_IOV_SIZE];
		unsigned int iohandle[CSM_DP_MAX_IOV_SIZE];
		unsigned int n;
		enum csm_dp_channel ch = dp_data->mode ? CSM_DP_CH_DATA : CSM_DP_CH_CONTROL;
		unsigned int flags = 0;

		if (cmdline_option.tx_count) {
			if (cmdline_option.tx_sg)
				n = 1;
			else  {
				n = cmdline_option.tx_count - dp_data->stats.__ping_count;
				if (n > cmdline_option.tx_bundle)
					n = cmdline_option.tx_bundle;
			}
		} else {
			if (cmdline_option.tx_sg)
				n = 1;
			else
				n = cmdline_option.tx_bundle;
		}

		if (__create_ping_pkt(dp_handle, iov, n, iohandle, dp_data))
			break;

		if (cmdline_option.tx_sg)
			flags |= CSM_DP_TX_FLAG_SG;
		if (cmdline_option.tx_mirror)
			flags |= CSM_DP_TX_FLAG_MIRROR;

		if (cmdline_option.tx_sg)
			ret = csm_dp_send(dp_handle, ch, iov, CSM_DP_MAX_SG_IOV_SIZE, flags);
		else
			ret = csm_dp_send(dp_handle, ch, iov, n, flags);

		if (ret >= 0)
			dp_data->stats._num_tx += n;
		else
			dp_data->stats._num_tx_drop += n;

		dp_data->stats.__ping_count += n;
		if (cmdline_option.tx_intval_us)
			nanosleep(&intval, NULL);
		__free_ping_pkt(dp_handle, iov,
			(cmdline_option.tx_sg) ? CSM_DP_MAX_SG_IOV_SIZE : n,
			iohandle, dp_data);
		if (cmdline_option.tx_count &&
				dp_data->stats.__ping_count >= cmdline_option.tx_count)
			break;
	}
	/* sleep 1 second for loopback packets to come back, before declare done */
	sleep(1);
	dp_data->__done = true;
	return NULL;
}

static int __rx_init(struct csm_dp_app_data *dp_data, enum csm_dp_channel mode)
{
	int ret;
	char thread_name[30] = {0x00};
	uint16_t handle = csm_dp_get_handle(dp_data->fd);
	if (handle == INVALID_HANDLE)
		return -EINVAL;

	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);

	if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
		return -EINVAL;

	if (mode == CSM_DP_CH_DATA) {
		dp_data->rx_affinity = rx_affinity++;
		ret = pthread_create(&dp_data->tid[RX_THREAD], NULL, __rx_poll_main, (void *)dp_data);
		if (!ret) {
			snprintf(thread_name, sizeof(thread_name), "RX_DATA_%u_%u",
				bus, vf);
			pthread_setname_np(dp_data->tid[RX_THREAD], thread_name);
		}
	}
	else {
		dp_data->rx_affinity = rx_affinity++;
		ret = pthread_create(&dp_data->tid[RX_THREAD], NULL, __rx_main, (void *)dp_data);
		if (!ret) {
			snprintf(thread_name, sizeof(thread_name), "RX_CONTROL_%u_%u",
				bus, vf);
			pthread_setname_np(dp_data->tid[RX_THREAD], thread_name);
		}
	}

	return ret;
}

static int __tx_init(struct csm_dp_app_data *dp_data, enum csm_dp_channel mode)
{
	int ret;
	char thread_name[30] = {0x00};
	uint16_t handle = csm_dp_get_handle(dp_data->fd);
        if (handle == INVALID_HANDLE)
                return -EINVAL;

        unsigned int bus = csm_dp_get_bus_index(handle);
        unsigned int vf = csm_dp_get_vf_index(handle);

        if (bus >= CSM_DP_MAX_BUS || vf >= CSM_DP_MAX_VF)
                return -EINVAL;

	if (mode == CSM_DP_CH_DATA) {
		dp_data->tx_affinity = tx_affinity++;
		ret = pthread_create(&dp_data->tid[TX_THREAD], NULL, __tx_main, (void *)dp_data);
		if (!ret) {
			snprintf(thread_name, sizeof(thread_name), "TX_DATA_%u_%u",
				bus, vf);
			pthread_setname_np(dp_data->tid[TX_THREAD], thread_name);
		}
	}
	else {
		dp_data->tx_affinity = tx_affinity++;
		ret = pthread_create(&dp_data->tid[TX_THREAD], NULL, __tx_main, (void *)dp_data);
		if (!ret) {
			snprintf(thread_name, sizeof(thread_name), "TX_CONTROL_%u_%u",
				bus, vf);
			pthread_setname_np(dp_data->tid[TX_THREAD], thread_name);
		}
	}

	return ret;
}

static int __result_init(void)
{
	int ret = pthread_create(&result_tid, NULL, __result_main, NULL);

	if (!ret)
		pthread_setname_np(result_tid, "RESULT_THREAD");

	return ret;
}

static int create_dp_ping_instance(uint16_t handle, enum csm_dp_channel mode)
{
	int fd, i, j;
	unsigned int bus = csm_dp_get_bus_index(handle);
	unsigned int vf = csm_dp_get_vf_index(handle);
	struct csm_dp_app_data (*dp_data)[CSM_DP_MAX_VF] = (mode == CSM_DP_CH_CONTROL) ? dp_app_control : dp_app_data;
	bool *init = (mode == CSM_DP_CH_CONTROL) ? &app_initialized_control : &app_initialized_data;

	if(*init == false) {
		for (i = 0; i < CSM_DP_MAX_BUS; i++){
			for (j = 0; j < CSM_DP_MAX_VF; j++)
				dp_data[i][j].fd = -1;
		}
		*init = true;
	}

	fd = __csm_init(handle, mode);
	if (fd < 0) return -1;

	dp_data[bus][vf].fd = fd;
	dp_data[bus][vf].mode = mode;
	dp_data[bus][vf].stats.first_result = true;
	__csm_rx_drain(handle, mode);

	if (__ping_result_fifo_init(&dp_data[bus][vf].__result_fifo,
		cmdline_option.result_fifo_depth)) return -1;

	if (__rx_init(&dp_data[bus][vf], mode)) {
		printf("rx_init failed\n");
		return -1;
	}
	if (__tx_init(&dp_data[bus][vf], mode)) {
		pthread_cancel(dp_data[bus][vf].tid[RX_THREAD]);
		__ping_result_fifo_cleanup(&dp_data[bus][vf].__result_fifo);
		printf("tx_init failed\n");
		return -1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	int ret;
	unsigned int i;
	unsigned int bus, vf;
	uint16_t handle;
	void *res;
	__parse_cmdline(argc, argv);

	bus = cmdline_option.bus_num;
	vf = cmdline_option.vf_num;

	for (i = 0; i < cmdline_option.num_vf; i++) {
		if (cmdline_option.num_vf > 1)
			vf = i;

		handle = CREATE_HANDLE(bus, vf);

		if (cmdline_option.poll_mode == CSM_DP_CH_CONTROL || cmdline_option.run_both) {
			ret = create_dp_ping_instance(handle, CSM_DP_CH_CONTROL);
			if (ret < 0) {
				printf("dp_ping_instance creation failed ret: %d\n", ret);
				return ret;
			}
			printf("\n\n");
		}

		if (cmdline_option.poll_mode == CSM_DP_CH_DATA || cmdline_option.run_both) {
			ret = create_dp_ping_instance(handle, CSM_DP_CH_DATA);
			if (ret < 0) {
				printf("dp_ping_instance creation failed ret: %d\n", ret);
				return ret;
			}
			printf("\n\n");
		}
	}

	if (__result_init()) {
		printf("result_init failed\n");
		return -1;
	}

	pthread_join(result_tid, &res);
	for (i = 0; i < cmdline_option.num_vf; i++) {
		if (cmdline_option.num_vf > 1)
			vf = i;

		handle = CREATE_HANDLE(bus, vf);

		if (cmdline_option.poll_mode == CSM_DP_CH_CONTROL || cmdline_option.run_both) {
			struct csm_dp_app_data (*dp_data)[CSM_DP_MAX_VF] = dp_app_control;
			pthread_join(dp_data[bus][vf].tid[RX_THREAD], &res);
			pthread_join(dp_data[bus][vf].tid[TX_THREAD], &res);
			__ping_result_fifo_cleanup(&dp_data[bus][vf].__result_fifo);
			__csm_cleanup(handle);
		}

		if (cmdline_option.poll_mode == CSM_DP_CH_DATA || cmdline_option.run_both) {
			struct csm_dp_app_data (*dp_data)[CSM_DP_MAX_VF] = dp_app_data;
			pthread_join(dp_data[bus][vf].tid[RX_THREAD], &res);
			pthread_join(dp_data[bus][vf].tid[TX_THREAD], &res);
			__ping_result_fifo_cleanup(&dp_data[bus][vf].__result_fifo);
			__csm_cleanup(handle);
		}
	}
	return 0;
}
