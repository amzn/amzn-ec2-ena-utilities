// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#include <getopt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_icmp.h>
#include <rte_version.h>

#define PORT_ID 0

#define BUF_IDS 100

#define PKT_SIZE_MIN 64
#define PKT_SIZE_MAX ETHER_MAX_JUMBO_FRAME_LEN
#define PKT_SIZE_DEFAULT 64

#define ITERATIONS_MIN 1
#define ITERATIONS_MAX 10000000
#define ITERATIONS_DEFAULT 1000

#define NUM_MBUFS 16383
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define BP_IP_VER_IHL 0x45
#define BP_IP_TTL 64

#define TIMEOUT 100000

#if RTE_VERSION < RTE_VERSION_NUM(18, 8, 0, 0)
#define RING_SIZE 1024
#endif

static struct ether_addr source_mac, destination_mac;
static uint32_t source_ip, destination_ip;
static uint32_t pkt_size = PKT_SIZE_DEFAULT;
static uint32_t iterations = ITERATIONS_DEFAULT;
static uint32_t verbose = 0;
static uint16_t q = 0;

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = ETHER_MAX_JUMBO_FRAME_LEN,
#if RTE_VERSION < RTE_VERSION_NUM(18, 8, 0, 0)
		.jumbo_frame = 1,
		.ignore_offload_bitfield = 1,
#endif
	},
};

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	uint16_t rx_rings, tx_rings;
	uint16_t nb_rxd, nb_txd;
	int retval;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	rte_eth_dev_info_get(port, &dev_info);

#if RTE_VERSION < RTE_VERSION_NUM(18, 8, 0, 0)
	nb_rxd = RING_SIZE;
	nb_txd = RING_SIZE;
#else
	nb_rxd = dev_info.rx_desc_lim.nb_max;
	nb_txd = dev_info.tx_desc_lim.nb_max;
#endif

	port_conf.txmode.offloads |= (dev_info.tx_offload_capa &
				      DEV_TX_OFFLOAD_MBUF_FAST_FREE);

	rx_rings = dev_info.max_rx_queues;
	tx_rings = dev_info.max_tx_queues;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
	    rte_eth_dev_socket_id(port), NULL, mbuf_pool);
	if (retval < 0)
		return retval;

	txconf = dev_info.default_txconf;
#if RTE_VERSION < RTE_VERSION_NUM(18, 8, 0, 0)
	txconf.txq_flags = ETH_TXQ_FLAGS_IGNORE;
#endif
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	retval = rte_eth_tx_queue_setup(port, q, nb_txd,
	    rte_eth_dev_socket_id(port), &txconf);
	if (retval < 0)
		return retval;

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	rte_eth_macaddr_get(port, &source_mac);
	printf("Port %u MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
			   ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 "\n",
			port,
			source_mac.addr_bytes[0], source_mac.addr_bytes[1],
			source_mac.addr_bytes[2], source_mac.addr_bytes[3],
			source_mac.addr_bytes[4], source_mac.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}

static struct rte_mbuf*
create_mbuf(struct rte_mempool *mp, uint16_t size, uint16_t pkt_id)
{
	struct rte_mbuf* m;
	struct ether_hdr *eth_h;
	struct ipv4_hdr *ip_h;
	struct icmp_hdr *icmp_h;
	uint8_t *data;
	uint16_t ip_len, data_len, cs;

	m = rte_pktmbuf_alloc(mp);
	if (m == NULL) {
		printf("Cannot alloc mbuf\n");
		return NULL;
	}
	rte_prefetch0(rte_pktmbuf_mtod(m, void *));

	/* Create Ethernet header */
	eth_h = (struct ether_hdr *)rte_pktmbuf_append(m, ETHER_HDR_LEN);
	eth_h->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	ether_addr_copy(&source_mac, &eth_h->s_addr);
	ether_addr_copy(&destination_mac, &eth_h->d_addr);

	/* Create IPv4 header */
	ip_h = (struct ipv4_hdr *)rte_pktmbuf_append(m, sizeof(struct ipv4_hdr));
	ip_h->version_ihl = BP_IP_VER_IHL;
	ip_h->type_of_service = 0;
	ip_len = size - ETHER_HDR_LEN - ETHER_CRC_LEN;
	ip_h->total_length = rte_cpu_to_be_16(ip_len);
	ip_h->fragment_offset = 0;
	ip_h->time_to_live = BP_IP_TTL;
	ip_h->next_proto_id = 0x01; /* ICMP */
	ip_h->src_addr = rte_cpu_to_be_32(source_ip);
	ip_h->dst_addr = rte_cpu_to_be_32(destination_ip);
	ip_h->hdr_checksum = 0;
	ip_h->hdr_checksum = rte_ipv4_cksum(ip_h);

	/* Create ICMP header */
	icmp_h = (struct icmp_hdr *)rte_pktmbuf_append(m, sizeof(struct icmp_hdr));
	icmp_h->icmp_type = IP_ICMP_ECHO_REQUEST;
	icmp_h->icmp_ident = pkt_id;
	icmp_h->icmp_code = 0;
	icmp_h->icmp_cksum = 0;

	/* Data */
	data_len = ip_len - sizeof(struct ipv4_hdr) - sizeof(struct icmp_hdr);
	data = (uint8_t *)rte_pktmbuf_append(m, data_len);
	memset(data, 0, data_len);

	cs = rte_raw_cksum(icmp_h, ip_len - sizeof(struct ipv4_hdr));
	cs = (cs == 0xffff) ? cs : (uint16_t)~cs;
	icmp_h->icmp_cksum = cs;

	return m;
}

/**
 * Validate mbufs by checking if it comes from the right source (as it is
 * possible that we will receive packet from another host) by using MAC.
 * Then, check if ICMP ID is the same as it it supposed to be.
 */
static inline int8_t
validate(struct rte_mbuf *mbuf[], uint16_t n, uint16_t pkt_id)
{
	struct ether_hdr *eth;
	struct icmp_hdr *icmp;
	uint16_t i;
	int8_t ret = -1;

	for (i = 0; i < n; i++) {
		eth = rte_pktmbuf_mtod(mbuf[i], struct ether_hdr*);
		if (!is_same_ether_addr(&eth->s_addr, &destination_mac)) {
			continue;
		}

		icmp = rte_pktmbuf_mtod_offset(mbuf[i], struct icmp_hdr*,
			(sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr)));
		if (icmp->icmp_ident != pkt_id) {
			continue;
		}

		ret = 0;
		break;
	}
	return ret;
}

static inline int
compare_u32(const void *a, const void *b)
{
	/*
	 * NOTE: memcmp can be used as long as unsigned values are being compared.
	 * It gives wrong results for signed numbers.
	 */
	return memcmp(a, b, sizeof(uint32_t));
}

static inline uint32_t
percentile(uint32_t *data, uint32_t len, uint32_t pc)
{
	return data[((len-1)*pc)/1000];
}

static __attribute__((noreturn)) void
lcore_main(struct rte_mempool *mbuf_pool)
{
	struct rte_mbuf *buf_to_send[BUF_IDS];
	struct rte_mbuf *bufs[BURST_SIZE];
	struct rte_mbuf *m[1];
	uint32_t *times;
	uint64_t tsc_hz = rte_get_tsc_hz();
	uint64_t start, end, timeout, end_timeout;
	uint32_t i;
	uint32_t timeout_pkt = 0;
	uint16_t buf;
	uint16_t nb_tx, nb_rx = 0;

	timeout = TIMEOUT * tsc_hz / 1000000ul;

	times = rte_zmalloc(NULL, sizeof(uint32_t) * iterations, 0);
	if (times == NULL) {
		rte_exit(-1, "cannot allocate memory\n");
	}

	for (i = 0; i < BUF_IDS; i++) {
		buf_to_send[i] = create_mbuf(mbuf_pool, pkt_size, i);
	}
	m[0] = rte_pktmbuf_alloc(mbuf_pool);
	rte_pktmbuf_attach(m[0], buf_to_send[0]);

	for (i=0; i < iterations; i++) {
		start = rte_get_tsc_cycles();

		nb_tx = rte_eth_tx_burst(PORT_ID, q, m, 1);
		if (unlikely(nb_tx != 1)) {
			rte_pktmbuf_free(m[0]);
			rte_exit(-1, "send failed\n");
		}

		end_timeout = start + timeout;

		/* Create next mbuf */
		m[0] = rte_pktmbuf_alloc(mbuf_pool);
		rte_pktmbuf_attach(m[0], buf_to_send[(i+1) % BUF_IDS]);

		do {
			nb_rx = rte_eth_rx_burst(PORT_ID, q, bufs, BURST_SIZE);

			if (end_timeout < rte_get_tsc_cycles()) {
				printf("RX burst timed out\n");
				timeout_pkt++;
				break;
			}
		} while ((nb_rx == 0) || (validate(bufs, nb_rx, i % BUF_IDS) == -1));

		end =  rte_get_tsc_cycles();
		end -= start;
		end *= 1000000;
		end /= tsc_hz;
		times[i] = (uint32_t)end;

		for (buf = 0; buf < nb_rx; buf++) {
			rte_pktmbuf_free(bufs[buf]);
		}
	}

	if (verbose) {
		for (i=0; i < iterations; i++) {
			printf("%d\t\n", times[i]);
		}
	}

	qsort(times, iterations, sizeof(uint32_t), compare_u32);
	printf("P50 %10d\n", percentile(times, iterations-timeout_pkt, 500));
	printf("P90 %10d\n", percentile(times, iterations-timeout_pkt, 900));
	printf("P99 %10d\n", percentile(times, iterations-timeout_pkt, 990));
	printf("Timeouts %5d\n", timeout_pkt);

	if (times != NULL) {
		rte_free(times);
	}

	rte_exit(0, "Test ended\n");
}

/* display usage */
static void
usage(const char *prgname)
{

	printf("%s [EAL options] -- \n"
	       "  -m destination MAC address\n"
	       "  -i source IPv4 address\n"
	       "  -j destination IPv4 address\n"
	       "  -s packet size\n"
	       "  -b iterations\n"
	       "  -q queue id\n"
	       "  -v verbose\n",
	       prgname);
}

static const char short_options[] =
	"m:"	/* destination MAC address */
	"i:"	/* source IPv4 address */
	"j:"	/* destination IPv4 address */
	"s:"	/* pkt size */
	"b:"	/* iterations */
	"q:"	/* queue ID */
	"v"	/* verbose */
;

static const struct option lgopts[] = {
	{NULL, 0, 0, 0},
};

static int
parse_ip(const char *q_arg, uint32_t *ip)
{
	int rc;
	uint32_t t_ip[4];

	if (q_arg == NULL)
		return -1;

	rc = sscanf(q_arg, "%u.%u.%u.%u",
		    &t_ip[0], &t_ip[1], &t_ip[2], &t_ip[3]);
	if (rc != 4)
		return -1;

	*ip = IPv4(t_ip[0], t_ip[1], t_ip[2], t_ip[3]);
	return 0;
}

static int
parse_mac(const char *q_arg, struct ether_addr *mac)
{
	int rc;

	if (q_arg == NULL)
		return -1;

	rc = sscanf(q_arg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		    &mac->addr_bytes[0], (&mac->addr_bytes[1]),
		    &mac->addr_bytes[2], (&mac->addr_bytes[3]),
		    &mac->addr_bytes[4], (&mac->addr_bytes[5]));

	if (rc != 6)
		return -1;
	return 0;
}

static int
parse_num(const char *q_arg, uint32_t* size, uint32_t min, uint32_t max)
{
	int rc;

	rc = sscanf(q_arg, "%u", size);
	if (rc != 1) {
		return -1;
	}

	if (*size < min || *size > max) {
		return -1;
	}

	return 0;
}

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	uint32_t num;

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, short_options,
				  lgopts, &option_index)) != EOF) {
		switch (opt) {
		case 'm':
			if (parse_mac(optarg, &destination_mac) != 0) {
				printf("invalid destination MAC\n");
				return -1;
			}
		break;
		case 'i':
			if (parse_ip(optarg, &source_ip) != 0) {
				printf("invalid source IP\n");
				return -1;
			}
		break;
		case 'j':
			if (parse_ip(optarg, &destination_ip) != 0) {
				printf("invalid destination IP\n");
				return -1;
			}
		break;
		case 's':
			if (parse_num(optarg, &pkt_size, PKT_SIZE_MIN, PKT_SIZE_MAX) != 0) {
				printf("invalid packet size\n");
				return -1;
			}
		break;
		case 'b':
			if (parse_num(optarg, &iterations, ITERATIONS_MIN, ITERATIONS_MAX) != 0) {
				printf("invalid number of iterations\n");
				return -1;
			}
		break;
		case 'q':
			if (parse_num(optarg, &num, 0, 31) != 0) {
				printf("invalid queue id\n");
				return -1;
			}
			q = num;
		break;
		case 'v':
			verbose = 1;
		break;
		default:
			usage(prgname);
			return -1;
		}
	}

	if (optind >= 0) {
		argv[optind-1] = prgname;
	}

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	/* parse application arguments (after the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Invalid console arguments\n");
	}
#if RTE_VERSION > RTE_VERSION_NUM(18, 4, 0, 0)
	nb_ports = rte_eth_dev_count_avail();
#else
	nb_ports = rte_eth_dev_count();
#endif
	if (nb_ports < 1)
		rte_exit(EXIT_FAILURE, "Error: no port\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, ETHER_MAX_JUMBO_FRAME_LEN, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize all ports. */
	if (port_init(PORT_ID, mbuf_pool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
			 PORT_ID);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the master core only. */
	lcore_main(mbuf_pool);

	return 0;
}
