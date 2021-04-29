// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#include <getopt.h>
#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_icmp.h>
#include <rte_version.h>

#define PORT_ID 0

#define NUM_MBUFS 16383
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define RING_SIZE 1024

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = ETHER_MAX_JUMBO_FRAME_LEN,
#if RTE_VERSION < RTE_VERSION_NUM(18, 8, 0, 0)
		.jumbo_frame = 1,
		.ignore_offload_bitfield = 1,
#endif
	},
};

uint16_t q = 0;

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
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
			   ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}

static inline void
swap_mac_ip(struct rte_mbuf *mbuf[], uint16_t n)
{
	struct ether_hdr *eth;
	struct ipv4_hdr *ip;
	struct icmp_hdr *icmp;
	struct ether_addr eth_addr;
	uint32_t ip_addr;
	uint16_t i;
	uint16_t cs;

	for (i = 0; i < n; i++) {
		eth = rte_pktmbuf_mtod(mbuf[i], struct ether_hdr*);
		if (rte_be_to_cpu_16(eth->ether_type) != ETHER_TYPE_IPv4)
			continue;

		ip = (struct ipv4_hdr*) &eth[1];
		if (ip->next_proto_id != 0x01)
			continue;

		// swap MAC
		ether_addr_copy(&eth->s_addr, &eth_addr);
		ether_addr_copy(&eth->d_addr, &eth->s_addr);
		ether_addr_copy(&eth_addr, &eth->d_addr);

		// swap IP
		ip_addr = ip->src_addr;
		ip->src_addr = ip->dst_addr;
		ip->dst_addr = ip_addr;

		icmp = (struct icmp_hdr*) &ip[1];
		icmp->icmp_type = IP_ICMP_ECHO_REPLY;
		cs = ~icmp->icmp_cksum & 0xffff;
		cs += ~htons(IP_ICMP_ECHO_REQUEST << 8) & 0xffff;
		cs += htons(IP_ICMP_ECHO_REPLY << 8);
		cs = (cs & 0xffff) + (cs >> 16);
		cs = (cs & 0xffff) + (cs >> 16);
		icmp->icmp_cksum = ~cs;
	}
}

static __attribute__((noreturn)) void
lcore_main(uint16_t q)
{
	struct rte_mbuf *bufs[BURST_SIZE];
	uint16_t nb_rx, nb_tx, buf;

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

	/*
	 * In each iteration of the loop, the amount of `nb_rx` (up to
	 * `BURST_SIZE`) packets is received in one
	 * shot, processed in a simple way and transmited again (ideally all of the
	 * packets). The processing is done by the `swap_mac_ip` routine, which:
	 *   - changes the packet type field in the ICMP header (from
	 *   `IP_ICMP_ECHO_REQUEST` to `IP_ICMP_ECHO_REPLY`)
	 *   - MAC and IP addresses of the sender and receiver are swapped so that
	 *   the packet will really be transmitted back to its origin
	 *
	 * From the memory allocation standpoint, the `rte_eth_rx_burst` is
	 * responsible for acquiring `rte_mbuf` instances (from a preallocated
	 * memory pool associated with the device) and storing respective pointers
	 * in the `bufs` array. Symmetrically, the `rte_eth_tx_burst` consumes the
	 * buffers and handles their release (that is marking them as free in the
	 * mempool). Only if, for some reason, not all of received packets are
	 * transmitted back in one shot (that is `nb_tx < nb_rx`) the outstanding
	 * buffers must be released explicitly. Such packets won't return to their
	 * origin as expected though.
	 *
	 * The loop runs forever, until the application is killed.
	 */
	for (;;) {
		nb_rx = rte_eth_rx_burst(PORT_ID, q, bufs, BURST_SIZE);
		if (unlikely(nb_rx == 0))
			continue;

		swap_mac_ip(bufs, nb_rx);
		nb_tx = rte_eth_tx_burst(PORT_ID, q, bufs, nb_rx);

		/* Free any unsent packets. */
		if (unlikely(nb_tx < nb_rx)) {
			for (buf = nb_tx; buf < nb_rx; buf++)
				rte_pktmbuf_free(bufs[buf]);
		}
	}
}

static int
parse_num(const char *q_arg, uint16_t* size, uint32_t min, uint32_t max)
{
        int rc;

        rc = sscanf(q_arg, "%hu", size);
        if (rc != 1) {
                return -1;
        }

        if (*size < min || *size > max) {
                return -1;
        }

        return 0;
}

static const char short_options[] =
        "q:"    /* queue ID */
;

static const struct option lgopts[] = {
        {NULL, 0, 0, 0},
};

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, short_options,
		lgopts, &option_index)) != EOF) {
		switch (opt) {
			case 'q':
			if (parse_num(optarg, &q, 0, 31) != 0) {
				printf("invalid queue id\n");
				return -1;
			}
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
		rte_exit(EXIT_FAILURE, "Error: no port.\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, ETHER_MAX_JUMBO_FRAME_LEN, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize port. */
	if (port_init(PORT_ID, mbuf_pool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", PORT_ID);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the master core only. */
	lcore_main(q);

	return 0;
}
