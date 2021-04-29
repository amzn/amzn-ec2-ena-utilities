# BSD LICENSE
#
# Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
 DPDK Test suite.

 Test ENA
 Based on Test Shutdown API Feature.

 Changes made to the original file:
   * Rename class name to TestENA
   * Add custom constants
   * Update documentation and port on get_interface() call in set_up_all()
     method
   * Initialize all variables and extra objects needed by the test in
     set_up_all() method
   * Remove methods:
     - get_stats
     - check_forwarding
     - send_packet
     - test_stop_restart
     - test_set_promiscuousmode
     - test_reset_queues
     - test_reconfigure_ports
     - test_reset_queues
     - test_change_linkspeed
     - test_enable_disablejumbo
     - test_enable_disablerss
     - test_change_numberrxdtxd
     - test_change_numberrxdtxdaftercycle
     - test_change_thresholds
     - test_stress_test
     - test_link_stats
   * Modify method check_ports(), to do not check for fm10k driver and fix
     error log about link status (opposite condition)
   * Add implementation for the set_up() method
   * Add methods:
     - restart_ports
     - test_perf_latency
     - get_queue_stats
     - __find_active_queue
     - __detect_one_flow
     - generate_flows_list
     - create_pktgen_flows
     - __test_perf_bw
     - get_flows_filename
     - save_flows
     - load_flows_from_file
     - test_perf_bw
     - init_pktgen_instances
     - mono_traffic
     - bi_traffic
     - parse_stress
     - generate_pcap_execute
     - generate_pcap
     - pcap_per_queue
     - generate_mono_traffic
     - generate_bi_traffic
     - validate
     - get_queues_from_pcap
     - test_perf_pcap
     - add_unit
     - find_existing_pcaps
     - generate_pcap_string
     - get_pcap_dirnm
     - detect_best_rates
  * Rework tear_down() and tear_down_all() methods to perform additional cleanup
    required by the test suite
"""
from __future__ import division
import time
import re
import json
import os
import ast
from test_case import TestCase
from pmd_output import PmdOutput
from settings import HEADER_SIZE, PROTOCOL_PACKET_SIZE
from settings import AUTO_QUEUE_TX_RATE, DEFAULT_QUEUE_TX_RATE
from settings import PCAP_DIR, PCAP_TESTER, PCAP_DUT, PCAP_FILENAME_SUFFIX
from etgen import SoftwarePacketGenerator, LatencyGenerator
from project_dpdk import copy_pcap
from exception import FlowDetectionException
from utils import gen_pcap_fpath


class TestENA(TestCase):
    HOST_PROMPT = "# "
    TESTPMD_PROMPT = "testpmd> "
    TESTPMD_FLAGS = ["--disable-hw-vlan"]
    SUPORTED_PKT_TYPES = ["tcp", "udp"]
    MAX_QUEUE_DEFAULT = 8
    MAX_QUEUE_N_TYPE = 32
    MIN_QUEUE = 1
    MIN_PKT_SIZE = 64
    MAX_PKT_SIZE = 9000
    QUEUES_STATS = "ethtool -S {} | egrep queue_[0-9]+_rx_cnt |"

    def set_up_all(self):
        """
        Run at the start of each test suite:
         * check number of ports,
         * config MTU on testers interfaces.
        """
        ports = self.dut.get_ports()
        self.verify(len(ports) >= 1, "Insufficient number of ports.")
        self.ports = ports[:1]
        self.ports_socket = self.dut.get_numa_id(self.ports[0])

        for port in self.ports:
           self.tester.send_expect("ifconfig %s mtu %s" % (
                self.tester.get_interface(self.tester.get_local_port(port)), 9001), "# ")

        self.pmdout = PmdOutput(self.dut)

        self.core_list = [0, 1]

        self.port_dut = self.ports[0]
        self.port_tester = self.tester.get_local_port(self.port_dut)

        self.tester.used_port = self.port_tester
        self.dut.used_port = self.port_dut

        self.smac = self.tester.get_mac_address(self.port_tester)
        self.dmac = self.dut.get_mac_address(self.port_dut)
        self.sip = self.tester.get_ipv4_address(self.port_tester)
        self.dip = self.dut.get_ipv4_address(self.port_dut)
        self.iface_tester = self.tester.get_interface(self.port_tester)

        dut_q_b = self.get_queue_stats(self.dut)
        tester_q_b = self.get_queue_stats(self.tester)
        self.dut.send_expect("ping {} -f -c 1000".format(self.sip), self.HOST_PROMPT)
        dut_q_e = self.get_queue_stats(self.dut)
        tester_q_e = self.get_queue_stats(self.tester)
        dut_stats = [e - b for e, b in zip(dut_q_e, dut_q_b)]
        tester_stats = [e - b for e, b in zip(tester_q_e, tester_q_b)]
        self.icmp_dut_q = dut_stats.index(max(dut_stats))
        self.icmp_tester_q = tester_stats.index(max(tester_stats))

        # Check which flags are supported by current testpmd version
        v1, v2, v3 = self.pmdout.testpmd_dpdk_ver()
        self.testpmd_flags = ""
        if v1 < 18 or (v1 == 18 and v2 < 8):
            TestENA.TESTPMD_FLAGS.append("--disable-crc-strip")

        help = self.pmdout.testpmd_help()
        for flag in self.TESTPMD_FLAGS:
            if flag in help:
                self.testpmd_flags += flag + " "
        self.pmd_on = False

        self.pktgen_tester = SoftwarePacketGenerator(self.tester)
        self.pktgen_dut = SoftwarePacketGenerator(self.dut)

        self.latency_send = LatencyGenerator(self.tester, [self.port_tester], self.icmp_tester_q)
        self.latency_echo = LatencyGenerator(self.dut, [self.port_dut], self.icmp_dut_q)
        self.test_configs_copy = self.test_configs

        dut_ncpu = self.dut.get_cpu_number()
        tester_ncpu = self.tester.get_cpu_number()

        self.max_queue = min(self.dut.max_io_queue, self.tester.max_io_queue,
                             dut_ncpu - SoftwarePacketGenerator.NOT_USED_CPUS,
                             tester_ncpu - SoftwarePacketGenerator.NOT_USED_CPUS)

    def check_ports(self, status=True):
        """
        Check link status of the ports.
        """

        for port in self.ports:
            out = self.tester.send_expect(
                "ethtool %s" % self.tester.get_interface(self.tester.get_local_port(port)), "# ")
            if status:
                self.verify("Link detected: yes" in out, "Link status correct")
            else:
                self.verify("Link detected: no" in out, "Wrong link status")

    def set_up(self):
        """
        Run before each test case.
        """
        self.dut.to_base_dir()
        self.tester.to_base_dir()

    def restart_ports(self, command):
        self.dut.send_expect("stop", self.TESTPMD_PROMPT)
        self.dut.send_expect("port stop all", self.TESTPMD_PROMPT)
        self.dut.send_expect(command, self.TESTPMD_PROMPT)
        out = self.dut.send_expect("port start all", self.TESTPMD_PROMPT)
        self.dut.send_expect("start", self.TESTPMD_PROMPT)
        return out

    def test_perf_latency(self):
        pkt_sizes = [64, 1500, 9000]
        counts = 100000
        self.result_table_create(['size', 'p50, us', 'p90, us', 'p99, us', 'pkt loss, %'])
        loses = 0

        self.latency_echo.start_echo()

        for pkt_size in pkt_sizes:
            stats = self.latency_send.start_test(self.dmac, self.sip, self.dip, pkt_size, counts)
            self.result_table_add([pkt_size, stats[0], stats[1], stats[2], stats[3]])
            loses += stats[3]

        self.latency_echo.stop_echo()
        self.latency_send.end()
        self.latency_echo.end()

        self.result_table_print()
        self.verify(loses == 0, "Some pings lost")

    def get_queue_stats(self, host):
        iface = host.ports_info[host.used_port]['intf']
        command = self.QUEUES_STATS.format(iface) + \
            " awk -F ' ' ' {{print $2}}'"
        out = host.send_expect(command, self.HOST_PROMPT)
        try:
            stats = out.split("\n")
            stats = [int(s) for s in stats]
        except:
            assert 0, "Cannot parse queue stats: {}, out: {}".\
                format(command, out)

        return stats

    # The `n_min > 0` is used only in one corner case, when ZERO_HITS were
    # detected at first turn and statistics are read again. Then, if no
    # probing packets are received, few ARP packets could mislead the
    # measurement and suggest that a wrong queue belongs to the flow. An
    # arbitrarily large `n_min protects against that.
    def __find_active_queue(self, rxq_stats, n_min=0):
        found = False

        for (qid, qstats) in rxq_stats.items():
            pkts_cnt = qstats["cnt"]
            if pkts_cnt > n_min:
                if found:
                    raise FlowDetectionException(FlowDetectionException.MULTIPLE_HITS)
                found = True
                out_qid = qid

        if not found:
            # This can possibly happen if statistics are read too quickly.
            raise FlowDetectionException(FlowDetectionException.ZERO_HITS)

        return out_qid


    def __detect_one_flow(self, tx_gen, rx_gen, tx_cmd, ports_pair, send=True):
        tx_crb = tx_gen.host

        if send:
            tx_crb.scapy_send(tx_cmd)

        try:
            (_, rxq_stats) = rx_gen.queue_stats()
            queue_id = self.__find_active_queue(rxq_stats)

        except FlowDetectionException as fde:
            if fde.state == FlowDetectionException.MULTIPLE_HITS:
                self.logger.info("Multiple HITS, retry counter: %s" %
                        self.detect_loop_ttl)
                if self.detect_loop_ttl > 0:
                    # If multiple queues receive packet we cannot tell which one
                    # actually forms a flow. Rarely happens but not an error. Eg.
                    # ARP packets are incoming occasionally and spoil the result.
                    self.detect_loop_ttl -= 1
                    return self.__detect_one_flow(tx_gen, rx_gen, tx_cmd, ports_pair)
                else:
                    assert 0, "Multiple queues receive packets too often." \
                            "Ports: %s" % ports
            elif fde.state == FlowDetectionException.ZERO_HITS:
                self.logger.info("Zero HITS, ttl: %s" %
                        self.detect_loop_ttl)
                if self.detect_loop_ttl > 0:
                    # Do not resend packets, only try to read statistics once
                    # again. Maybe previous probe was done before they arrived.
                    self.detect_loop_ttl -= 1
                    return self.__detect_one_flow(tx_gen, rx_gen, tx_cmd, ports_pair,
                            send=False)
                else:
                    assert 0, "No queues received packets. Ports: %s" % ports_pair
        # All good
        else:
            return queue_id

    def generate_flows_list(self, tx_conf, rx_conf, total_queues, direction, flow_nb):
        # After this function the tx/rx_conf['queue_nb'] will be no higher
        # than `total_queues`. It can be limited by the nb of CPUs on an
        # instance. For `bi` direction it is limited by the half of CPU amount
        # (half for Tx, half for Rx). Pktgen is launched in a passive mode just
        # to observe the association between flows and queues.
        rx_conf['tx_rates'] = DEFAULT_QUEUE_TX_RATE
        f_pcap = rx_conf['f_pcap']
        # Rx pktgen instance shouldn't use any pcaps - force it to do so, by
        # setting f_pcap field as None
        rx_conf['f_pcap'] = None
        rx_conf['queue_nb'] = TestENA.init_pktgen_instance(rx_conf)
        time.sleep(2)

        flows = self.create_pktgen_flows(tx_conf, rx_conf, flow_nb)

        tx_host = tx_conf['host']
        rx_gen = rx_conf['pktgen']

        tx_host.send_expect("^C", "")
        tx_host.scapy_exit()
        rx_gen.quit()
        rx_gen.end()

        # Revert the old value f_pcap value
        rx_conf['f_pcap'] = f_pcap

        self.save_flows(flows, tx_host, rx_conf['host'])

        return flows

    # Sends packets from Tx side to consequtive port numbers of Rx side. For
    # each, it observes which queue received the traffic and records that. The
    # goal is to find a set of flows allowing to occupy all queues available on
    # Rx, that is to create the number of `flow_nb` distinctive flows.
    def create_pktgen_flows(self, tx_conf, rx_conf, flow_nb):
        self.detect_loop_ttl = 10                       # chosen arbitrarily
        self.flow_npackets = 100
        port_min = int(self.test_configs['BW_port_min'])
        port_max = int(self.test_configs['BW_port_max'])

        # Instances of SoftwarePacketGenerator
        rx_gen = rx_conf['pktgen']
        tx_gen = tx_conf['pktgen']
        # Instances of DPDKDut/DPDKTester
        rx_host = rx_conf['host']
        tx_host = tx_conf['host']

        # Do not rely on self.max_queues value as it may no longer be valid
        # there. It can be modified if the test case if bidirectional and the
        # instance is lacking CPU's.
        rxq_num = rx_conf['queue_nb']
        q_to_port = [None] * rxq_num
        flows_per_queue = flow_nb // rxq_num
        flows_nb_rest = flow_nb % rxq_num

        assert (port_min + rxq_num - 1) <= port_max, "Port range is too small"

        # Make sure Tx uses standard Linux driver
        tx_gen.end()
        tx_host.logger.info("Pktgen flows creation:")

        tx_iface = tx_host.ports_info[tx_host.used_port]['intf']
        tx_cmd = 'send([IP(dst="{dip}")/' \
          'UDP(sport={{sport}}, dport={{dport}})/' \
          'Raw(load="P" * 100)] * {n}, iface="{iface}")'.format(
            dip=rx_host.ports_info[rx_host.used_port]['ipv4'],
            n=self.flow_npackets, iface=tx_iface)

        # Init scapy on tester to periodically send packets
        tx_host.scapy_run()
        tx_host.scapy_send("conf.iface='{}'".format(tx_iface))
        # Discard first stats read, just to zeroize them.
        rx_gen.queue_stats()

        # Find required amount of queues forming unique flows.
        dst_port = port_min
        src_port = port_min
        wanted = flow_nb
        while wanted > 0:
            queue_id = self.__detect_one_flow(tx_gen, rx_gen,
                    tx_cmd.format(dport=dst_port, sport=src_port), dst_port)

            assert queue_id is not None

            q_flow_nb = 0 if q_to_port[queue_id] is None else len(q_to_port[queue_id])
            if q_flow_nb < flows_per_queue or \
               (queue_id < flows_nb_rest and q_flow_nb < (flows_per_queue + 1)):
                wanted -= 1
                if q_to_port[queue_id] is None:
                    q_to_port[queue_id] = [[src_port, dst_port]]
                else:
                    q_to_port[queue_id].append([src_port, dst_port])
                self.logger.info("Queue[{:02}]: Associated port pair {} (src_port={}, dst_port={})".format(
                    queue_id, q_flow_nb + 1, src_port, dst_port))
            else:
                self.logger.info("Queue[{:02}]: Already occupied. Looking for another one".format(
                        queue_id))
                # Change source port only on failure
                src_port = port_min if src_port > port_max else src_port + 1
            # Change destination port each time
            dst_port = port_min if dst_port > port_max else dst_port + 1

        flows = filter(lambda p: p is not None, q_to_port)

        tx_host.scapy_exit()
        # Prepare a list of lists to be identical to json.loads() (used
        # further) output
        return flows

    def __test_perf_bw(self, flows=None, stress=None):
        # Validate pkt_sizes
        try:
            pkt_sizes = [int(size) for size in self.test_configs["BW_size"].split(",")]
            for pkt_sz in pkt_sizes:
                if pkt_sz < self.MIN_PKT_SIZE or pkt_sz > self.MAX_PKT_SIZE:
                    raise ValueError("Unsupported packet size.")
        except:
            self.verify(0, "Wrong packet sizes was provided")
            return
        # Validate pkt_types
        try:
            pkt_types = [type.lower() for type in self.test_configs["BW_types"].split(",")]
            for type in pkt_types:
                if type not in self.SUPORTED_PKT_TYPES:
                    raise ValueError("Unsupported packet type.")
        except:
            self.verify(0, "Wrong packet types configuration")
            return

        total_queues = self.validate("BW_queue", self.max_queue)
        if total_queues < self.MIN_QUEUE or total_queues > self.max_queue:
            self.verify(0, "Wrong number of queues")
        # Get the list of requested number of flows
        if self.test_configs["BW_flows"] == "AUTO":
            flows_nb_list = [1, total_queues]
        else:
            flows_nb_list = [int(x) for x in self.test_configs["BW_flows"].split(",")]
        # Validate interval
        try:
            interval = int(self.test_configs["BW_interval"])
            if interval < 1:
                raise ValueError("Unsupported interval length")
        except:
            self.verify(0, "Wrong interval length")
            return
        # Validate measurements_number
        try:
            measurements_number = int(self.test_configs["BW_measurements"])
            if measurements_number < 1:
                raise ValueError("Unsupported number of measurements")
        except:
            self.verify(0, "Wrong number of measurements")
            return

        direction = self.test_configs["BW_direction"]

        target_gbps = int(self.test_configs["BW_target_gbps"])
        if target_gbps == 0:
            # Use instance default Gbps limit if not specified by the user
            tester_gbps = self.tester.instance_max_gbps
            dut_gbps = self.dut.instance_max_gbps
        else:
            dut_gbps = tester_gbps = target_gbps

        tester_conf = {
            'host'      : self.tester,
            'pktgen'    : self.pktgen_tester,
            'tx_flow'   : self.test_configs["BW_tx_flow"],
            'f_pcap'    : PCAP_FILENAME_SUFFIX,
            'queue_nb'  : total_queues,     # verified by init_XXX_instance(s)
            'max_gbps'  : tester_gbps,
            'tx_rates'  : None
        }
        dut_conf = {
            'host'      : self.dut,
            'pktgen'    : self.pktgen_dut,
            'tx_flow'   : False,
            'f_pcap'    : PCAP_FILENAME_SUFFIX,
            'queue_nb'  : total_queues,     # verified by init_XXX_instance(s)
            'max_gbps'  : dut_gbps,
            'tx_rates'  : None
        }

        if direction == "mono":
            self.logger.info('Direction: mono')
            if self.test_configs["two_way_mono"] is False:
                table_hdrs = ['direction','size', 'flows',
                        'Tx queues DUT / Tester', 'type',
                        'Rx on DUT, Gb/s', 'Rx on DUT, Mpps'
                        ]
            else:
                # This case is only used internally for debug purposes. Not
                # relevant for a regular test suite execution
                table_hdrs = ['direction','size', 'flows',
                        'Tx queues DUT / Tester', 'type',
                        'Tx on Tester, Gb/s', 'Rx on Tester, Gb/s',
                        'Tx on DUT, Gb/s', 'Rx on DUT, Gb/s',
                        'Tx on Tester, Mpps', 'Rx on Tester, Mpps',
                        'Tx on DUT, Mpps', 'Rx on DUT, Mpps',
                        ]

            tester_conf['mode'] = 'tx'
            dut_conf['mode'] = 'rx'

        else:
            self.logger.info('Direction: bi')
            table_hdrs = ['direction','size', 'flows',
                    'Tx queues DUT / Tester', 'type',
                    'Rx on DUT, Gb/s',
                    'Rx on Tester, Gb/s',
                    'Rx on DUT, Mpps',
                    'Rx on Tester, Mpps'
                    ]

            tester_conf['mode'] = 'bi'
            dut_conf['mode'] = 'bi'

        # Determine the flows for the Tester
        tester_flows = flows
        # If the flows weren't provided, try to load them from the existing file
        if tester_flows is None and not self.test_configs['force_setup']:
            tester_flows = self.load_flows_from_file(self.tester, self.dut)
        # If still couldn't determine the flows, perform the detection step
        if tester_flows is None:
            tester_flows = self.generate_flows_list(tester_conf, dut_conf,
                    total_queues, direction, self.max_flows_nb)

        # Determine the flows for the DUT only for bidirectional tests or
        # monodirectional-reverse
        if direction == "bi" or self.test_configs["two_way_mono"]:
            dut_flows = flows

            if dut_flows is None and not self.test_configs['force_setup']:
                dut_flows = self.load_flows_from_file(self.dut, self.tester)
            if dut_flows is None:

                dut_flows = self.generate_flows_list(dut_conf, tester_conf,
                        total_queues, direction, self.max_flows_nb)
        else:
            # In any other case, just point dut and tester to the same flow array
            # for compatibility with further code which requires both values to
            # be valid lists.
            dut_flows = tester_flows

        # Now zip DUT and Tester flows into common structure
        all_tester_flows_list = []
        all_dut_flows_list = []
        q_nb = min(dut_conf['queue_nb'], tester_conf['queue_nb'])
        for flows_nb in flows_nb_list:
            if flows_nb < 1:
                raise ValueError("Less than 1 flow makes no sense.")
            flows_per_queue = flows_nb // q_nb
            flows_remainder = flows_nb % q_nb
            tester_flow_list = []
            dut_flow_list = []
            for (tester_ports_pairs, dut_ports_pairs, qid) in zip(tester_flows, dut_flows, range(q_nb)):
                flows_needed = flows_per_queue
                if qid < flows_remainder:
                    flows_needed += 1
                if flows_needed > 0:
                    tester_flow_list.append(tester_ports_pairs[:flows_needed])
                    dut_flow_list.append(dut_ports_pairs[:flows_needed])
            all_tester_flows_list.append(tester_flow_list)
            all_dut_flows_list.append(dut_flow_list)

        self.logger.info("Requested DUT queues: {}, available: {}".format(
            total_queues, dut_conf['queue_nb']))

        if direction == "mono":
            traffic = self.mono_traffic
            tester_conf['tx_rates'] = AUTO_QUEUE_TX_RATE
            dut_conf['tx_rates'] = DEFAULT_QUEUE_TX_RATE
            # When f_pcap has some value, then etgen tries to use pcap files on
            # the host. As the Tester is the default Tx generator, this option
            # should be initially disabled.
            dut_conf['f_pcap'] = None
        elif direction == "bi":
            traffic = self.bi_traffic
            # Compensate the parameters forbidden before generate_flows_list
            dut_conf['tx_flow'] = self.test_configs["BW_tx_flow"]
            tester_conf['tx_rates'] = AUTO_QUEUE_TX_RATE
            dut_conf['tx_rates'] = AUTO_QUEUE_TX_RATE

        # NOTE: These are deprecated for now
        # if stress is not None and direction == "tri":
        #     traffic = self.tester2_traffic
        # elif direction == "tri_bi":
        #     traffic = self.tester2_bi_traffic
        # elif direction == "tri_mono":
        #     traffic = self.tester2_mono_traffic

        self.result_table_create(table_hdrs)
        self.result_table_set_precision(3)
        self.pkt_cnts = []

        addr_tester = {
            "src_mac" : self.tester.get_mac_address(self.port_tester),
            "dst_mac" : self.dut.get_mac_address(self.port_dut),
            "src_ip"  : self.tester.get_ipv4_address(self.port_tester),
            "dst_ip"  : self.dut.get_ipv4_address(self.port_dut),
        }
        addr_dut = {
            "src_mac" : self.dut.get_mac_address(self.port_dut),
            "dst_mac" : self.tester.get_mac_address(self.port_tester),
            "src_ip"  : self.dut.get_ipv4_address(self.port_dut),
            "dst_ip"  : self.tester.get_ipv4_address(self.port_tester),
        }

        for pkt_sz in pkt_sizes:
            self.logger.info('\tSize:' + str(pkt_sz))
            for (tester_flow_list, dut_flow_list) in zip(all_tester_flows_list, all_dut_flows_list):
                self.logger.info('\t\tFlows number: {}'.format(
                    sum([len(x) for x in tester_flow_list])))
                for pkt_type in pkt_types:
                    # Reset changes of previous iterations
                    for cnf in [ tester_conf, dut_conf ]:
                        cnf['queue_nb'] = total_queues
                        cnf['d_pcap'] = get_pcap_dirnm(pkt_sz, pkt_type, direction)
                    self.logger.info('\t\tPacket type:' + str(pkt_type))
                    self.logger.info('\t\t\tGenerating pcap file...')

                    self.generate_pcap(self.tester, addr_tester, tester_flow_list, pkt_type, pkt_sz, direction)
                    if direction == "bi":
                        self.generate_pcap(self.dut, addr_dut, dut_flow_list, pkt_type, pkt_sz, direction)

                    traffic(tester_conf, dut_conf, measurements_number,
                            interval, pkt_sz, tester_flow_list, dut_flow_list, pkt_type)

                    if direction == "mono" and self.test_configs["two_way_mono"]:
                        _d_conf = dut_conf.copy()
                        _t_conf = tester_conf.copy()
                        _d_conf['mode'] = 'tx'
                        _t_conf['mode'] = 'rx'
                        _d_conf['tx_flow'] = _t_conf['tx_flow']
                        _t_conf['tx_flow'] = False
                        _t_conf['f_pcap'] = None
                        _d_conf['f_pcap'] = PCAP_FILENAME_SUFFIX
                        _d_conf['tx_rates'] = AUTO_QUEUE_TX_RATE
                        _t_conf['tx_rates'] = DEFAULT_QUEUE_TX_RATE

                        self.generate_pcap(self.dut, addr_dut, dut_flow_list, pkt_type, pkt_sz, direction)

                        self.mono_traffic(_t_conf, _d_conf,
                                measurements_number, interval, pkt_sz,
                                tester_flow_list, dut_flow_list, pkt_type)

        self.pktgen_tester.end()
        self.pktgen_dut.end()
        self.result_table_print()

        if direction == "tri_mono" or direction == "tri_bi":
            self.result_table_create(['size', 'queues', 'type', 'DUT Tx', "DUT Rx",
                                      "Tester1 Tx", "Tester1 Rx", "Tester2 Tx",
                                      "Tester2 Rx"])
            self.result_table_set_precision(3)
            for r in self.pkt_cnts:
                self.result_table_add(r)
            self.result_table_print()

        elif stress is not None and self.pkt_cnts:
            print("\n")     # tables separation
            hdr_row = ['direction', 'size', 'flows',
                          'Tx queues DUT / Tester', 'type',
                          'Tester Tx, b/s',
                          'DUT Rx, b/s',
                          'FW missing',
                          'Tester Tx errors',
                          'DUT Rx errors',
                          'DUT Rx drops',
                          'DUT Tx, b/s',
                          'Tester Rx, b/s',
                          'BW missing',
                          'DUT TX errors',
                          'Tester Rx errors',
                          'Tester Rx drops',
                        ]

            self.result_table_create(hdr_row)
            self.result_table_set_precision(3)

            for r in self.pkt_cnts:
                self.result_table_add(r)
            self.result_table_print()

    def get_flows_filename(self, tx_host, rx_host):
        tx_port = tx_host.used_port
        rx_port = rx_host.used_port
        out = 'flows_{src_ip}_{src_mac}_{dst_ip}_{dst_mac}'.format(
                src_ip=tx_host.get_ipv4_address(tx_port),
                src_mac=tx_host.get_mac_address(tx_port),
                dst_ip=rx_host.get_ipv4_address(rx_port),
                dst_mac=rx_host.get_mac_address(rx_port),
                )
        return out

    def save_flows(self, flows, tx_host, rx_host):
        fname = self.get_flows_filename(tx_host, rx_host)
        tx_host.send_expect("rm -f {}".format(fname), "# ")
        tx_host.save_file(fname, json.dumps(flows))
        tx_host.logger.info("Flows list saved to {}".format(fname))

    def load_flows_from_file(self, tx_host, rx_host):
        out = None
        fname = self.get_flows_filename(tx_host, rx_host)

        if tx_host.path_exist(fname) is True:
            data = tx_host.send_expect("cat {}".format(fname), "# ")
            try:
                data = json.loads(data)
            except:
                self.logger.error("Reading file {} failed." \
                        "Flows list will be generated from scratch".format(fname))
            else:
                # Verify, if:
                # 1. It's an list
                # 2. It was created for the same amount of queues which are
                #    planned to be used
                # 3. There are enough flows for each queue
                total_queues = self.validate("BW_queue", self.max_queue)
                flows_per_q = [self.max_flows_nb // total_queues] * total_queues
                for i in range(0, self.max_flows_nb % total_queues):
                    flows_per_q[i] += 1
                if type(data) is type([]) and \
                   len(data) == total_queues and \
                   all([len(d) >= f for (d, f) in zip(data, flows_per_q)]) :
                    out = data

        # Even if pcap files would be found, it is not sure whether they are
        # valid ones.
        if out is None:
            self.test_configs['try_reuse_pcaps'] = False

        return out

    def test_perf_bw(self, flows=None, stress=None):
        if self.test_configs["BW_flows"] == "AUTO":
            self.max_flows_nb = self.validate("BW_queue", self.max_queue)
        else:
            self.max_flows_nb = max([int(x) for x in self.test_configs["BW_flows"].split(",")])

        self.__test_perf_bw(flows=flows)

    @staticmethod
    def init_pktgen_instance(conf, flow_list=None, burst_rate=100):
        dev_port = conf['host'].used_port
        pktgen = conf['pktgen']

        return pktgen.init(dev_port, dev_port, conf, burst_rate, flow_list)

    @staticmethod
    def init_pktgen_instances(conf1, conf2, flow_list1, flow_list2):
        start_timeout = 2

        conf1['queue_nb'] = TestENA.init_pktgen_instance(conf1, flow_list1)
        conf2['queue_nb'] = TestENA.init_pktgen_instance(conf2, flow_list2)

        time.sleep(start_timeout)

    @staticmethod
    def detect_best_rates(tx_conf, rx_conf, flow_list):
        burst_rate = 100
        init_timeout = 3
        start_timeout = 2
        stop_timeout = 1
        traffic_timeout = 5
        # Max rate value is 10 Gbps per flow, absolute limit.
        rate_max = 10000
        txq_used = len(flow_list)
        flows_nb = sum([len(queue_flow) for queue_flow in flow_list])

        tx_host = tx_conf['host']
        tx_host.logger.info("\tDetect the most optimal Tx rates for the flow")

        tx_inst = tx_conf['pktgen']
        rx_inst = rx_conf['pktgen']
        f_pcap = rx_conf['f_pcap']
        # Make sure that Rx machine don't use Tx pcaps
        rx_conf['f_pcap'] = None
        rxq_num = TestENA.init_pktgen_instance(rx_conf, flow_list)
        rx_conf['f_pcap'] = f_pcap

        # Each Tx queue can have different number of flows, so it's rate limit
        # can differ
        q_rate_max = [len(queue_flow) * rate_max for queue_flow in flow_list]
        # Maximum possible rate for the single Tx flow, taking into
        # consideration the number of queueus
        flow_rate_max = min(rate_max, tx_conf["max_gbps"] * 1000 // flows_nb)
        tx_rates = [int(len(queue_flow) * flow_rate_max) for queue_flow in flow_list]
        # The step rate should be 1/10 of regular Tx queue rate, but not bigger than 1Gbps
        step_rate = min(tx_rates[0] // 10, 1000)
        old_tx_rates = list(tx_rates)

        # Run once with default values and limit the flows to rate value, which
        # was achieved
        tx_conf["tx_rates"] = tx_rates
        TestENA.init_pktgen_instance(tx_conf, flow_list)
        time.sleep(init_timeout)

        # Execute flow for 5 seconds
        tx_inst.start()
        time.sleep(start_timeout)
        # First statistic read juz zeroize the counters
        rx_inst.queue_stats()
        start_time = time.time()
        time.sleep(traffic_timeout)
        end_time = time.time()
        (_, rxq_stats) = rx_inst.queue_stats()
        tx_inst.quit()
        time.sleep(stop_timeout)

        test_time = end_time - start_time

        for qid in range(rxq_num):
            rx_rate_total = rxq_stats[qid]["bytes"]
            rx_rate_mbps = rx_rate_total * 8 // 1000000 // test_time
            if rx_rate_mbps < (tx_rates[qid] - step_rate):
                    # As rx_rate_mbps reading may not be not very accurate, adjust it by the step_rate value.
                    # Especially small packets flows benefits from having higher rate.
                    tx_rates[qid] = rx_rate_mbps + step_rate

        rate_stable = [False] * txq_used
        rate_changed = True
        # Increase rate for queues which show improvement until all queues have
        # stable rate value.
        while rate_changed:
            old_tx_rates = tx_rates
            tx_rates = [min(rate_max, rate + step_rate) if not stable else rate
                        for (stable, rate, rate_max) in zip(rate_stable, old_tx_rates, q_rate_max)]
            tx_conf["tx_rates"] = tx_rates

            # Start Tx instance with new rates
            TestENA.init_pktgen_instance(tx_conf, flow_list)
            time.sleep(init_timeout)

            # Execute flow for 5 seconds
            tx_inst.start()
            time.sleep(start_timeout)
            # Clean Rx statistics
            rx_inst.queue_stats()
            start_time = time.time()
            time.sleep(traffic_timeout)
            end_time = time.time()
            (_, rxq_stats) = rx_inst.queue_stats()
            tx_inst.quit()
            time.sleep(stop_timeout)
            test_time = end_time - start_time

            # Get the rate and compare it with expected
            rate_changed = False
            for qid in range(rxq_num):
                if rate_stable[qid]:
                    continue
                rx_rate_total = rxq_stats[qid]["bytes"]
                rx_rate_mbps = rx_rate_total * 8 // 1000000 // test_time
                expected_rate = old_tx_rates[qid] + step_rate
                if rx_rate_mbps >= expected_rate:
                    # Keep the adjusted rate
                    rate_changed = True
                else:
                    # Revert the old rate value
                    tx_rates[qid] = old_tx_rates[qid]
                    rate_stable[qid] = True

        rx_inst.quit()
        tx_host.logger.debug("\tDone. Tx rates detected: {}".format(tx_rates))

    def mono_traffic(self, t_conf, d_conf, msr_nb, interval, size,
            t_flow_list, d_flow_list, pkt_type):
        if d_conf['mode'] == 'tx' and t_conf['mode'] == 'rx':
            tx_conf = d_conf
            rx_conf = t_conf
            flow_dir_str = 'DUT -> Tester'
            flow_list = d_flow_list
        elif d_conf['mode'] == 'rx' and t_conf['mode'] == 'tx':
            tx_conf = t_conf
            rx_conf = d_conf
            flow_dir_str = 'Tester -> DUT'
            flow_list = t_flow_list
        else:
            assert 0, "Invalid mono traffic configuration - both Tx mode and Rx mode hosts must be provided."

        tx_gen = tx_conf['pktgen']
        rx_gen = rx_conf['pktgen']

        TestENA.detect_best_rates(tx_conf, rx_conf, flow_list)

        TestENA.init_pktgen_instances(tx_conf, rx_conf, flow_list, flow_list)

        self.logger.info("\t\t\tLaunching the traffic")
        stats_dict = self.generate_mono_traffic(tx_gen, rx_gen,
                msr_nb, interval)
        tx_gen.quit()
        rx_gen.quit()

        parsed_stats = stats_dict['parsed_stats']
        avg_tx = stats_dict['avg_tx_stats']
        avg_rx = stats_dict['avg_rx_stats']

        avg_rx_gbps = 8 * avg_rx['rx_bytes'] / 1000000000 / avg_rx['rx_delay_sec']
        avg_rx_mpps = avg_rx['rx_pkt'] / 1000000 / avg_rx['rx_delay_sec']

        avg_tx_gbps = 8 * avg_tx['tx_bytes'] / 1000000000 / avg_tx['tx_delay_sec']
        avg_tx_mpps = avg_tx['tx_pkt'] / 1000000 / avg_tx['tx_delay_sec']

        _q_str = "{} / {}".format(0, tx_conf['queue_nb'])
        flows_nb = sum([len(queue_flow) for queue_flow in flow_list])
        pkts = [flow_dir_str, size, flows_nb, _q_str, pkt_type] + parsed_stats[:]
        self.pkt_cnts.append(pkts)

        if self.test_configs["two_way_mono"] is False:
            self.result_table_add([flow_dir_str, size, flows_nb,
                _q_str,
                pkt_type,
                avg_rx_gbps, avg_rx_mpps,
                ])
        else:
            self.result_table_add([flow_dir_str, size, flows_nb,
                _q_str,
                pkt_type,
                avg_tx_gbps, 0,
                0, avg_rx_gbps,
                avg_tx_mpps, 0,
                0, avg_rx_mpps,
                ])

    def bi_traffic(self, t_conf, d_conf, msr_nb, interval, size,
            t_flow_list, d_flow_list, pkt_type):
        t_gen = t_conf['pktgen']
        d_gen = d_conf['pktgen']
        # The number of flows should be symmetrical
        flows_nb = sum([len(queue_flow) for queue_flow in t_flow_list])

        TestENA.detect_best_rates(t_conf, d_conf, t_flow_list)
        TestENA.detect_best_rates(d_conf, t_conf, d_flow_list)
        TestENA.init_pktgen_instances(t_conf, d_conf, t_flow_list, d_flow_list)

        self.logger.info("\t\t\tLaunching the traffic")
        stats_dict = self.generate_bi_traffic(t_gen, d_gen, msr_nb, interval)
        t_gen.quit()
        d_gen.quit()

        parsed_stats = stats_dict['parsed_stats']
        avg_t_pc = stats_dict['avg_tester_stats']
        avg_d_pc = stats_dict['avg_dut_stats']

        avg_d_tx_gbps = 8 * avg_d_pc['tx_bytes'] / 1000000000 / avg_d_pc['tx_delay_sec']
        avg_d_tx_mpps = avg_d_pc['tx_pkt'] / 1000000 / avg_d_pc['tx_delay_sec']

        avg_t_rx_gbps = 8 * avg_t_pc['rx_bytes'] / 1000000000 / avg_t_pc['rx_delay_sec']
        avg_t_rx_mpps = avg_t_pc['rx_pkt'] / 1000000 / avg_t_pc['rx_delay_sec']

        avg_d_rx_gbps = 8 * avg_d_pc['rx_bytes'] / 1000000000 / avg_d_pc['rx_delay_sec']
        avg_d_rx_mpps = avg_d_pc['rx_pkt'] / 1000000 / avg_d_pc['rx_delay_sec']

        avg_t_tx_gbps = 8 * avg_t_pc['tx_bytes'] / 1000000000 / avg_t_pc['tx_delay_sec']
        avg_t_tx_mpps = avg_t_pc['tx_pkt'] / 1000000 / avg_t_pc['tx_delay_sec']

        _q_str = "{} / {}".format(d_conf['queue_nb'], t_conf['queue_nb'])
        self.result_table_add(['Tester <=> DUT', size, flows_nb, _q_str, pkt_type,
            avg_d_rx_gbps,
            avg_t_rx_gbps,
            avg_d_rx_mpps,
            avg_t_rx_mpps
            ])

        pkts = ['Tester <=> DUT', size, flows_nb, _q_str, pkt_type] + parsed_stats
        self.pkt_cnts.append(pkts)

    # The `backward` parameter affects only results placement order:
    #   - False: Tester -> DUT
    #   - True: DUT -> Tester
    # This is because in 'mono' case, the function is called twice for two
    # directions and results must be printed appropriately
    def parse_stress(self, tx_pc, rx_pc, backward=False):
        missing = tx_pc["tx_pkt"] - rx_pc["rx_pkt"]

        if self.test_configs["BW_direction"] == "bi":
            missing_bw = rx_pc["tx_pkt"] - tx_pc["rx_pkt"]
            pkts = [add_unit(p[0] / p[1]) for p in [
                    (8 * tx_pc["tx_bytes"], tx_pc["tx_delay_sec"]),
                    (8 * rx_pc["rx_bytes"], rx_pc["rx_delay_sec"]),
                    (missing, 1),
                    (tx_pc["tx_err"], 1),
                    (rx_pc["rx_err"], 1),
                    (rx_pc["rx_drops"], 1),
                    (8 * rx_pc["tx_bytes"], rx_pc["tx_delay_sec"]),
                    (8 * tx_pc["rx_bytes"], tx_pc["rx_delay_sec"]),
                    (missing_bw, 1),
                    (rx_pc["tx_err"], 1),
                    (tx_pc["rx_err"], 1),
                    (tx_pc["rx_drops"], 1)
                ]]

        elif self.test_configs["BW_direction"] == "mono":
            missing_bw = rx_pc["tx_pkt"] - tx_pc["rx_pkt"]
            if backward is False:
                pkts = [add_unit(p[0] / p[1]) for p in [
                        (8 * tx_pc["tx_bytes"], tx_pc["tx_delay_sec"]),
                        (8 * rx_pc["rx_bytes"], rx_pc["rx_delay_sec"]),
                        (missing, 1),
                        (tx_pc["tx_err"], 1),
                        (rx_pc["rx_err"], 1),
                        (rx_pc["rx_drops"], 1),
                        ]]
                # pkts.extend([0,0,0,0,0,0])
                pkts.extend([add_unit(p[0] / p[1]) for p in [
                    (8 * rx_pc["tx_bytes"], rx_pc["rx_delay_sec"]),
                    (8 * tx_pc["rx_bytes"], tx_pc["tx_delay_sec"]),
                    (missing_bw, 1),
                    (rx_pc["tx_err"], 1),
                    (tx_pc["rx_err"], 1),
                    (tx_pc["rx_drops"], 1)
                    ]])
            else:
                missing_bw = rx_pc["tx_pkt"] - tx_pc["rx_pkt"]
                # pkts = [0,0,0,0,0,0]
                pkts = [add_unit(p[0] / p[1]) for p in [
                    (8 * rx_pc["tx_bytes"], rx_pc["rx_delay_sec"]),
                    (8 * tx_pc["rx_bytes"], tx_pc["tx_delay_sec"]),
                    (missing_bw, 1),
                    (rx_pc["tx_err"], 1),
                    (tx_pc["rx_err"], 1),
                    (tx_pc["rx_drops"], 1)
                        ]]
                pkts.extend([add_unit(p[0] / p[1]) for p in [
                        (8 * tx_pc["tx_bytes"], tx_pc["tx_delay_sec"]),
                        (8 * rx_pc["rx_bytes"], rx_pc["rx_delay_sec"]),
                        (missing, 1),
                        (tx_pc["tx_err"], 1),
                        (rx_pc["rx_err"], 1),
                        (rx_pc["rx_drops"], 1),
                        ]])

        return pkts

    def generate_pcap_execute(self, host, pkg, l=8192):
        host.scapy_foreground()
        burst = len(pkg)
        m = l // burst
        m += 1 if l % burst != 0 else 0
        host.scapy_append('wrpcap("{}", ([{}]*{})[:{}])'.format(
            PCAP_FILENAME_SUFFIX, ", ".join(pkg), m, l))
        status = host.scapy_execute()
        self.verify(status == 0, "Error during generating pcap files.")

    # Creates pcap files both on given host.
    def generate_pcap(self, host, addr, flows, pkt_type, size, direction="mono"):
        if not self.test_configs["BW_tx_flow"]:
            return

        pcap_dir = get_pcap_dirnm(size, pkt_type, direction)

        ex_pcaps = []
        # Additionally to start parameters, the 'try_reuse_pcaps' entry can be
        # set to `False` by the `load_flows_from_file`.
        if self.test_configs['force_setup'] is False and \
            self.test_configs['try_reuse_pcaps'] is True:
            self.logger.debug("Trying to reuse pcaps")
            if host.path_exist(pcap_dir):
                find_existing_pcaps(host, ex_pcaps, pcap_dir)
        else:
            self.logger.debug("Pcaps cannot be reused")

        self.logger.debug("Pcaps found: {}".format(ex_pcaps))
        self.pcap_per_queue(host, addr, flows, pkt_type, size, pcap_dir, ex_pcaps)

    def pcap_per_queue(self, host, addr, flows, pkt_type, size, pcap_dir, ex_flows):
        # Create directory if it does not exist
        host.mk_dir(pcap_dir)

        # pcap files are indexed from 0
        start = len(ex_flows)
        self.logger.debug("start: {}".format(start))

        i = start
        for ports_pairs in flows:
            if ports_pairs in ex_flows:
                continue
            pkg = generate_pcap_string(ports_pairs, pkt_type, size)
            pcap_cmd = pkg.format(smac=addr["src_mac"], dmac=addr["dst_mac"],
                                  sip=addr["src_ip"], dip=addr["dst_ip"])
            _p_fpath = gen_pcap_fpath(ports_pairs, i, pcap_dir)
            self.logger.debug("Generating: %s" % _p_fpath)
            flow_entries = 2048 // len(ports_pairs)
            host.scapy_append("wrpcap('{}', [{}]*{})".format(_p_fpath, pcap_cmd, flow_entries))
            i += 1

        host.scapy_execute()

    def generate_mono_traffic(self, tx, rx, msr_nb, interval, is_backward=False):
        start_timeout = 2

        tx.reset_all_counts()
        rx.reset_all_counts()
        time.sleep(start_timeout)

        tx.start()
        time.sleep(start_timeout)
        rx_bps = 0
        rx_pps = 0
        tx_bps = 0
        tx_pps = 0
        for i in range(msr_nb):
            time.sleep(interval)
            rx_bps_m, rx_pps_m, _, _ = rx.stats()
            _, _, tx_bps_m, tx_pps_m = tx.stats()
            rx_bps += rx_bps_m
            rx_pps += rx_pps_m
            tx_bps += tx_bps_m
            tx_pps += tx_pps_m
        tx.stop()

        tx_pc = tx.pkt_counts()
        rx_pc = rx.pkt_counts()

        # Do not reset before stats collection!
        rx.reset_all_counts()

        rx_bps /= msr_nb
        rx_pps /= msr_nb
        tx_bps /= msr_nb
        tx_pps /= msr_nb

        pkts = self.parse_stress(tx_pc, rx_pc, is_backward)

        out = {
                'rate_rx_bps'   : rx_bps,
                'rate_rx_pps'   : rx_pps,
                'rate_tx_bps'   : tx_bps,
                'rate_tx_pps'   : tx_pps,
                'parsed_stats'  : pkts,
                'avg_tx_stats'  : tx_pc,
                'avg_rx_stats'  : rx_pc,
                }
        return out


    def generate_bi_traffic(self, t_gen, d_gen, msr_nb, interval):
        start_timeout = 2
        t_rx_bps = t_rx_pps = t_tx_bps = t_tx_pps = 0
        d_rx_bps = d_rx_pps = d_tx_bps = d_tx_pps = 0

        t_gen.reset_all_counts()
        d_gen.reset_all_counts()
        time.sleep(start_timeout)

        t_gen.start()
        d_gen.start()
        time.sleep(start_timeout)

        for i in range(msr_nb):
            time.sleep(interval)

            _t_rx_bps, _t_rx_pps, _t_tx_bps, _t_tx_pps = t_gen.stats()
            _d_rx_bps, _d_rx_pps, _d_tx_bps, _d_tx_pps = d_gen.stats()

            t_rx_bps += _t_rx_bps
            t_rx_pps += _t_rx_pps
            t_tx_bps += _t_tx_bps
            t_tx_pps += _t_tx_pps
            d_rx_bps += _d_rx_bps
            d_rx_pps += _d_rx_pps
            d_tx_bps += _d_tx_bps
            d_tx_pps += _d_tx_pps

        t_gen.stop()
        d_gen.stop()

        t_gen_pc = t_gen.pkt_counts()
        d_gen_pc = d_gen.pkt_counts()

        t_gen.reset_all_counts()
        d_gen.reset_all_counts()

        t_rx_bps /= msr_nb
        t_rx_pps /= msr_nb
        t_tx_bps /= msr_nb
        t_tx_pps /= msr_nb
        d_rx_bps /= msr_nb
        d_rx_pps /= msr_nb
        d_tx_bps /= msr_nb
        d_tx_pps /= msr_nb

        pkts = self.parse_stress(t_gen_pc, d_gen_pc)

        out = {
                'rates_t_rx_bps'    : t_rx_bps,
                'rates_t_rx_pps'    : t_rx_pps,
                'rates_t_tx_bps'    : t_tx_bps,
                'rates_t_tx_pps'    : t_tx_pps,
                'rates_d_rx_bps'    : d_rx_bps,
                'rates_d_rx_pps'    : d_rx_pps,
                'rates_d_tx_bps'    : d_tx_bps,
                'rates_d_tx_pps'    : d_tx_pps,
                'parsed_stats'      : pkts,
                'avg_tester_stats'  : t_gen_pc,
                'avg_dut_stats'     : d_gen_pc,
            }
        return out

    def validate(self, name, default):
        try:
            v = self.test_configs[name]
            if v == "AUTO":
                return default
            else:
                return int(v)
        except:
            self.verify(0, "Wrong {} value".format(name))

    def get_queues_from_pcap(self, fpath):
        ports = []
        sp_name = 'scapy_detect_queues.py'
        sp = '{}/{}'.format(self.tester.dst_dir, sp_name)

        # Copy a heredoc script to the tester
        # DO NOT change the indentation
        _scr = \
        """ \
cat << '@@@' > {_sp}
from scapy.all import rdpcap

fpath = '{_pcap_path}'
ports = []
pckts = rdpcap(fpath)

for pkt in pckts:
    try:
        sp = pkt[1][1].sport
        dp = pkt[1][1].dport
    except AttributeError:
        continue
    else:
        port_pair = [ sp, dp ]
        if port_pair not in ports:
            ports.append(port_pair)

print(ports)

@@@
        """.format(_sp=sp, _pcap_path=fpath)

        # Execute the heredoc
        self.tester.send_expect(_scr, "# ")
        time.sleep(1)

        # Verify that the script is there
        tester_tmpfiles = self.tester.send_expect("ls {}".format(self.tester.dst_dir), "# ")
        assert sp_name in tester_tmpfiles, "Script not copied to tester!"

        # Run the script on tester to detect queues
        _cmd = "/usr/bin/env python {}".format(sp)
        _ports = self.tester.send_expect(_cmd, "# ")
        ports = ast.literal_eval(_ports)
        return ports

    def test_perf_pcap(self):

        def cmd_pcap_path():
            return "/tmp/pcap_tester.pcap"

        try:
            tester_path = copy_pcap(self.tester, PCAP_TESTER)
        except Exception as e:
            self.logger.error(e)
            exit()

        # Local pcap is copied to tester, then more information is retrieved
        # from the remote copy in order not to require Scapy to be installed
        # locally.
        flows = self.get_queues_from_pcap(tester_path)

        # Assumption - Differently to `test_perf_bw`:
        # - `flows_nb` NOT set by the "BW_flows" parameter, determined by the
        #   number of different pairs of ports in packets inside the pcap file,
        # - `total_queues` NOT set by "BW_queue" parameter, primarily equals to
        # `flows` but additionally limited by `self.max_queue`,
        flows_nb = len(flows)

        total_queues = \
            flows_nb if flows_nb <= self.max_queue else self.max_queue
        if total_queues < self.MIN_QUEUE:
            self.verify(0, "Wrong number of queues")

        pcap_tester = "{}/{}".format(PCAP_DIR, PCAP_TESTER)
        out = self.tester.send_expect("ls {}/{}".format(self.tester.base_dir,
                                                        pcap_tester), "# ")
        assert "No such file" not in out, "Cannot find pcap file."

        interval = self.validate("BW_interval", 1)
        assert interval >= 1, "Unsupported interval length"

        measurements_number = self.validate("BW_measurements", 1)
        assert measurements_number >= 1, "Unsupported number of measurements."

        tester_conf = {
            'host'      : self.tester,
            'pktgen'    : self.pktgen_tester,
            'tx_flow'   : self.test_configs["BW_tx_flow"],
            'f_pcap'    : pcap_tester,
            'queue_nb'  : total_queues,    # filled by init_pktgen_instances
            'pcap_cmd'  : cmd_pcap_path,
        }
        dut_conf = {
            'host'      : self.dut,
            'pktgen'    : self.pktgen_dut,
            'tx_flow'   : False,
            'f_pcap'    : None,
            'queue_nb'  : total_queues,    # filled by init_pktgen_instances
        }
        # Assumption: this test runs in the 'mono' mode
        tester_conf['mode'] = 'tx'
        dut_conf['mode'] = 'rx'
        direction = 'mono'

        # Nb of flows may surpass self.max_queue but it is always equal to
        # len(flows)
        TestENA.init_pktgen_instances(tester_conf, dut_conf, flows, flows)

        stats_dict = self.generate_mono_traffic(self.pktgen_tester,
                self.pktgen_dut, measurements_number, interval)
        rx_bps_dut = stats_dict['rate_rx_bps']
        rx_pps_dut = stats_dict['rate_rx_pps']
        tx_bps_tester = stats_dict['rate_tx_bps']
        tx_pps_tester = stats_dict['rate_tx_pps']

        self.pktgen_tester.quit()
        self.pktgen_dut.quit()

        self.result_table_create(['direction','size', 'flows',
            'Tx queues DUT / Tester', 'type', 'Rx on DUT, Gb/s',
            'Rx on DUT, pps' ])
        self.result_table_set_precision(3)

        # Packet type and size not known - depends on the pcap contents
        self.result_table_add(['Tester -> DUT', 'N/A', flows_nb,
            total_queues, 'N/A', rx_bps_dut, rx_pps_dut])
        self.result_table_print()

    def tear_down(self):
        """
        Run after each test case.
        """
        self.tester.send_expect("^C", "")
        self.dut.send_expect("^C", "")
        self.tester.scapy_exit()
        self.dut.scapy_exit()
        self.latency_echo.stop_echo()
        self.latency_send.stop_echo()
        self.pktgen_dut.quit()
        self.pktgen_tester.quit()
        if self.pmd_on:
            self.pmdout.quit()
            self.pmd_on = False
        self.dut.kill_all()
        self.test_configs = self.test_configs_copy

    def tear_down_all(self):
        """
        Run after each test suite.
        """
        self.pktgen_dut.quit()
        self.pktgen_tester.quit()
        if self.pmd_on:
            self.pmdout.quit()
            self.pmd_on = False
        self.tester.free_hugepage()
        self.dut.free_hugepage()
        self.dut.kill_all()


def add_unit(value):
    for unit in ["", "k", "M", "G", "T", "P", "E", "Z"]:
        if abs(value) < 1000:
            return "{:.3f} {}".format(value, unit)
        value /= 1000

def find_existing_pcaps(crb_obj, ex_pcaps, p_dir):
    patt = re.compile(r'_(\d+)_(\d+)')
    _flist = crb_obj.send_expect("ls -1 {}".format(p_dir), "# ")
    for l in _flist.split('\n'):
        res = patt.findall(l)
        if res is not None:
            ports = []
            for r in res:
                ports.append([int(r[0]), int(r[1])])
            ex_pcaps.append(ports)


def generate_pcap_string(ports_pairs, pkt_type, size):
    header_size = HEADER_SIZE['eth'] + HEADER_SIZE['ip'] + HEADER_SIZE[pkt_type]
    padding = size - header_size
    flags = ", flags=0" if pkt_type == "tcp" else ""
    pkg = ""
    for pp in ports_pairs:
        pkg += 'Ether(src="{{smac}}", dst="{{dmac}}")/' \
               'IP(src="{{sip}}", dst="{{dip}}")/' \
               '{pkt_type}(sport={sport}, dport={dport}{flags})/' \
               'Raw(load="P" * {padding}),'\
                    .format(pkt_type=pkt_type.upper(), sport=pp[0],
                        dport=pp[1], flags=flags, padding=padding)
    return pkg

def get_pcap_dirnm(size, pkt_type, direction):
    out = 'pcaps_{}_{}_{}'.format(size, pkt_type, direction)
    return out
