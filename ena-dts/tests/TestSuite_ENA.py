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
     - generate_ports_list
     - create_pktgen_flows
     - __test_perf_bw
     - get_ports_filename
     - save_ports
     - load_ports_from_file
     - test_perf_bw
     - init_dut_instance
     - init_pktgen_instances
     - mono_traffic
     - mono_traffic_reverse
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
  * Rework tear_down() and tear_down_all() methods to perform additional cleanup
    required by the test suite
"""
import time
import re
import json
import os
import ast
from test_case import TestCase
from pmd_output import PmdOutput
from settings import HEADER_SIZE, PROTOCOL_PACKET_SIZE, DEFAULT_QUEUE_TX_RATE
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

        self.dut_instance_type = self.dut.check_instance_type()
        self.tester_instance_type = self.tester.check_instance_type()
        self.dut_ncpu = self.dut.get_cpu_number()
        self.tester_ncpu = self.tester.get_cpu_number()

        ntype = re.compile("[a-zA-Z]\d[a-zA-Z]*n\.\w*")
        is_dut_ntype = ntype.match(self.dut_instance_type) is not None
        is_tester_ntype = ntype.match(self.tester_instance_type) is not None
        if is_dut_ntype and is_tester_ntype:
            self.max_queue = min(self.MAX_QUEUE_N_TYPE,
                    self.dut_ncpu - SoftwarePacketGenerator.NOT_USED_CPUS,
                    self.tester_ncpu - SoftwarePacketGenerator.NOT_USED_CPUS)
        else:
            self.max_queue = min(self.MAX_QUEUE_DEFAULT,
                    self.dut_ncpu - SoftwarePacketGenerator.NOT_USED_CPUS,
                    self.tester_ncpu - SoftwarePacketGenerator.NOT_USED_CPUS)

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
    def __find_active_queue(self, lua_table, n_min=0):
        # self.logger.info(lua_table)
        found = 0

	for l in lua_table.splitlines():
	    res = self.active_que_re.match(l)
	    if res is not None:
	        pkts_cnt = int(res.group(2))
	        if pkts_cnt > n_min:
                    found += 1
                    if found == 1:
                        qid = int(res.group(1))
                    else:
                        raise FlowDetectionException(
                                FlowDetectionException.MULTIPLE_HITS)
        else:
            if found == 0:
                # This can possibly happen if statistics are read too quickly.
                raise FlowDetectionException(FlowDetectionException.ZERO_HITS)

        return qid


    def __detect_one_flow(self, t_gen, d_gen, t_cmd, dport, send=True):
        t_crb = t_gen.tester

        if send:
            t_crb.scapy_send(t_cmd)

        try:
            queue_id = self.__find_active_queue(d_gen.queue_stats())

        except FlowDetectionException as fde:
            if fde.state == FlowDetectionException.MULTIPLE_HITS:
                self.logger.info("Multiple HITS, retry counter: %s" %
                        self.detect_loop_ttl)
                if self.detect_loop_ttl > 0:
                    # If multiple queues receive packet we cannot tell which one
                    # actually forms a flow. Rarely happens but not an error. Eg.
                    # ARP packets are incoming occasionally and spoil the result.
                    self.detect_loop_ttl -= 1
                    return self.__detect_one_flow(t_gen, d_gen, t_cmd, dport)
                else:
                    assert 0, "Multiple queues receive packets too often." \
                            "DUT port: %s" % dport
            elif fde.state == FlowDetectionException.ZERO_HITS:
                self.logger.info("Zero HITS, ttl: %s" %
                        self.detect_loop_ttl)
                if self.detect_loop_ttl > 0:
                    # Do not resend packets, only try to read statistics once
                    # again. Maybe previous probe was done before they arrived.
                    self.detect_loop_ttl -= 1
                    return self.__detect_one_flow(t_gen, d_gen, t_cmd, dport,
                            send=False)
                else:
                    assert 0, "No queues received packets. DUT port: %s" % port
        # All good
        else:
            return queue_id

    def generate_ports_list(self, dut_conf, tester_conf, total_queues,
            direction):
        # After this function the dut/tester_conf['queue_nb'] will be no higher
        # than `total_queues`. It can be limited by the nb of CPUs on an
        # instance. For `bi` direction it is limited by the half of CPU amount
        # (half for Tx, half for Rx). Pktgen is launched in a passive mode just
        # to observe the association between ports and queues.
        self.init_dut_instance(dut_conf, total_queues)
        self.logger.info("Requested DUT queues: %s, available: %s" %
                (total_queues, dut_conf['queue_nb']))

        ports = self.create_pktgen_flows(tester_conf, dut_conf)
        self.tester.send_expect("^C", "")
        self.tester.scapy_exit()
        self.pktgen_dut.quit()
        self.pktgen_dut.end()
        self.save_ports(ports)

        return ports

    # Sends packets from Tx side to consequtive port numbers of Rx side. For
    # each, it observes which queue received the traffic and records that. The
    # goal is to find a set of ports allowing to occupy all queues available on
    # Rx, that is to create the number of `wanted` distinctive flows.
    # Nevertheless, it can be limited by the `d_conf[queue_nb]` number of
    # queues oferred by HW.
    def create_pktgen_flows(self, tx_conf, rx_conf):
        # pre-compile the pattern
        self.active_que_re = re.compile(r'.*[q](\d+).*= (\d+),')
        self.detect_loop_ttl = 10                       # chosen arbitrarily
        self.flow_npackets = 100
        self.flow_detect_min = self.flow_npackets/2     # chosen arbitrarily
        port_min = int(self.test_configs['BW_port_min'])
        port_max = int(self.test_configs['BW_port_max'])

        # Instances of SoftwarePacketGenerator
        rx_gen = rx_conf['instance']
        tx_gen = tx_conf['instance']
        # Instances of DPDKDut/DPDKTester
        rx_crb = rx_gen.tester     # an unfortunate member name
        tx_crb = tx_gen.tester

        # Do not rely on self.max_queues value as it may no longer be valid
        # there. It can be modified if the test case if bidirectional and the
        # instance is lacking CPU's.
        rxq_num = rx_conf['queue_nb']
        q_to_port = [None] * rxq_num;
        _rx_ports = [None] * rxq_num

        assert (port_min + rxq_num - 1) <= port_max, "Port range is too small"

        # Make sure Tx uses standard Linux driver
        tx_gen.end()
        self.logger.info("Pktgen flows creation: ")

        tx_iface = tx_crb.ports_info[tx_crb.used_port]['intf']
        tx_cmd = 'send([IP(dst="{dip}")/' \
          'TCP(sport={{sport}}, dport={{dport}})/' \
          'Raw(load="P" * 100)] * {n}, iface="{iface}")'.format(
            dip=rx_crb.ports_info[rx_crb.used_port]['ipv4'],
            n=self.flow_npackets, iface=tx_iface)

        # Init scapy on tester to periodically send packets
        tx_crb.scapy_run()
        tx_crb.scapy_send("conf.iface='{}'".format(tx_iface))
        # Discard first stats read, just to zeroize them.
        rx_gen.queue_stats()

        # Find required amount of queues forming unique flows.
        rx_port = port_min
        tx_port = port_min
        wanted = rxq_num
        while wanted > 0:
            queue_id = self.__detect_one_flow(tx_gen, rx_gen,
                    tx_cmd.format(dport=rx_port, sport=tx_port), rx_port)

            assert queue_id is not None

            if q_to_port[queue_id] is None:
                q_to_port[queue_id] = [rx_port, tx_port]
                wanted -= 1
                self.logger.info("Port pair: ({}, {}) associated with queue: {}".format(
                    tx_port, rx_port, queue_id))
            else:
                self.logger.info("Queue {} already occupied. Looking for another one".format(
                        queue_id))
                # Change Tx port only on failure
                tx_port = port_min if tx_port > port_max else tx_port + 1
            # Change Rx port each time
            rx_port = port_min if rx_port > port_max else rx_port + 1

        flows = filter(lambda p: p is not None, q_to_port)

        if wanted != 0:
            self.logger.error("Less than %s flows detected! Expect lower bandwidth" % wanted)
            found = len(flows)
            for i in range(found, rxq_num):
                flows[i] = flows[ i%found ]

        # Now pass only `wanted` number of useful ports
        assert len(flows) == rxq_num, \
            "Number of destination ports is wrong"
        tx_crb.scapy_exit()
        # Prepare a list of lists to be identical to json.loads() (used
        # further) output
        return flows

    def __test_perf_bw(self, ports=None, stress=None):
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
            flow_list = [1, total_queues]
        else:
            flow_list = self.test_configs["BW_flows"].split(",")
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
        ports_lists = []

        tester_conf = {
            'instance'  : self.pktgen_tester,
            'tx_flow'   : self.test_configs["BW_tx_flow"],
            'f_pcap'    : PCAP_FILENAME_SUFFIX,
            'queue_nb'  : total_queues,     # verified by init_XXX_instance(s)
        }
        dut_conf = {
            'instance'  : self.pktgen_dut,
            'tx_flow'   : False,
            'f_pcap'    : None,             # pktgen cmd won't have '-s 0:...'
            'queue_nb'  : total_queues,     # verified by init_XXX_instance(s)
        }

        if direction == "mono":
            self.logger.info('Direction: mono')
            if self.test_configs["two_way_mono"] is False:
                table_hdrs = ['direction','size', 'flows',
                        'Tx queues DUT / Tester', 'type',
                        'Rx on DUT, Mb/s', 'Rx on DUT, pps'
                        ]
            else:
                # This case is only used internally for debug purposes. Not
                # relevant for a regular test suite execution
                table_hdrs = ['direction','size', 'flows',
                        'Tx queues DUT / Tester', 'type',
                        'Tx on Tester, Mb/s', 'Rx on Tester, Mb/s',
                        'Tx on DUT, Mb/s', 'Rx on DUT, Mb/s',
                        'Tx on Tester, pps', 'Rx on Tester, pps',
                        'Tx on DUT, pps', 'Rx on DUT, pps',
                        ]

            tester_conf['mode'] = 'tx'
            dut_conf['mode'] = 'rx'

        else:
            self.logger.info('Direction: bi')
            table_hdrs = ['direction','size', 'flows',
                    'Tx queues DUT / Tester', 'type',
                    'Rx on DUT, Mb/s',
                    'Rx on Tester, Mb/s',
                    'Rx on DUT, pps',
                    'Rx on Tester, pps'
                    ]

            tester_conf['mode'] = 'bi'
            dut_conf['mode'] = 'bi'

        if ports is None:
            # Do not limit Tx rates for queues detection step
            ports = self.generate_ports_list(dut_conf, tester_conf,
                    total_queues, direction)

        for flows_nb in flow_list:
            flows_nb = int(flows_nb)
            if flows_nb < 1:
                raise ValueError("Less than 1 flow makes no sense.")
            if flows_nb <= dut_conf['queue_nb']:
                ports_lists.append(ports[0:flows_nb])
            else:
                self.logger.info("Requested number of flows: %s is" \
                        "larger than %s available queues" %
                        (flows_nb, dut_conf['queue_nb']))
                ports_lists.append(ports * (int(flows_nb) / len(ports)) \
                        + ports[0:(int(flows_nb) % len(ports))])

        if direction == "mono":
            traffic = self.mono_traffic
            tester_conf['tx_rates'] = self.test_configs['tx_rates']
            dut_conf['tx_rates'] = DEFAULT_QUEUE_TX_RATE
        elif direction == "bi":
            traffic = self.bi_traffic
            # Compensate the parameters forbidden before generate_ports_list
            dut_conf['tx_flow'] = self.test_configs["BW_tx_flow"]
            dut_conf['f_pcap'] = PCAP_FILENAME_SUFFIX
            tester_conf['tx_rates'] = self.test_configs['tx_rates']
            dut_conf['tx_rates'] = self.test_configs['tx_rates']

        # NOTE: These are deprecated for now
        # if stress is not None and direction == "tri":
        #     traffic = self.tester2_traffic
        # elif direction == "tri_bi":
        #     traffic = self.tester2_bi_traffic
        # elif direction == "tri_mono":
        #     traffic = self.tester2_mono_traffic

        self.result_table_create(table_hdrs)
        self.pkt_cnts = []

        for pkt_sz in pkt_sizes:
            self.logger.info('\tSize:' + str(pkt_sz))
            for _ports_list in ports_lists:
                for pkt_type in pkt_types:
                    # Reset changes of previous iterations
                    for cnf in [ tester_conf, dut_conf ]:
                        cnf['queue_nb'] = total_queues
                        cnf['d_pcap'] = get_pcap_dirnm(pkt_sz, pkt_type, direction)
                    self.logger.info('\t\tPacket type:' + str(pkt_type))
                    self.logger.info('\t\t\tGenerating pcap file...')
                    self.generate_pcap(_ports_list, pkt_type, pkt_sz, direction)

                    self.logger.info('\t\t\tLaunching the traffic')
                    traffic(tester_conf, dut_conf, measurements_number,
                            interval, pkt_sz, _ports_list, pkt_type)

                    if direction == "mono" and self.test_configs["two_way_mono"]:
                        _d_conf = dut_conf.copy()
                        _t_conf = tester_conf.copy()
                        _d_conf['mode'] = 'tx'
                        _t_conf['mode'] = 'rx'
                        _d_conf['tx_flow'] = _t_conf['tx_flow']
                        _t_conf['tx_flow'] = False
                        _d_conf['f_pcap'] = PCAP_FILENAME_SUFFIX
                        _d_conf['tx_rates'] = self.test_configs['tx_rates']
                        _t_conf['tx_rates'] = DEFAULT_QUEUE_TX_RATE

                        self.mono_traffic_reverse(_t_conf, _d_conf,
                                measurements_number, interval, pkt_sz,
                                _ports_list, pkt_type)

        self.pktgen_tester.end()
        self.pktgen_dut.end()
        self.result_table_print()

        if direction == "tri_mono" or direction == "tri_bi":
            self.result_table_create(['size', 'queues', 'type', 'DUT Tx', "DUT Rx",
                                      "Tester1 Tx", "Tester1 Rx", "Tester2 Tx",
                                      "Tester2 Rx"])
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

            for r in self.pkt_cnts:
                self.result_table_add(r)
            self.result_table_print()

    def get_ports_filename(self):
        t_port = self.tester.used_port
        d_port = self.dut.used_port
        out = 'ports_{tip}_{tmac}_{dip}_{dmac}'.format(
                tip=self.tester.get_ipv4_address(t_port),
                tmac=self.tester.get_mac_address(t_port),
                dip=self.dut.get_ipv4_address(d_port),
                dmac=self.dut.get_mac_address(d_port),
                )
        return out

    def save_ports(self, ports):
        fname = self.get_ports_filename()
        self.tester.save_file(fname,json.dumps(ports))
        self.logger.info("Ports list saved to {}".format(fname))

    def load_ports_from_file(self):
        out = None
        fname = self.get_ports_filename()

        if self.tester.path_exist(fname) is True:
            data = self.tester.send_expect("cat {}".format(fname), "# ")
            try:
                data = json.loads(data)
            except:
                self.logger.error("Reading file {} failed." \
                        "Ports list will be generated from scratch".format(fname))
            else:
                if type(data) is type([]) and len(data) == self.max_queue:
                    out = data

        # Even if pcap files would be found, it is not sure whether they are
        # valid ones if the ports list file was not found.
        if out is None:
            self.test_configs['try_reuse_pcaps'] = False

        return out

    def test_perf_bw(self, ports=None, stress=None):
        if ports is None and self.test_configs['force_setup'] is False:
                ports = self.load_ports_from_file()

        self.__test_perf_bw(ports=ports)

    def init_dut_instance(self, d_dict, queue_nb):
        burst_rate = 100
        start_timeout = 2

        d_inst = d_dict['instance']
        d_dict['tx_rates'] = DEFAULT_QUEUE_TX_RATE
        _q_num = d_inst.init(self.port_dut, self.port_dut, d_dict,
                burst_rate)
        d_dict['queue_nb'] = _q_num

        time.sleep(start_timeout)

    def init_pktgen_instances(self, t_dict, d_dict, ports_list):
        burst_rate = 100
        start_timeout = 2
        flows = len(ports_list)

        t_inst = t_dict['instance']
        _q_num = t_inst.init(self.port_tester, self.port_tester, t_dict,
                burst_rate, ports_list)
        t_dict['queue_nb'] = _q_num

        d_inst = d_dict['instance']
        _q_num = d_inst.init(self.port_dut, self.port_dut, d_dict,
                burst_rate, ports_list)
        d_dict['queue_nb'] = _q_num

        time.sleep(start_timeout)

    def mono_traffic(self, t_conf, d_conf, msr_nb, interval, size, ports_list,
            pkt_type):
        t_gen = t_conf['instance']
        d_gen = d_conf['instance']
        flows = len(ports_list)

        self.init_pktgen_instances(t_conf, d_conf, ports_list)

        stats_dict = self.generate_mono_traffic(t_gen, d_gen,
                msr_nb, interval)
        t_gen.quit()
        d_gen.quit()

        parsed_stats = stats_dict['parsed_stats']
        avg_tx_tester = stats_dict['avg_tx_stats']
        avg_rx_dut = stats_dict['avg_rx_stats']

        avg_rx_Mbps_dut = \
            (8 * avg_rx_dut['rx_bytes'] / 1000000) / avg_rx_dut['rx_delay_sec']
        avg_rx_pps_dut = avg_rx_dut['rx_pkt'] / avg_rx_dut['rx_delay_sec']

        avg_tx_Mbps_tester = \
            (8 * avg_tx_tester['tx_bytes'] / 1000000) / avg_tx_tester['tx_delay_sec']
        avg_tx_pps_tester = avg_tx_tester['tx_pkt'] / avg_tx_tester['tx_delay_sec']

        _q_str = "{} / {}".format(0, t_conf['queue_nb'])
        pkts = ['Tester -> DUT', size, flows, _q_str, pkt_type] + parsed_stats[:]
        self.pkt_cnts.append(pkts)

        if self.test_configs["two_way_mono"] is False:
            self.result_table_add(['Tester -> DUT',size, flows,
                _q_str,
                pkt_type,
                avg_rx_Mbps_dut, avg_rx_pps_dut,
                ])
        else:
            self.result_table_add(['Tester -> DUT', size, flows,
                _q_str,
                pkt_type,
                avg_tx_Mbps_tester, 0,
                0, avg_rx_Mbps_dut,
                avg_tx_pps_tester, 0,
                0, avg_rx_pps_dut,
                ])

    # Only invoked if 'two_way_mono' is True. Configuration dictionaries are
    # copies as the original ones are may still be needed after this function
    # returns (in next iterations of the caller's loop)
    def mono_traffic_reverse(self, t_conf, d_conf, msr_nb, interval, size,
            ports_list, pkt_type):

        t_gen = t_conf['instance']
        d_gen = d_conf['instance']
	flows = len(ports_list)

        self.init_pktgen_instances(t_conf, d_conf, ports_list)

        # The traffic direction in backward: DUT -> Tester
        stats_dict = self.generate_mono_traffic(d_gen, t_gen, msr_nb, interval,
                is_backward=True)

        parsed_stats = stats_dict['parsed_stats']
        avg_tx_dut = stats_dict['avg_tx_stats']
        avg_rx_tester = stats_dict['avg_rx_stats']

        avg_rx_Mbps_tester = \
            (8 * avg_rx_tester['rx_bytes'] / 1000000) / avg_rx_tester['rx_delay_sec']
        avg_rx_pps_tester = avg_rx_tester['rx_pkt'] / avg_rx_tester['rx_delay_sec']

        avg_tx_Mbps_dut = \
            (8 * avg_tx_dut['tx_bytes'] / 1000000) / avg_tx_dut['tx_delay_sec']
        avg_tx_pps_dut = avg_tx_dut['tx_pkt'] / avg_tx_dut['tx_delay_sec']

        t_gen.quit()
        d_gen.quit()

        # Only printed if 'two_way_mono' is True
        _q_str = "{} / {}".format(d_conf['queue_nb'], 0)
        self.result_table_add(['DUT -> Tester',size, flows,
            _q_str,
            pkt_type,
            0, avg_rx_Mbps_tester,
            avg_tx_Mbps_dut, 0,
            0, avg_rx_pps_tester,
            avg_tx_pps_dut, 0,
            ])

        _q_str = "{} / {}".format(d_conf['queue_nb'], 0)
        pkts = ['DUT -> Tester', size, flows, _q_str, pkt_type] + parsed_stats[:]
        self.pkt_cnts.append(pkts)

    def bi_traffic(self, t_conf, d_conf, msr_nb, interval, size, ports_list,
            pkt_type):

        t_gen = t_conf['instance']
        d_gen = d_conf['instance']
        flows = len(ports_list)

        self.init_pktgen_instances(t_conf, d_conf, ports_list)

        stats_dict = self.generate_bi_traffic(t_gen, d_gen, msr_nb, interval)
        t_gen.quit()
        d_gen.quit()

        parsed_stats = stats_dict['parsed_stats']
        avg_t_pc = stats_dict['avg_tester_stats']
        avg_d_pc = stats_dict['avg_dut_stats']

        avg_d_tx_Mbps = \
            (8 * avg_d_pc['tx_bytes'] / 1000000) / avg_d_pc['tx_delay_sec']
        avg_d_tx_pps = avg_d_pc['tx_pkt'] / avg_d_pc['tx_delay_sec']

        avg_t_rx_Mbps = \
            (8 * avg_t_pc['rx_bytes'] / 1000000) / avg_t_pc['rx_delay_sec']
        avg_t_rx_pps = avg_t_pc['rx_pkt'] / avg_t_pc['rx_delay_sec']

        avg_d_rx_Mbps = \
            (8 * avg_d_pc['rx_bytes'] / 1000000) / avg_d_pc['rx_delay_sec']
        avg_d_rx_pps = avg_d_pc['rx_pkt'] / avg_d_pc['rx_delay_sec']

        avg_t_tx_Mbps = \
            (8 * avg_t_pc['tx_bytes'] / 1000000) / avg_t_pc['tx_delay_sec']
        avg_t_tx_pps = avg_t_pc['tx_pkt'] / avg_t_pc['tx_delay_sec']

        _q_str = "{} / {}".format(d_conf['queue_nb'], t_conf['queue_nb'])
        self.result_table_add(['Tester <=> DUT', size, flows, _q_str, pkt_type,
            avg_d_rx_Mbps,
            avg_t_rx_Mbps,
            avg_d_rx_pps,
            avg_t_rx_pps
            ])

        pkts = ['Tester <=> DUT', size, flows, _q_str, pkt_type] + parsed_stats
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
                    (missing, 1.0),
                    (tx_pc["tx_err"], 1.0),
                    (rx_pc["rx_err"], 1.0),
                    (rx_pc["rx_drops"], 1.0),
                    (8 * rx_pc["tx_bytes"], rx_pc["tx_delay_sec"]),
                    (8 * tx_pc["rx_bytes"], tx_pc["rx_delay_sec"]),
                    (missing_bw, 1.0),
                    (rx_pc["tx_err"], 1.0),
                    (tx_pc["rx_err"], 1.0),
                    (tx_pc["rx_drops"], 1.0)
                ]]

        elif self.test_configs["BW_direction"] == "mono":
            missing_bw = rx_pc["tx_pkt"] - tx_pc["rx_pkt"]
            if backward is False:
                pkts = [add_unit(p[0] / p[1]) for p in [
                        (8 * tx_pc["tx_bytes"], tx_pc["tx_delay_sec"]),
                        (8 * rx_pc["rx_bytes"], rx_pc["rx_delay_sec"]),
                        (missing, 1.0),
                        (tx_pc["tx_err"], 1.0),
                        (rx_pc["rx_err"], 1.0),
                        (rx_pc["rx_drops"], 1.0),
                        ]]
                # pkts.extend([0,0,0,0,0,0])
                pkts.extend([add_unit(p[0] / p[1]) for p in [
                    (8 * rx_pc["tx_bytes"], rx_pc["rx_delay_sec"]),
                    (8 * tx_pc["rx_bytes"], tx_pc["tx_delay_sec"]),
                    (missing_bw, 1.0),
                    (rx_pc["tx_err"], 1.0),
                    (tx_pc["rx_err"], 1.0),
                    (tx_pc["rx_drops"], 1.0)
                    ]])
            else:
                missing_bw = rx_pc["tx_pkt"] - tx_pc["rx_pkt"]
                # pkts = [0,0,0,0,0,0]
                pkts = [add_unit(p[0] / p[1]) for p in [
                    (8 * rx_pc["tx_bytes"], rx_pc["rx_delay_sec"]),
                    (8 * tx_pc["rx_bytes"], tx_pc["tx_delay_sec"]),
                    (missing_bw, 1.0),
                    (rx_pc["tx_err"], 1.0),
                    (tx_pc["rx_err"], 1.0),
                    (tx_pc["rx_drops"], 1.0)
                        ]]
                pkts.extend([add_unit(p[0] / p[1]) for p in [
                        (8 * tx_pc["tx_bytes"], tx_pc["tx_delay_sec"]),
                        (8 * rx_pc["rx_bytes"], rx_pc["rx_delay_sec"]),
                        (missing, 1.0),
                        (tx_pc["tx_err"], 1.0),
                        (rx_pc["rx_err"], 1.0),
                        (rx_pc["rx_drops"], 1.0),
                        ]])

        return pkts

    def generate_pcap_execute(self, host, pkg, l=8192):
        host.scapy_foreground()
        burst = len(pkg)
        m = l / burst
        m += 1 if l % burst != 0 else 0
        host.scapy_append('wrpcap("{}", ([{}]*{})[:{}])'.format(
            PCAP_FILENAME_SUFFIX, ", ".join(pkg), m, l))
        status = host.scapy_execute()
        self.verify(status == 0, "Error during generating pcap files.")

    # Creates pcap files both on Tester and DUT, although detection of queues
    # were performed only on DUT. We rely on the fact that this is
    # Rx_port-to-queue association is the same on all instances using DPDK.
    def generate_pcap(self, ports, pkt_type, size, direction="mono"):
        pcap_dir = get_pcap_dirnm(size, pkt_type, direction)

        t_ex_pcaps = []
        d_ex_pcaps = []

        # Additionally to start parameters, the 'try_reuse_pcaps' entry can be
        # set to `False` by the `load_ports_from_file`.
        if self.test_configs['force_setup'] is False and \
            self.test_configs['try_reuse_pcaps'] is True:
            self.logger.debug("Trying to reuse pcaps")
            if self.tester.path_exist(pcap_dir):
                find_existing_pcaps(self.tester, t_ex_pcaps, pcap_dir)
            if self.dut.path_exist(pcap_dir):
                find_existing_pcaps(self.dut, d_ex_pcaps, pcap_dir)
        else:
            self.logger.debug("Pcaps cannot be reused")

        self.logger.debug("Pcaps on Tester: {}".format(t_ex_pcaps))
        self.logger.debug("Pcaps on Dut: {}".format(d_ex_pcaps))
        pkg_rx = []     # tests DUT's Rx performance
        for port in ports:
            if port in d_ex_pcaps:
                continue
            self.logger.debug("Rx, needs creation: %s " % port)
            pkg = generate_pcap_string(port, pkt_type, size)
            pkg_rx.append(pkg.format(
                smac=self.smac, dmac=self.dmac,
                sip=self.sip, dip=self.dip))

        pkg_tx = []     # Tx, respectively
        for port in ports:
            if port in t_ex_pcaps:
                continue
            self.logger.debug("Tx, needs creation: %s " % port)
            pkg = generate_pcap_string(port, pkt_type, size)
            pkg_tx.append(pkg.format(
                smac=self.dmac, dmac=self.smac,
                sip=self.dip, dip=self.sip))

        if self.test_configs["BW_tx_flow"]:
            self.pcap_per_queue(ports, pkt_type, size, pcap_dir, t_ex_pcaps,
                    d_ex_pcaps)

    def pcap_per_queue(self, ports, pkt_type, size, pcap_dir, t_ports,
            d_ports):
        # Create directories on both ends if not existing
        self.tester.mk_dir(pcap_dir)
        self.dut.mk_dir(pcap_dir)

        # pcap files are indexed from 0
        t_start = len(t_ports)
        self.logger.debug("t_start: %s" % t_start)
        d_start = len(d_ports)
        self.logger.debug("d_start: %s" % d_start)

        # DUT part
        i = d_start
        for port in ports:
            if port in d_ports:
                continue
            pkg = generate_pcap_string(port, pkt_type, size)
            tx = pkg.format(smac=self.dmac, dmac=self.smac,
                            sip=self.dip, dip=self.sip)
            _p_fpath = gen_pcap_fpath(port, i, pcap_dir)
            self.logger.debug("Generating: %s" % _p_fpath)
            self.dut.scapy_append("wrpcap('{}', [{}]*2048)".format(
                    _p_fpath, tx))
            i += 1

        # Tester part
        i = t_start
        for port in ports:
            if port in t_ports:
                continue
            pkg = generate_pcap_string(port, pkt_type, size)
            rx = pkg.format(smac=self.smac, dmac=self.dmac,
                            sip=self.sip, dip=self.dip)
            _p_fpath = gen_pcap_fpath(port, i, pcap_dir)
            self.logger.debug("Generating: %s" % _p_fpath)
            self.tester.scapy_append("wrpcap('{}', [{}]*2048)".format(
                    _p_fpath, rx))
            i += 1

        for host in [self.tester, self.dut]:
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
        ports = self.get_queues_from_pcap(tester_path)

        # Assumption - Differently to `test_perf_bw`:
        # - `flows` NOT set by the "BW_flows" parameter, determined by the
        #   number of different pairs of ports in packets inside the pcap file,
        # - `total_queues` NOT set by "BW_queue" parameter, primarily equals to
        # `flows` but additionally limited by `self.max_queue`,
        flows = len(ports)

        total_queues = \
            flows if flows <= self.max_queue else self.max_queue
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
            'instance'  : self.pktgen_tester,
            'tx_flow'   : self.test_configs["BW_tx_flow"],
            'f_pcap'    : pcap_tester,
            'queue_nb'  : total_queues,    # filled by init_pktgen_instances
            'pcap_cmd'  : cmd_pcap_path,
        }
        dut_conf = {
            'instance'  : self.pktgen_dut,
            'tx_flow'   : False,
            'f_pcap'    : None,
            'queue_nb'  : total_queues,    # filled by init_pktgen_instances
        }
        # Assumption: this test runs in the 'mono' mode
        tester_conf['mode'] = 'tx'
        dut_conf['mode'] = 'rx'
        direction = 'mono'

        # Nb of flows may surpass self.max_queue but it is always equal to
        # len(ports)
        self.init_pktgen_instances(tester_conf, dut_conf, ports)

        stats_dict = self.generate_mono_traffic(self.pktgen_tester,
                self.pktgen_dut, measurements_number, interval)
        rx_bps_dut = stats_dict['rate_rx_bps']
        rx_pps_dut = stats_dict['rate_rx_pps']
        tx_bps_tester = stats_dict['rate_tx_bps']
        tx_pps_tester = stats_dict['rate_tx_pps']

        self.pktgen_tester.quit()
        self.pktgen_dut.quit()

        self.result_table_create(['direction','size', 'flows',
            'Tx queues DUT / Tester', 'type', 'Rx on DUT, Mb/s',
            'Rx on DUT, pps' ])

        # Packet type and size not known - depends on the pcap contents
        self.result_table_add(['Tester -> DUT', 'N/A', flows,
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
        value /= 1000.0

def find_existing_pcaps(crb_obj, ex_pcaps, p_dir):
    patt = re.compile(r'\d{1,}_([\d]{1,})_([\d]{1,})_*')
    _flist = crb_obj.send_expect("ls -1 {}".format(p_dir), "# ")
    for l in _flist.split('\n'):
        res = patt.search(l)
        if res is not None:
            o = res.groups()
            ex_pcaps.append([int(o[0]), int(o[1])])


def generate_pcap_string(port, pkt_type, size):
    header_size = HEADER_SIZE['eth'] + HEADER_SIZE['ip'] + HEADER_SIZE[pkt_type]
    padding = size - header_size
    pkg = 'Ether(src="{{smac}}", dst="{{dmac}}")/' \
          'IP(src="{{sip}}", dst="{{dip}}")/' \
          '{pkt_type}(sport={sport}, dport={dport})/' \
          'Raw(load="P" * {padding})'\
        .format(pkt_type=pkt_type.upper(), sport=port[0],
                dport=port[1], padding=padding)
    return pkg

def get_pcap_dirnm(size, pkt_type, direction):
    out = 'pcaps_{}_{}_{}'.format(size, pkt_type, direction)
    return out
