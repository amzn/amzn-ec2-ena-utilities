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
 Changes made to the original file:
   * Identify tester also by it's IP
   * Remove private fields:
     - bgProcIsRunning
     - inBg
     - scapyCmds
   * Copy tester specific packages
   * Return tester username using crb config
   * Add methods for Tester class:
     - get_ssh_key
     - get_mac_address (renamed get_mac)
     - get_ipv4_address
   * Remove methods for Tester class:
     - restore_interfaces
     - scapy_append
     - scapy_background
     - scapy_foreground
     - scapy_get_result
   * Remove logs about ports info
   * Remove argument 'kill_all' from the kill_all method
"""

"""
Interface for bulk traffic generators.
"""

import re
import subprocess
from time import sleep
from settings import NICS, load_global_setting, PERF_SETTING
from crb import Crb
from net_device import GetNicObj
from etgen import IxiaPacketGenerator, SoftwarePacketGenerator
from settings import IXIA, USERNAME
from settings import tester_prefix
import random
from utils import GREEN, convert_int2ip, convert_ip2int
from exception import ParameterInvalidException
from multiprocessing import Process


class Tester(Crb):

    """
    Start the DPDK traffic generator on the machine `target`.
    A config file and pcap file must have previously been copied
    to this machine.
    """
    PORT_INFO_CACHE_KEY = 'tester_port_info'
    CORE_LIST_CACHE_KEY = 'tester_core_list'
    NUMBER_CORES_CACHE_KEY = 'tester_number_cores'
    PCI_DEV_CACHE_KEY = 'tester_pci_dev_info'

    def __init__(self, crb, serializer):
        self.NAME = 'tester_{}'.format(crb['tester IP'])
        super(Tester, self).__init__(crb, serializer, self.NAME)

        self.duts = None
        self.bgCmds = []
        self.bgItf = ''
        self.re_run_time = 0

        # To Tester copy Tester packages
        for i in [0, 1]:
            self.packages[i] = tester_prefix + self.packages[i]

    def init_ext_gen(self):
        """
        Initialize tester packet generator object.
        """
        if self.it_uses_external_generator():
            self.ixia_packet_gen = IxiaPacketGenerator(self)
        self.packet_gen = SoftwarePacketGenerator(self)

    def set_re_run(self, re_run_time):
        """
        set failed case re-run time
        """
        self.re_run_time = int(re_run_time)

    def get_ip_address(self):
        """
        Get ip address of tester CRB.
        """
        return self.crb['tester IP']

    def get_username(self):
        """
        Get login username of tester CRB.
        """
        return self.crb['tester_user']

    def get_ssh_key(self):
        """
        Get ssh key for tester CRB.
        """
        return self.crb['tester_ssh_key']

    def get_password(self):
        """
        Get tester login password of tester CRB.
        """
        return self.crb['tester pass']

    def has_external_traffic_generator(self):
        """
        Check whether performance test will base on IXIA equipment.
        """
        try:
            if self.crb[IXIA] is not None:
                return True
        except Exception as e:
            return False

        return False

    def get_external_traffic_generator(self):
        """
        Return IXIA object.
        """
        return self.crb[IXIA]

    def it_uses_external_generator(self):
        """
        Check whether IXIA generator is ready for performance test.
        """
        return load_global_setting(PERF_SETTING) == 'yes' and self.has_external_traffic_generator()

    def tester_prerequisites(self):
        """
        Prerequest function should be called before execute any test case.
        Will call function to scan all lcore's information which on Tester.
        Then call pci scan function to collect nic device information.
        Then discovery the network topology and save it into cache file.
        At last setup DUT' environment for validation.
        """
        self.init_core_list()
        self.pci_devices_information()
        self.restore_interfaces()
        self.scan_ports()

    def get_local_port(self, remotePort):
        """
        Return tester local port connect to specified dut port.
        """
        return self.duts[0].ports_map[remotePort]

    def get_local_port_type(self, remotePort):
        """
        Return tester local port type connect to specified dut port.
        """
        return self.ports_info[self.get_local_port(remotePort)]['type']

    def get_local_port_bydut(self, remotePort, dutIp):
        """
        Return tester local port connect to specified port and specified dut.
        """
        for dut in self.duts:
            if dut.crb['My IP'] == dutIp:
                return dut.ports_map[remotePort]

    def get_local_index(self, pci):
        """
        Return tester local port index by pci id
        """
        index = -1
        for port in self.ports_info:
            index += 1
            if pci == port['pci']:
                return index
        return -1

    def get_pci(self, localPort):
        """
        Return tester local port pci id.
        """
        if localPort == -1:
            raise ParameterInvalidException("local port should not be -1")

        return self.ports_info[localPort]['pci']

    def get_interface(self, localPort):
        """
        Return tester local port interface name.
        """
        if localPort == -1:
            raise ParameterInvalidException("local port should not be -1")

        if 'intf' not in self.ports_info[localPort]:
            return 'N/A'

        return self.ports_info[localPort]['intf']

    def get_mac_address(self, localPort):
        """
        Return tester local port mac address.
        """
        if localPort == -1:
            raise ParameterInvalidException("local port should not be -1")

        if self.ports_info[localPort]['type'] == 'ixia':
            return "00:00:00:00:00:01"
        else:
            return self.ports_info[localPort]['mac']

    def get_ipv4_address(self, localPort):
        """
        Return tester local port IPv4 address
        """
        if localPort == -1:
            raise ParameterInvalidException("local port should not be -1")

        return self.ports_info[localPort]['ipv4']

    def get_port_status(self, port):
        """
        Return link status of ethernet.
        """
        eth = self.ports_info[port]['intf']
        out = self.send_expect("ethtool %s" % eth, "# ")

        status = re.search(r"Link detected:\s+(yes|no)", out)
        if not status:
            self.logger.error("ERROR: unexpected output")

        if status.group(1) == 'yes':
            return 'up'
        else:
            return 'down'

    def set_promisc(self):
        try:
            for (pci_bus, pci_id) in self.pci_devices_info:
                addr_array = pci_bus.split(':')
                port = GetNicObj(self, addr_array[0], addr_array[1], addr_array[2])
                itf = port.get_interface_name()
                self.enable_promisc(itf)
                if port.get_interface2_name():
                    itf = port.get_interface2_name()
                    self.enable_promisc(itf)
        except Exception as e:
            pass

    def load_serializer_ports(self):
        cached_ports_info = self.serializer.load(self.PORT_INFO_CACHE_KEY)
        if cached_ports_info is None:
            return

        # now not save netdev object, will implemented later
        self.ports_info = cached_ports_info

    def save_serializer_ports(self):
        cached_ports_info = []
        for port in self.ports_info:
            port_info = {}
            for key in port.keys():
                if type(port[key]) is str:
                    port_info[key] = port[key]
                # need save netdev objects
            cached_ports_info.append(port_info)
        self.serializer.save(self.PORT_INFO_CACHE_KEY, cached_ports_info)

    def scan_ports(self):
        """
        Scan all ports on tester and save port's pci/mac/interface.
        """
        self.restore_interfaces()
        if self.read_cache:
            self.load_serializer_ports()
            self.scan_ports_cached()

        if not self.read_cache or self.ports_info is None:
            self.scan_ports_uncached()
            if self.it_uses_external_generator():
                self.ports_info.extend(self.ixia_packet_gen.get_ports())
            self.save_serializer_ports()

    def scan_ports_cached(self):
        if self.ports_info is None:
            return

        for port_info in self.ports_info:
            if port_info['type'] == 'ixia':
                continue

            addr_array = port_info['pci'].split(':')
            domain_id = addr_array[0]
            bus_id = addr_array[1]
            devfun_id = addr_array[2]

            port = GetNicObj(self, domain_id, bus_id, devfun_id)
            intf = port.get_interface_name()

            self.logger.info("Tester cached: [000:%s %s] %s" % (
                             port_info['pci'], port_info['type'], intf))
            port_info['port'] = port

    def scan_ports_uncached(self):
        """
        Return tester port pci/mac/interface information.
        """
        self.ports_info = []

        for (pci_bus, pci_id) in self.pci_devices_info:
            # ignore unknown card types
            if pci_id not in NICS.values():
                self.logger.info("Tester: [%s %s] %s" % (pci_bus, pci_id,
                                                             "unknow_nic"))
                continue

            addr_array = pci_bus.split(':')
            domain_id = addr_array[0]
            bus_id = addr_array[1]
            devfun_id = addr_array[2]

            port = GetNicObj(self, domain_id, bus_id, devfun_id)
            intf = port.get_interface_name()

            if "No such file" in intf:
                self.logger.info("Tester: [%s %s] %s" % (pci_bus, pci_id,
                                                             "unknow_interface"))
                continue

            self.logger.info("Tester: [%s %s] %s" % (pci_bus, pci_id, intf))
            macaddr = port.get_mac_addr()

            ipv6 = port.get_ipv6_addr()
            ipv4 = port.get_ipv4_addr()

            # store the port info to port mapping
            self.ports_info.append({'port': port,
                                    'pci': pci_bus,
                                    'type': pci_id,
                                    'intf': intf,
                                    'mac': macaddr,
				    'ipv4': ipv4,
                                    'ipv6': ipv6})

            # return if port is not connect x3
            if not port.get_interface2_name():
                continue

            intf = port.get_interface2_name()

            self.logger.info("Tester: [%s %s] %s" % (pci_bus, pci_id, intf))
            macaddr = port.get_intf2_mac_addr()

            ipv6 = port.get_ipv6_addr()

            # store the port info to port mapping
            self.ports_info.append({'port': port,
                                    'pci': pci_bus,
                                    'type': pci_id,
                                    'intf': intf,
                                    'mac': macaddr,
                                    'ipv6': ipv6})

    def send_ping(self, localPort, ipv4, mac):
        """
        Send ping6 packet from local port with destination ipv4 address.
        """
        if self.ports_info[localPort]['type'] == 'ixia':
            return "Not implemented yet"
        else:
            return self.send_expect("ping -w 5 -c 5 -A -I %s %s" % (self.ports_info[localPort]['intf'], ipv4), "# ", 10)

    def send_ping6(self, localPort, ipv6, mac):
        """
        Send ping6 packet from local port with destination ipv6 address.
        """
        if self.ports_info[localPort]['type'] == 'ixia':
            return self.ixia_packet_gen.send_ping6(self.ports_info[localPort]['pci'], mac, ipv6)
        else:
            return self.send_expect("ping6 -w 5 -c 5 -A %s%%%s" % (ipv6, self.ports_info[localPort]['intf']), "# ", 10)

    def get_port_numa(self, port):
        """
        Return tester local port numa.
        """
        pci = self.ports_info[port]['pci']
        out = self.send_expect("cat /sys/bus/pci/devices/%s/numa_node" % pci, "#")
        return int(out)

    def check_port_list(self, portList, ftype='normal'):
        """
        Check specified port is IXIA port or normal port.
        """
        dtype = None
        plist = set()
        for txPort, rxPort, _ in portList:
            plist.add(txPort)
            plist.add(rxPort)

        plist = list(plist)
        if len(plist) > 0:
            dtype = self.ports_info[plist[0]]['type']

        for port in plist[1:]:
            if dtype != self.ports_info[port]['type']:
                return False

        if ftype == 'ixia' and dtype != ftype:
            return False

        return True

    def traffic_generator_throughput(self, portList, rate_percent=100, delay=5):
        """
        Run throughput performance test on specified ports.
        """
        if self.check_port_list(portList, 'ixia'):
            return self.ixia_packet_gen.throughput(portList, rate_percent, delay)
        if not self.check_port_list(portList):
            self.logger.warning("exception by mixed port types")
            return None
        return self.packet_gen.throughput(portList, rate_percent)

    def verify_packet_order(self, portList, delay):
        if self.check_port_list(portList, 'ixia'):
            return self.ixia_packet_gen.is_packet_ordered(portList, delay)
        else:
            self.logger.warning("Only ixia port support check verify packet order function")
            return False

    def run_rfc2544(self, portlist, delay=120, permit_loss_rate=0):
        """
        test_rate: the line rate we are going to test.
        """
        test_rate = float(100)

        self.logger.info("test rate: %f " % test_rate)
        loss_rate, tx_num, rx_num = self.traffic_generator_loss(portlist, test_rate, delay)
        while loss_rate > permit_loss_rate:
                test_rate = float(1 - loss_rate) * test_rate
                loss_rate, tx_num, rx_num = self.traffic_generator_loss(portlist, test_rate, delay)

        self.logger.info("zero loss rate is %s" % test_rate)
        return test_rate, tx_num, rx_num


    def traffic_generator_loss(self, portList, ratePercent, delay=60):
        """
        Run loss performance test on specified ports.
        """
        if self.check_port_list(portList, 'ixia'):
            return self.ixia_packet_gen.loss(portList, ratePercent, delay)
        elif not self.check_port_list(portList):
            self.logger.warning("exception by mixed port types")
            return None
        return self.packet_gen.loss(portList, ratePercent, delay)

    def traffic_generator_latency(self, portList, ratePercent=100, delay=5):
        """
        Run latency performance test on specified ports.
        """
        if self.check_port_list(portList, 'ixia'):
            return self.ixia_packet_gen.latency(portList, ratePercent, delay)
        else:
            return None

    def parallel_transmit_ptks(self, send_f=None, intf='', pkts=[], interval=0.01):
        """
        Callable function for parallel processes
        """
        print GREEN("Transmitting and sniffing packets, please wait few minutes...")
        send_f(intf=intf, pkts=pkts, interval=interval)

    def check_random_pkts(self, portList, pktnum=2000, interval=0.01, allow_miss=True, seq_check=False, params=None):
        """
        Send several random packets and check rx packets matched
        """
        # load functions in packet module
        module = __import__("packet")
        pkt_c = getattr(module, "Packet")
        send_f = getattr(module, "send_packets")
        sniff_f = getattr(module, "sniff_packets")
        load_f = getattr(module, "load_sniff_packets")
        compare_f = getattr(module, "compare_pktload")
        strip_f = getattr(module, "strip_pktload")
        save_f = getattr(module, "save_packets")
        tx_pkts = {}
        rx_inst = {}
        # packet type random between tcp/udp/ipv6
        random_type = ['TCP', 'UDP', 'IPv6_TCP', 'IPv6_UDP']
        pkt_minlen = {'TCP': 64, 'UDP': 64, 'IPv6_TCP': 74, 'IPv6_UDP': 64}
        # at least wait 2 seconds
        timeout = int(pktnum * (interval + 0.01)) + 2
        for txport, rxport in portList:
            pkts = []
            txIntf = self.get_interface(txport)
            rxIntf = self.get_interface(rxport)
            print GREEN("Preparing transmit packets, please wait few minutes...")
            for num in range(pktnum):
                # chose random packet
                pkt_type = random.choice(random_type)
                pkt = pkt_c(pkt_type=pkt_type,
                            pkt_len=random.randint(pkt_minlen[pkt_type], 1514),
                            ran_payload=True)
                # config packet if has parameters
                if params and len(portList) == len(params):
                    for param in params:
                        layer, config = param
                        pkt.config_layer(layer, config)
                # hardcode src/dst port for some protocal may cause issue
                if "TCP" in pkt_type:
                    pkt.config_layer('tcp', {'src': 65535, 'dst': 65535})
                else:
                    pkt.config_layer('udp', {'src': 65535, 'dst': 65535})
                # sequence saved in layer3 source ip
                if "IPv6" in pkt_type:
                    ip_str = convert_int2ip(num, 6)
                    pkt.config_layer('ipv6', {'src': ip_str})
                else:
                    ip_str = convert_int2ip(num, 4)
                    pkt.config_layer('ipv4', {'src': ip_str})

                pkts.append(pkt)
            tx_pkts[txport] = pkts

            # send and sniff packets
            save_f(pkts=pkts, filename="/tmp/%s_tx.pcap" % txIntf)
            inst = sniff_f(intf=rxIntf, count=pktnum, timeout=timeout)
            rx_inst[rxport] = inst

        # Transmit packet simultaneously
        processes = []
        for txport, _ in portList:
            txIntf = self.get_interface(txport)
            processes.append(Process(target = self.parallel_transmit_ptks,
                             args=(send_f, txIntf, tx_pkts[txport], interval)))

        for transmit_proc in processes:
            transmit_proc.start()

        for transmit_proc in processes:
            transmit_proc.join()

        # Verify all packets
        prev_id = -1
        for txport, rxport in portList:
            recv_pkts = load_f(rx_inst[rxport])

            # only report when recevied number not matched
            if len(tx_pkts[txport]) > len(recv_pkts):
                print ("Pkt number not matched,%d sent and %d received\n" \
                       % (len(tx_pkts[txport]), len(recv_pkts)))

                if allow_miss is False:
                    return False

            # check each received packet content
            print GREEN("Comparing sniffed packets, please wait few minutes...")
            for idx in range(len(recv_pkts)):
                try:
                    l3_type = recv_pkts[idx].strip_element_layer2('type')
                    sip = recv_pkts[idx].strip_element_layer3('src')
                except:
                    continue
                # ipv4 packet
                if l3_type == 2048:
                    t_idx = convert_ip2int(sip, 4)
                # ipv6 packet
                elif l3_type == 34525:
                    t_idx = convert_ip2int(sip, 6)
                else:
                    continue

                if seq_check:
                    if t_idx <= prev_id:
                        print "Packet %d sequence not correct" % t_idx
                        return False
                    else:
                        prev_id = t_idx

                if compare_f(tx_pkts[txport][t_idx], recv_pkts[idx], "L4") is False:
                    print "Pkt recevied index %d not match original " \
                          "index %d" % (idx, t_idx)
                    print "Sent: %s" % strip_f(tx_pkts[txport][t_idx], "L4")
                    print "Recv: %s" % strip_f(recv_pkts[idx], "L4")
                    return False

        return True

    def extend_external_packet_generator(self, clazz, instance):
        """
        Update packet generator function, will implement later.
        """
        if self.it_uses_external_generator():
            self.ixia_packet_gen.__class__ = clazz
            current_attrs = instance.__dict__
            instance.__dict__ = self.ixia_packet_gen.__dict__
            instance.__dict__.update(current_attrs)

    def sendpkt_bg(self, localPort, dst_mac):
        """
        loop to Send packet in background, should call stop_sendpkt_bg to stop it.
        """
        itf = self.get_interface(localPort)
        src_mac = self.get_mac_address(localPort)
        script_str = "from scapy.all import *\n" + \
                     "sendp([Ether(dst='%s', src='%s')/IP(len=46)], iface='%s', loop=1)\n" % (dst_mac, src_mac, itf)

        self.send_expect("rm -fr send_pkg_loop.py", "# ")
        f = open("send_pkt_loop.py", "w")
        f.write(script_str)
        f.close()

        self.proc = subprocess.Popen(['python', 'send_pkt_loop.py'])

    def stop_sendpkt_bg(self):
        """
        stop send_pkt_loop in background
        """
        if self.proc:
            self.proc.kill()
            self.proc = None

    def kill_all(self):
        """
        Kill all scapy process or DPDK application on tester.
        """
        if not self.has_external_traffic_generator():
            self.alt_session.send_expect('killall scapy 2>/dev/null; echo tester', '# ', 5)

    def close(self):
        """
        Close ssh session and IXIA tcl session.
        """
        if self.session:
            self.session.close()
            self.session = None
        if self.alt_session:
            self.alt_session.close()
            self.alt_session = None
        if self.it_uses_external_generator():
            self.ixia_packet_gen.close()

    def crb_exit(self):
        """
        Close all resource before crb exit
        """
        self.logger.logger_exit()
        self.close()
