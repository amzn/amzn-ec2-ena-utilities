#!/usr/bin/python
# BSD LICENSE
#
# Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
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
   * Set as none at SCAPY_LAYERS:
     - etag
     - lldp
     - nvgre
   * Rework some documentation comments
   * Rework some error logs
"""

"""
Generic packet create, transmit and analyze module
Base on scapy(python program for packet manipulation)
"""

import os
import time
import sys
import re
import signal
import random
import subprocess
import shlex        # separate command line for pipe
from uuid import uuid4
from settings import FOLDERS

from scapy.config import conf
conf.use_pcap = True

import struct
from socket import AF_INET6
from scapy.all import conf
from scapy.utils import wrpcap, rdpcap, hexstr
from scapy.layers.inet import Ether, IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrRouting, IPv6ExtHdrFragment
from scapy.layers.l2 import Dot1Q, ARP, GRE
from scapy.layers.sctp import SCTP, SCTPChunkData
from scapy.sendrecv import sniff
from scapy.route import *
from scapy.packet import bind_layers, Raw
from scapy.sendrecv import sendp
from scapy.arch import get_if_hwaddr

# load extension layers
exec_file = os.path.realpath(__file__)
DTS_PATH = exec_file.replace('/framework/packet.py', '')
DEP_FOLDER = DTS_PATH + '/dep'
sys.path.append(DEP_FOLDER)

from vxlan import Vxlan

# packet generator type should be configured later
PACKETGEN = "scapy"

LayersTypes = {
    "L2": ['ether', 'vlan', 'etag', '1588', 'arp', 'lldp'],
    # ipv4_ext_unknown, ipv6_ext_unknown
    "L3": ['ipv4', 'ipv4ihl', 'ipv6', 'ipv4_ext', 'ipv6_ext', 'ipv6_ext2', 'ipv6_frag'],
    "L4": ['tcp', 'udp', 'frag', 'sctp', 'icmp', 'nofrag'],
    "TUNNEL": ['ip', 'gre', 'vxlan', 'nvgre', 'geneve', 'grenat'],
    "INNER L2": ['inner_mac', 'inner_vlan'],
    # inner_ipv4_unknown, inner_ipv6_unknown
    "INNER L3": ['inner_ipv4', 'inner_ipv4_ext', 'inner_ipv6', 'inner_ipv6_ext'],
    "INNER L4": ['inner_tcp', 'inner_udp', 'inner_frag', 'inner_sctp', 'inner_icmp', 'inner_nofrag'],
    "PAYLOAD": ['raw']
}

# Saved back groud sniff process id
SNIFF_PIDS = {}

# Saved packet generator process id
# used in pktgen or tgen
PKTGEN_PIDS = {}

# default filter for LLDP packet
LLDP_FILTER = {'layer': 'ether', 'config': {'type': 'not lldp'}}


class scapy(object):
    SCAPY_LAYERS = {
        'ether': Ether(dst="ff:ff:ff:ff:ff:ff"),
        'vlan': Dot1Q(),
        'etag': None,
        '1588': Ether(type=0x88f7),
        'arp': ARP(),
        'ipv4': IP(),
        'ipv4ihl': IP(ihl=10),
        'ipv4_ext': IP(frag=5),
        'ipv6': IPv6(src="::1"),
        'ipv6_ext': IPv6(src="::1", nh=43) / IPv6ExtHdrRouting(),
        'ipv6_ext2': IPv6() / IPv6ExtHdrRouting(),
        'udp': UDP(),
        'tcp': TCP(),
        'sctp': SCTP(),
        'icmp': ICMP(),
        'gre': GRE(),
        'raw': Raw(),
        'vxlan': Vxlan(),

        'inner_mac': Ether(),
        'inner_vlan': Dot1Q(),
        'inner_ipv4': IP(),
        'inner_ipv4_ext': IP(),
        'inner_ipv6': IPv6(src="::1"),
        'inner_ipv6_ext': IPv6(src="::1"),

        'inner_tcp': TCP(),
        'inner_udp': UDP(),
        'inner_sctp': SCTP(),
        'inner_icmp': ICMP(),

        'lldp': None,
        'ip_frag': IP(frag=5),
        'ipv6_frag': IPv6(src="::1") / IPv6ExtHdrFragment(),
        'ip_in_ip': IP() / IP(),
        'ip_in_ip_frag': IP() / IP(frag=5),
        'ipv6_in_ip': IP() / IPv6(src="::1"),
        'ipv6_frag_in_ip': IP() / IPv6(src="::1", nh=44) / IPv6ExtHdrFragment(),
        'nvgre': None,
        'geneve': "Not Implement",
    }

    def __init__(self):
        self.pkt = None
        pass

    def assign_pkt(self, pkt):
        self.pkt = pkt

    def add_layers(self, layers):
        self.pkt = None
        for layer in layers:
            if self.pkt is not None:
                self.pkt = self.pkt / self.SCAPY_LAYERS[layer]
            else:
                self.pkt = self.SCAPY_LAYERS[layer]

    def ether(self, pkt_layer, dst="ff:ff:ff:ff:ff:ff", src="00:00:20:00:00:00", type=None):
        if pkt_layer.name != "Ethernet":
            return
        pkt_layer.dst = dst
        pkt_layer.src = src
        if type is not None:
            pkt_layer.type = type

    def vlan(self, pkt_layer, vlan, prio=0, type=None):
        if pkt_layer.name != "802.1Q":
            return
        pkt_layer.vlan = int(vlan)
        pkt_layer.prio = prio
        if type is not None:
            pkt_layer.type = type

    def strip_vlan(self, element):
        value = None

        if self.pkt.haslayer('Dot1Q') is 0:
            return None

        if element == 'vlan':
            value = int(str(self.pkt[Dot1Q].vlan))
        return value

    def etag(self, pkt_layer, ECIDbase=0, prio=0, type=None):
        if pkt_layer.name != "802.1BR":
            return
        pkt_layer.ECIDbase = int(ECIDbase)
        pkt_layer.prio = prio
        if type is not None:
            pkt_layer.type = type

    def strip_etag(self, element):
        value = None

        if self.pkt.haslayer('Dot1BR') is 0:
            return None

        if element == 'ECIDbase':
            value = int(str(self.pkt[Dot1BR].ECIDbase))
        return value

    def strip_layer2(self, element):
        value = None
        layer = self.pkt.getlayer(0)
        if layer is None:
            return None

        if element == 'src':
            value = layer.src
        elif element == 'dst':
            value = layer.dst
        elif element == 'type':
            value = layer.type

        return value

    def strip_layer3(self, element):
        value = None
        layer = self.pkt.getlayer(1)
        if layer is None:
            return None

        if element == 'src':
            value = layer.src
        elif element == 'dst':
            value = layer.dst
        else:
            value = layer.getfieldval(element)

        return value

    def strip_layer4(self, element):
        value = None
        layer = self.pkt.getlayer(2)
        if layer is None:
            return None

        if element == 'src':
            value = layer.sport
        elif element == 'dst':
            value = layer.dport
        else:
            value = layer.getfieldval(element)

        return value

    def ipv4(self, pkt_layer, frag=0, src="127.0.0.1", proto=None, tos=0, dst="127.0.0.1", chksum=None, len=None, version=4, flags=None, ihl=None, ttl=64, id=1, options=None):
        pkt_layer.frag = frag
        pkt_layer.src = src
        if proto is not None:
            pkt_layer.proto = proto
        pkt_layer.tos = tos
        pkt_layer.dst = dst
        if chksum is not None:
            pkt_layer.chksum = chksum
        if len is not None:
            pkt_layer.len = len
        pkt_layer.version = version
        if flags is not None:
            pkt_layer.flags = flags
        if ihl is not None:
            pkt_layer.ihl = ihl
        pkt_layer.ttl = ttl
        pkt_layer.id = id
        if options is not None:
            pkt_layer.options = options

    def ipv6(self, pkt_layer, version=6, tc=0, fl=0, plen=0, nh=0, hlim=64, src="::1", dst="::1"):
        """
        Configure IPv6 protocal.
        """
        pkt_layer.version = version
        pkt_layer.tc = tc
        pkt_layer.fl = fl
        if plen:
            pkt_layer.plen = plen
        if nh:
            pkt_layer.nh = nh
        pkt_layer.src = src
        pkt_layer.dst = dst

    def tcp(self, pkt_layer, src=53, dst=53, flags=None, len=None, chksum=None):
        pkt_layer.sport = src
        pkt_layer.dport = dst
        if flags is not None:
            pkt_layer.flags = flags
        if len is not None:
            pkt_layer.len = len
        if chksum is not None:
            pkt_layer.chksum = chksum

    def udp(self, pkt_layer, src=53, dst=53, len=None, chksum=None):
        pkt_layer.sport = src
        pkt_layer.dport = dst
        if len is not None:
            pkt_layer.len = len
        if chksum is not None:
            pkt_layer.chksum = chksum

    def sctp(self, pkt_layer, src=53, dst=53, tag=None, len=None, chksum=None):
        pkt_layer.sport = src
        pkt_layer.dport = dst
        if tag is not None:
            pkt_layer.tag = tag
        if len is not None:
            pkt_layer.len = len
        if chksum is not None:
            pkt_layer.chksum = chksum

    def raw(self, pkt_layer, payload=None):
        if payload is not None:
            pkt_layer.load = ''
            for hex1, hex2 in payload:
                pkt_layer.load += struct.pack("=B", int('%s%s' % (hex1, hex2), 16))

    def gre(self, pkt_layer, proto=None):
        if proto is not None:
            pkt_layer.proto = proto

    def vxlan(self, pkt_layer, vni=0):
        pkt_layer.vni = vni

    def read_pcap(self, file):
        pcap_pkts = []
        try:
            pcap_pkts = rdpcap(file)
        except:
            pass

        return pcap_pkts

    def write_pcap(self, file):
        try:
            wrpcap(file, self.pkt)
        except:
            pass

    def send_pcap_pkt(self, crb=None, file='', intf='', count=1):
        if intf == '' or file == '' or crb is None:
            print "Invalid option for send packet by scapy"
            return

        content = 'pkts=rdpcap(\"%s\");sendp(pkts, iface=\"%s\", count=\"%s\" );exit()' % (file, intf, count)
        cmd_file = '/tmp/scapy_%s.cmd' % intf

        crb.create_file(content, cmd_file)
        crb.send_expect("scapy -c scapy_%s.cmd &" % intf, "# ")

    def print_summary(self):
        print "Send out pkt %s" % self.pkt.summary()

    def send_pkt(self, intf='', count=1):
        self.print_summary()

        if intf != '':
            # wait few seconds for link ready
            countdown = 600
            while countdown:
                link_st = subprocess.check_output("ip link show %s" % intf,
                                                  stderr=subprocess.STDOUT,
                                                  shell=True)
                if "LOWER_UP" in link_st:
                    break
                else:
                    time.sleep(0.01)
                    countdown -= 1
                    continue

            # fix fortville can't receive packets with 00:00:00:00:00:00
            if self.pkt.getlayer(0).src == "00:00:00:00:00:00":
                self.pkt.getlayer(0).src = get_if_hwaddr(intf)
            sendp(self.pkt, iface=intf, count=count)


class Packet(object):

    """
    Module for config/create packet
    Based on scapy module
    Usage: assign_layers([layers list])
           config_layer('layername', {layer config})
           ...
    """
    def_packet = {
        'TIMESYNC': {'layers': ['ether', 'raw'], 'cfgload': False},
        'ARP': {'layers': ['ether', 'arp'], 'cfgload': False},
        'LLDP': {'layers': ['ether', 'lldp'], 'cfgload': False},
        'IP_RAW': {'layers': ['ether', 'ipv4', 'raw'], 'cfgload': True},
        'TCP': {'layers': ['ether', 'ipv4', 'tcp', 'raw'], 'cfgload': True},
        'UDP': {'layers': ['ether', 'ipv4', 'udp', 'raw'], 'cfgload': True},
        'VLAN_UDP': {'layers': ['ether', 'vlan', 'ipv4', 'udp', 'raw'], 'cfgload': True},
        'ETAG_UDP': {'layers': ['ether', 'etag', 'ipv4', 'udp', 'raw'], 'cfgload': True},
        'SCTP': {'layers': ['ether', 'ipv4', 'sctp', 'raw'], 'cfgload': True},
        'IPv6_TCP': {'layers': ['ether', 'ipv6', 'tcp', 'raw'], 'cfgload': True},
        'IPv6_UDP': {'layers': ['ether', 'ipv6', 'udp', 'raw'], 'cfgload': True},
        'IPv6_SCTP': {'layers': ['ether', 'ipv6', 'sctp', 'raw'], 'cfgload': True},
    }

    def __init__(self, **options):
        """
        pkt_type: description of packet type
                  defined in def_packet
        options: special option for Packet module
                 pkt_len: length of network packet
                 ran_payload: whether payload of packet is random
                 pkt_file:
                 pkt_gen: packet generator type
                          now only support scapy
        """
        self.pkt_layers = []
        self.pkt_len = 64
        self.pkt_opts = options

        self.pkt_type = "UDP"

        if 'pkt_type' in self.pkt_opts.keys():
            self.pkt_type = self.pkt_opts['pkt_type']

        if self.pkt_type in self.def_packet.keys():
            self.pkt_layers = self.def_packet[self.pkt_type]['layers']
            self.pkt_cfgload = self.def_packet[self.pkt_type]['cfgload']
            if "IPv6" in self.pkt_type:
                self.pkt_len = 128
        else:
            self._load_pkt_layers()

        if 'pkt_len' in self.pkt_opts.keys():
            self.pkt_len = self.pkt_opts['pkt_len']

        if 'pkt_file' in self.pkt_opts.keys():
            self.uni_name = self.pkt_opts['pkt_file']
        else:
            self.uni_name = '/tmp/' + str(uuid4()) + '.pcap'

        if 'pkt_gen' in self.pkt_opts.keys():
            if self.pkt_opts['pkt_gen'] == 'scapy':
                self.pktgen = scapy()
            else:
                print "Not support other pktgen yet!!!"
        else:
            self.pktgen = scapy()

        self._load_assign_layers()

    def _load_assign_layers(self):
        # assign layer
        self.assign_layers()

        # config special layer
        self.config_def_layers()

        # handle packet options
        payload_len = self.pkt_len - len(self.pktgen.pkt) - 4

        # if raw data has not been configured and payload should configured
        if hasattr(self, 'configured_layer_raw') is False and self.pkt_cfgload is True:
            payload = []
            raw_confs = {}
            if 'ran_payload' in self.pkt_opts.keys():
                for loop in range(payload_len):
                    payload.append("%02x" % random.randrange(0, 255))
            else:
                for loop in range(payload_len):
                    payload.append('58')  # 'X'

            raw_confs['payload'] = payload
            self.config_layer('raw', raw_confs)

    def send_pkt(self, crb=None, tx_port='', auto_cfg=True, count=1):
        if tx_port == '':
            print "Invalid Tx interface"
            return

        self.tx_port = tx_port

        # check with port type
        if 'ixia' in self.tx_port:
            print "Not Support Yet"

        if crb is not None:
            self.pktgen.write_pcap(self.uni_name)
            crb.session.copy_file_to(self.uni_name)
            pcap_file = self.uni_name.split('/')[2]
            self.pktgen.send_pcap_pkt(
                crb=crb, file=pcap_file, intf=self.tx_port, count=count)
        else:
            self.pktgen.send_pkt(intf=self.tx_port, count=count)

    def check_layer_config(self, layer, config):
        """
        check the format of layer configuration
        every layer should has different check function
        """
        pass

    def assign_layers(self, layers=None):
        """
        assign layer for this packet
        maybe need add check layer function
        """
        if layers is not None:
            self.pkt_layers = layers

        for layer in self.pkt_layers:
            found = False
            l_type = layer.lower()

            for types in LayersTypes.values():
                if l_type in types:
                    found = True
                    break

            if found is False:
                self.pkt_layers.remove(l_type)
                print "INVAILD LAYER TYPE [%s]" % l_type.upper()

        self.pktgen.add_layers(self.pkt_layers)

    def _load_pkt_layers(self):
        name2type = {
            'MAC': 'ether',
            'VLAN': 'vlan',
            'ETAG': 'etag',
            'IP': 'ipv4',
            'IPv4-TUNNEL': 'inner_ipv4',
            'IPihl': 'ipv4ihl',
            'IPFRAG': 'ipv4_ext',
            'IPv6': 'ipv6',
            'IPv6-TUNNEL': 'inner_ipv6',
            'IPv6FRAG': 'ipv6_frag',
            'IPv6EXT': 'ipv6_ext',
            'IPv6EXT2': 'ipv6_ext2',
            'TCP': 'tcp',
            'UDP': 'udp',
            'SCTP': 'sctp',
            'ICMP': 'icmp',
            'NVGRE': 'nvgre',
            'GRE': 'gre',
            'VXLAN': 'vxlan',
            'PKT': 'raw',
        }

        layers = self.pkt_type.split('_')
        self.pkt_layers = []
        self.pkt_cfgload = True
        for layer in layers:
            if layer in name2type.keys():
                self.pkt_layers.append(name2type[layer])

    def config_def_layers(self):
        """
        Handel config packet layers by default
        """
        if self.pkt_type == "TIMESYNC":
            self.config_layer('ether', {'dst': 'FF:FF:FF:FF:FF:FF',
                                        'type': 0x88f7})
            self.config_layer('raw', {'payload': ['00', '02']})

        if self.pkt_type == "ARP":
            self.config_layer('ether', {'dst': 'FF:FF:FF:FF:FF:FF'})

        if self.pkt_type == "IPv6_SCTP":
            self.config_layer('ipv6', {'nh': 132})

        if "IPv6_NVGRE" in self.pkt_type:
            self.config_layer('ipv6', {'nh': 47})
            if "IPv6_SCTP" in self.pkt_type:
                self.config_layer('inner_ipv6', {'nh': 132})
            if "IPv6_ICMP" in self.pkt_type:
                self.config_layer('inner_ipv6', {'nh': 58})
            if "IPFRAG" in self.pkt_type:
                self.config_layer('raw', {'payload': ['00'] * 40})
            else:
                self.config_layer('raw', {'payload': ['00'] * 18})

        if "MAC_IP_IPv6" in self.pkt_type or\
           "MAC_IP_NVGRE" in self.pkt_type or \
           "MAC_IP_UDP_VXLAN" in self.pkt_type:
            if "IPv6_SCTP" in self.pkt_type:
                self.config_layer('ipv6', {'nh': 132})
            if "IPv6_ICMP" in self.pkt_type:
                self.config_layer('ipv6', {'nh': 58})
            if "IPFRAG" in self.pkt_type:
                self.config_layer('raw', {'payload': ['00'] * 40})
            else:
                self.config_layer('raw', {'payload': ['00'] * 18})

    def config_layer(self, layer, config={}):
        """
        Configure packet assgined layer
        return the status of configure result
        """
        try:
            idx = self.pkt_layers.index(layer)
        except Exception as e:
            print "INVALID LAYER ID %s" % layer
            return False

        if self.check_layer_config(layer, config) is False:
            return False

        if 'inner' in layer:
            layer = layer[6:]

        pkt_layer = self.pktgen.pkt.getlayer(idx)
        layer_conf = getattr(self, "_config_layer_%s" % layer)
        setattr(self, 'configured_layer_%s' % layer, True)

        return layer_conf(pkt_layer, config)

    def config_layers(self, layers=None):
        """
        Configure packet with multi configurations
        """
        for layer in layers:
            name, config = layer
            if name not in self.pkt_layers:
                print "[%s] is missing in packet!!!" % name
                raise
            if self.config_layer(name, config) is False:
                print "[%s] failed to configure!!!" % name
                raise

    def _config_layer_ether(self, pkt_layer, config):
        return self.pktgen.ether(pkt_layer, **config)

    def _config_layer_mac(self, pkt_layer, config):
        return self.pktgen.ether(pkt_layer, **config)

    def _config_layer_vlan(self, pkt_layer, config):
        return self.pktgen.vlan(pkt_layer, **config)

    def _config_layer_etag(self, pkt_layer, config):
        return self.pktgen.etag(pkt_layer, **config)

    def _config_layer_ipv4(self, pkt_layer, config):
        return self.pktgen.ipv4(pkt_layer, **config)

    def _config_layer_ipv6(self, pkt_layer, config):
        return self.pktgen.ipv6(pkt_layer, **config)

    def _config_layer_udp(self, pkt_layer, config):
        return self.pktgen.udp(pkt_layer, **config)

    def _config_layer_tcp(self, pkt_layer, config):
        return self.pktgen.tcp(pkt_layer, **config)

    def _config_layer_sctp(self, pkt_layer, config):
        return self.pktgen.sctp(pkt_layer, **config)

    def _config_layer_gre(self, pkt_layer, config):
        return self.pktgen.gre(pkt_layer, **config)

    def _config_layer_raw(self, pkt_layer, config):
        return self.pktgen.raw(pkt_layer, **config)

    def _config_layer_vxlan(self, pkt_layer, config):
        return self.pktgen.vxlan(pkt_layer, **config)

    def strip_layer_element(self, layer, element):
        """
        Strip packet layer elements
        return the status of configure result
        """
        strip_element = getattr(self, "strip_element_%s" % layer)

        return strip_element(element)

    def strip_element_layer2(self, element):
        return self.pktgen.strip_layer2(element)

    def strip_element_layer3(self, element):
        return self.pktgen.strip_layer3(element)

    def strip_element_vlan(self, element):
        return self.pktgen.strip_vlan(element)

    def strip_element_etag(self, element):
        return self.pktgen.strip_etag(element)

    def strip_element_layer4(self, element):
        return self.pktgen.strip_layer4(element)


def IncreaseIP(addr):
    """
    Add one to the last octet of the IPv4 address, like below:
    192.168.1.1 ->192.168.1.2
    If ip hw chksum is disabled, csum routine will increase ip
    """
    ip2int = lambda ipstr: struct.unpack('!I', socket.inet_aton(ipstr))[0]
    x = ip2int(addr)
    int2ip = lambda n: socket.inet_ntoa(struct.pack('!I', n))
    return int2ip(x + 1)


def IncreaseIPv6(addr):
    """
    Add one to the last octet of the IPv6 address, like below:
    FE80:0:0:0:0:0:0:0 -> FE80::1
    csum routine will increase ip
    """
    ipv6addr = struct.unpack('!8H', socket.inet_pton(AF_INET6, addr))
    addr = list(ipv6addr)
    addr[7] += 1
    ipv6 = socket.inet_ntop(AF_INET6, struct.pack(
        '!8H', addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7]))
    return ipv6


def send_packets(intf, pkts=None, interval=0.01):
    send_pkts = []
    try:
        for pkt in pkts:
            send_pkts.append(pkt.pktgen.pkt)
        sendp(send_pkts, iface=intf, inter=interval, verbose=False)
    except:
        pass


def save_packets(pkts=None, filename=None):
    save_pkts = []
    try:
        for pkt in pkts:
            save_pkts.append(pkt.pktgen.pkt)
        if filename:
            wrpcap(filename, save_pkts)
    except:
        pass


def get_ether_type(eth_type=""):
    # need add more types later
    if eth_type.lower() == "lldp":
        return '0x88cc'
    elif eth_type.lower() == "ip":
        return '0x0800'
    elif eth_type.lower() == "ipv6":
        return '0x86dd'

    return 'not support'


def get_filter_cmd(filters=[]):
    """
    Return bpd formated filter string, only support ether layer now
    """
    filter_sep = " and "
    filter_cmds = ""
    for pktfilter in filters:
        filter_cmd = ""
        if pktfilter['layer'] == 'ether':
            if pktfilter['config'].keys()[0] == 'dst':
                dmac = pktfilter['config']['dst']
                filter_cmd = "ether dst %s" % dmac
            elif pktfilter['config'].keys()[0] == 'src':
                smac = pktfilter['config']['src']
                filter_cmd = "ether src %s" % smac
            elif pktfilter['config'].keys()[0] == 'type':
                eth_type = pktfilter['config']['type']
                eth_format = r"(\w+) (\w+)"
                m = re.match(eth_format, eth_type)
                if m:
                    type_hex = get_ether_type(m.group(2))
                    if type_hex == 'not support':
                        continue
                    if m.group(1) == 'is':
                        filter_cmd = 'ether[12:2] = %s' % type_hex
                    elif m.group(1) == 'not':
                        filter_cmd = 'ether[12:2] != %s' % type_hex

        if len(filter_cmds):
            if len(filter_cmd):
                filter_cmds += filter_sep
                filter_cmds += filter_cmd
        else:
            filter_cmds = filter_cmd

    if len(filter_cmds):
        return ' \'' + filter_cmds + '\' '
    else:
        return ""


def sniff_packets(intf, count=0, timeout=5, filters=[]):
    """
    sniff all packets for certain port in certain seconds
    """
    param = ""
    direct_param = r"(\s+)\[ (\S+) in\|out\|inout \]"
    tcpdump_help = subprocess.check_output("tcpdump -h; echo 0",
                                           stderr=subprocess.STDOUT,
                                           shell=True)
    for line in tcpdump_help.split('\n'):
        m = re.match(direct_param, line)
        if m:
            opt = re.search("-Q", m.group(2));
            if opt:
                param = "-Q" + " in"
            else:
                opt = re.search("-P", m.group(2));
                if opt:
                    param = "-P" + " in"

    if len(param) == 0:
        print "tcpdump doesn not support direction chioce"

    if LLDP_FILTER not in filters:
        filters.append(LLDP_FILTER)

    filter_cmd = get_filter_cmd(filters)

    sniff_cmd = 'tcpdump -i %(INTF)s %(FILTER)s %(IN_PARAM)s -w %(FILE)s'
    options = {'INTF': intf, 'COUNT': count, 'IN_PARAM': param,
               'FILE': '/tmp/sniff_%s.pcap' % intf,
               'FILTER': filter_cmd}
    if count:
        sniff_cmd += ' -c %(COUNT)d'
        cmd = sniff_cmd % options
    else:
        cmd = sniff_cmd % options

    args = shlex.split(cmd)

    pipe = subprocess.Popen(args)
    index = str(time.time())
    SNIFF_PIDS[index] = (pipe, intf, timeout)
    time.sleep(0.5)
    return index


def load_sniff_pcap(index=''):
    """
    Stop sniffer and return pcap file
    """
    child_exit = False
    if index in SNIFF_PIDS.keys():
        pipe, intf, timeout = SNIFF_PIDS[index]
        time_elapse = int(time.time() - float(index))
        while time_elapse < timeout:
            if pipe.poll() is not None:
                child_exit = True
                break

            time.sleep(1)
            time_elapse += 1

        if not child_exit:
            pipe.send_signal(signal.SIGINT)
            pipe.wait()

        # wait pcap file ready
        time.sleep(1)
        return "/tmp/sniff_%s.pcap" % intf

    return ""


def load_sniff_packets(index=''):
    """
    Stop sniffer and return packet objects
    """
    pkts = []
    child_exit = False
    if index in SNIFF_PIDS.keys():
        pipe, intf, timeout = SNIFF_PIDS[index]
        time_elapse = int(time.time() - float(index))
        while time_elapse < timeout:
            if pipe.poll() is not None:
                child_exit = True
                break

            time.sleep(1)
            time_elapse += 1

        if not child_exit:
            pipe.send_signal(signal.SIGINT)
            pipe.wait()

        # wait pcap file ready
        time.sleep(1)
        try:
            cap_pkts = rdpcap("/tmp/sniff_%s.pcap" % intf)
            for pkt in cap_pkts:
                # packet gen should be scapy
                packet = Packet(tx_port=intf)
                packet.pktgen.assign_pkt(pkt)
                pkts.append(packet)
        except:
            pass

    return pkts


def load_pcapfile(filename=""):
    pkts = []
    try:
        cap_pkts = rdpcap(filename)
        for pkt in cap_pkts:
            # packet gen should be scapy
            packet = Packet()
            packet.pktgen.assign_pkt(pkt)
            pkts.append(packet)
    except:
        pass

    return pkts


def compare_pktload(pkt1=None, pkt2=None, layer="L2"):
    l_idx = 0
    if layer == "L2":
        l_idx = 0
    elif layer == "L3":
        l_idx = 1
    elif layer == "L4":
        l_idx = 2
    try:
        load1 = hexstr(str(pkt1.pktgen.pkt.getlayer(l_idx)))
        load2 = hexstr(str(pkt2.pktgen.pkt.getlayer(l_idx)))
    except:
        # return pass when scapy failed to extract packet
        return True

    if load1 == load2:
        return True
    else:
        return False


def strip_pktload(pkt=None, layer="L2"):
    if layer == "L2":
        l_idx = 0
    elif layer == "L3":
        l_idx = 1
    elif layer == "L4":
        l_idx = 2
    else:
        l_idx = 0
    try:
        load = hexstr(str(pkt.pktgen.pkt.getlayer(l_idx)), onlyhex=1)
    except:
        # return pass when scapy failed to extract packet
        load = ""

    return load

###############################################################################
###############################################################################
if __name__ == "__main__":
    inst = sniff_packets("lo", timeout=5, filters=[{'layer': 'ether',
                         'config': {'dst': 'FF:FF:FF:FF:FF:FF'}}])
    inst = sniff_packets("lo", timeout=5)
    pkt = Packet(pkt_type='UDP')
    pkt.send_pkt(tx_port='lo')
    pkts = load_sniff_packets(inst)

    pkt = Packet(pkt_type='UDP', pkt_len=1500, ran_payload=True)
    pkt.send_pkt(tx_port='lo')
    pkt = Packet(pkt_type='IPv6_TCP')
    pkt.send_pkt(tx_port='lo')
    pkt = Packet(pkt_type='IPv6_SCTP')
    pkt.send_pkt(tx_port='lo')
    pkt = Packet(pkt_type='VLAN_UDP')
    pkt.config_layer('vlan', {'vlan': 2})
    pkt.send_pkt(tx_port='lo')

    pkt = Packet()
    pkt.assign_layers(['ether', 'vlan', 'ipv4', 'udp',
                       'vxlan', 'inner_mac', 'inner_ipv4', 'inner_udp', 'raw'])
    pkt.config_layer('ether', {'dst': '00:11:22:33:44:55'})
    pkt.config_layer('vlan', {'vlan': 2})
    pkt.config_layer('ipv4', {'dst': '1.1.1.1'})
    pkt.config_layer('udp', {'src': 4789, 'dst': 4789, 'chksum': 0x1111})
    pkt.config_layer('vxlan', {'vni': 2})
    pkt.config_layer('raw', {'payload': ['58'] * 18})
    pkt.send_pkt(tx_port='lo')

    pkt = Packet()
    pkt.assign_layers(['ether', 'vlan', 'ipv4', 'udp',
                       'vxlan', 'inner_mac', 'inner_ipv4', 'inner_udp', 'raw'])
    # config packet
    pkt.config_layers([('ether', {'dst': '00:11:22:33:44:55'}), ('ipv4', {'dst': '1.1.1.1'}),
                       ('vxlan', {'vni': 2}), ('raw', {'payload': ['01'] * 18})])

    pkt.send_pkt(tx_port='lo')
