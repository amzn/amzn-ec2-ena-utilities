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
   * Remove support of '--txqflags' of the testpmd
   * Add methods to the PmdOutput:
     - testpmd_help
     - testpmd_dpdk_ver
"""

import os
import re
from time import sleep
from settings import TIMEOUT, PROTOCOL_PACKET_SIZE, get_nic_driver
from utils import create_mask


class PmdOutput():

    """
    Module for get all statics value by port in testpmd
    """

    def __init__(self, dut):
        self.dut = dut
        self.dut.testpmd = self
        self.rx_pkts_prefix = "RX-packets:"
        self.rx_missed_prefix = "RX-missed:"
        self.rx_bytes_prefix = "RX-bytes:"
        self.rx_badcrc_prefix = "RX-badcrc:"
        self.rx_badlen_prefix = "RX-badlen:"
        self.rx_error_prefix = "RX-errors:"
        self.rx_nombuf_prefix = "RX-nombuf:"
        self.tx_pkts_prefix = "TX-packets:"
        self.tx_error_prefix = "TX-errors:"
        self.tx_bytes_prefix = "TX-bytes:"
        self.bad_ipcsum_prefix = "Bad-ipcsum:"
        self.bad_l4csum_prefix = "Bad-l4csum:"
        self.set_default_corelist()

    def get_pmd_value(self, prefix, out):
        pattern = re.compile(prefix + "(\s+)([0-9]+)")
        m = pattern.search(out)
        if m is None:
            return None
        else:
            return int(m.group(2))

    def set_default_corelist(self):
        """
        set default cores for start testpmd
        """
        core_number = len(self.dut.cores)
        if core_number < 2:
            raise
        else:
            self.default_cores = "1S/2C/1T"

    def get_pmd_stats(self, portid):
        stats = {}
        out = self.dut.send_expect("show port stats %d" % portid, "testpmd> ")
        stats["RX-packets"] = self.get_pmd_value(self.rx_pkts_prefix, out)
        stats["RX-missed"] = self.get_pmd_value(self.rx_missed_prefix, out)
        stats["RX-bytes"] = self.get_pmd_value(self.rx_bytes_prefix, out)

        stats["RX-badcrc"] = self.get_pmd_value(self.rx_badcrc_prefix, out)
        stats["RX-badlen"] = self.get_pmd_value(self.rx_badlen_prefix, out)
        stats["RX-errors"] = self.get_pmd_value(self.rx_error_prefix, out)
        stats["RX-nombuf"] = self.get_pmd_value(self.rx_nombuf_prefix, out)
        stats["TX-packets"] = self.get_pmd_value(self.tx_pkts_prefix, out)
        stats["TX-errors"] = self.get_pmd_value(self.tx_error_prefix, out)
        stats["TX-bytes"] = self.get_pmd_value(self.tx_bytes_prefix, out)

        # display when testpmd config forward engine to csum
        stats["Bad-ipcsum"] = self.get_pmd_value(self.bad_ipcsum_prefix, out)
        stats["Bad-l4csum"] = self.get_pmd_value(self.bad_l4csum_prefix, out)
        return stats

    def get_pmd_cmd(self):
        return self.command

    def start_testpmd(self, cores, param='', eal_param='', socket=0):
        if type(cores) == list:
            core_list = cores
        elif cores == "Default":
            core_list = self.dut.get_core_list(self.default_cores)
        else:
            core_list = self.dut.get_core_list(cores, socket=socket)
        self.coremask = create_mask(core_list)
        command = "./%s/app/testpmd -c %s -n %d %s -- -i %s" \
            % (self.dut.target, self.coremask, self.dut.get_memory_channels(), eal_param, param)
        if "cavium" in self.dut.nic_type:
            # thunder nicvf does not support hw vlan filter, the application crashes
            # without this option added
            command += " --disable-hw-vlan-filter"
        out = self.dut.send_expect(command, "testpmd> ", 120)
        self.command = command
        # wait 10s to ensure links getting up before test start.
        sleep(10)
        return out

    def testpmd_help(self):
        command = "./{}/app/testpmd -- --help".format(self.dut.target)
        return self.dut.send_expect(command, "#")

    def testpmd_dpdk_ver(self):
        command = "cat VERSION"
        out = self.dut.send_expect(command, "#")
        re_str = "\s*(\d+).(\d+).(\d+)"
        match = re.search(re_str, out, re.MULTILINE)
        try:
            v1 = int(match.group(1))
            v2 = int(match.group(2))
            v3 = int(match.group(3))
        except:
            v1 = 18
            v2 = 5
            v3 = 0
            print("Cannot get DPDK version. Use DPDK {}.{}.{} by default."
                .format(v1, v2, v3))
        return v1, v2, v3


    def execute_cmd(self, pmd_cmd, expected='testpmd> ', timeout=TIMEOUT,
                    alt_session=False):
        return self.dut.send_expect('%s' % pmd_cmd, expected, timeout=timeout,
                                    alt_session=alt_session)

    def get_output(self, timeout=1):
        return self.dut.get_session_output(timeout=timeout)

    def get_value_from_string(self, key_str, regx_str, string):
        """
        Get some values from the given string by the regular expression.
        """
        pattern = r"(?<=%s)%s" % (key_str, regx_str)
        s = re.compile(pattern)
        res = s.search(string)
        if type(res).__name__ == 'NoneType':
            return ' '
        else:
            return res.group(0)

    def get_detail_from_port_info(self, key_str, regx_str, port):
        """
        Get the detail info from the output of pmd cmd 'show port info <port num>'.
        """
        out = self.dut.send_expect("show port info %d" % port, "testpmd> ")
        find_value = self.get_value_from_string(key_str, regx_str, out)
        return find_value

    def get_port_mac(self, port_id):
        """
        Get the specified port MAC.
        """
        return self.get_detail_from_port_info("MAC address: ", "([0-9A-F]{2}:){5}[0-9A-F]{2}", port_id)

    def get_port_connect_socket(self, port_id):
        """
        Get the socket id which the specified port is connectting with.
        """
        return self.get_detail_from_port_info("Connect to socket: ", "\d+", port_id)

    def get_port_memory_socket(self, port_id):
        """
        Get the socket id which the specified port memory is allocated on.
        """
        return self.get_detail_from_port_info("memory allocation on the socket: ", "\d+", port_id)

    def get_port_link_status(self, port_id):
        """
        Get the specified port link status now.
        """
        return self.get_detail_from_port_info("Link status: ", "\d+", port_id)

    def get_port_link_speed(self, port_id):
        """
        Get the specified port link speed now.
        """
        return self.get_detail_from_port_info("Link speed: ", "\d+", port_id)

    def get_port_link_duplex(self, port_id):
        """
        Get the specified port link mode, duplex or siplex.
        """
        return self.get_detail_from_port_info("Link duplex: ", "\S+", port_id)

    def get_port_promiscuous_mode(self, port_id):
        """
        Get the promiscuous mode of port.
        """
        return self.get_detail_from_port_info("Promiscuous mode: ", "\S+", port_id)

    def get_port_allmulticast_mode(self, port_id):
        """
        Get the allmulticast mode of port.
        """
        return self.get_detail_from_port_info("Allmulticast mode: ", "\S+", port_id)

    def check_tx_bytes(self, tx_bytes, exp_bytes = 0):
        """
        fortville nic will send lldp packet when nic setup with testpmd.
        so should used (tx_bytes - exp_bytes) % PROTOCOL_PACKET_SIZE['lldp']
        for check tx_bytes count right
        """
        # error_flage is true means tx_bytes different with expect bytes
        error_flage = 1
        for size in  PROTOCOL_PACKET_SIZE['lldp']:
            error_flage = error_flage and  (tx_bytes - exp_bytes) % size

        return not error_flage

    def get_port_vlan_offload(self, port_id):
        """
        Function: get the port vlan settting info.
        return value:
            'strip':'on'
            'filter':'on'
            'qinq':'off'
        """
        vlan_info = {}
        vlan_info['strip'] = self.get_detail_from_port_info(
            "strip ", '\S+', port_id)
        vlan_info['filter'] = self.get_detail_from_port_info(
            'filter', '\S+', port_id)
        vlan_info['qinq'] = self.get_detail_from_port_info(
            'qinq\(extend\) ', '\S+', port_id)
        return vlan_info

    def quit(self):
        self.dut.send_expect("quit", "# ")
