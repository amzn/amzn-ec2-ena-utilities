# BSD LICENSE
#
# Copyright(c) 2010-2017 Intel Corporation. All rights reserved.
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

import os
import time
import re

from collections import OrderedDict
#install GitPython
from git import Repo

class SystemInfo(object):

    def __init__(self, dut, pci_device_id):
	self.dut = dut
	self.pci_device_id = pci_device_id
        self.session = self.dut.session
        self.system_info =  OrderedDict()
        self.nic_info = OrderedDict()

    def get_system_info(self):

        board = self.session.send_expect("dmidecode -s system-product-name", "# ")
        self.system_info["Board"] = board

        processors = self.session.send_expect("dmidecode -s processor-version", "# ")
        processor = processors.split('\r\n')[0]
        self.system_info["CPU"] =  processor

        memories = self.session.send_expect("dmidecode -t memory", "]# ")
        channels, size, speed = self._strip_memory(memories)
        memory_info = "Total %d MBs in %d channels @ %s" %(size, channels, speed)
        self.system_info["Memory"] = memory_info

        release = self.session.send_expect("lsb_release -d |awk -F':' '{print $2}'", "# ")
        self.system_info["Operating system"] = release

        kernel = self.session.send_expect("uname -r", "# ")
        self.system_info["Linux kernel version"] = kernel
        
        gcc_info = self.session.send_expect("gcc --version", "# ")
        gcc = gcc_info.split('\r\n')[0]
        self.system_info["GCC version"] = gcc

        return self.system_info
        
    def _strip_memory(self, memories):
        """
        Size: 8192 MB Locator: DIMM_A1 Speed: 2133 MHz
        """
        s_regex = r"(\s+)Size: (\d+) MB"
        l_regex= r"(\s+)Locator: DIMM_(\w+)"
        speed_regex = r"(\s+)Speed: (.*)"
        size = ""
        locate = ""
        speed = "Unknown"
        memory_infos = []
        memory_channel = set()
        lines = memories.split('\r\n')
        total_size = 0
        for line in lines:
            m = re.match(s_regex, line)
            if m:
                size = m.group(2)
            l_m = re.match(l_regex, line)
            if l_m:
                locate = l_m.group(2)
            s_m = re.match(speed_regex, line)
            if s_m:
                speed = s_m.group(2)
            if speed != "Unknown":
                memory={"Size": size, "Locate": locate, "Speed": speed}
                memory_infos.append(memory)
                speed = "Unknown"
                total_size += int(size)
                memory_channel.add(locate[0])

        return len(memory_channel), total_size, memory_infos[0]["Speed"]

    def get_nic_info(self):

        cmd = "cat /sys/bus/pci/devices/%s/vendor" % self.pci_device_id
        vendor = self.session.send_expect(cmd, "# ")
        if "No such" in vendor:
            return None

        cmd = "cat /sys/bus/pci/devices/%s/device" % self.pci_device_id
        device = self.session.send_expect(cmd, "# ")
        if "No such" in device:
            return None

        cmd = "ls --color=never /sys/bus/pci/devices/%s/net" % self.pci_device_id
        interface = self.session.send_expect(cmd, "# ")
        if "No such" in interface:
            return None
        cmd = "ethtool -i %s | grep --color=never firmware |awk -F':' '{print $2}'" % interface
        firmware = self.session.send_expect(cmd, "# ")
        if "No such" in firmware:
            return None
        cmd = "lspci -vmmks %s |grep -i ^device |awk -F':' '{print $2}'" % self.pci_device_id
        self.nic_info['nic_name'] = self.session.send_expect(cmd, "# ")
        self.nic_info['device_id'] = vendor[2:] + ':' + device[2:]
        self.nic_info['firmware-version'] = firmware
        return self.nic_info

