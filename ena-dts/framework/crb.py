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
    * Add support for the scapy
    * Use SSH key for connecting to the instances
    * Configure paths and packages that must be sent onto target host
    * Add port configuration to the crb
    * Add methods to the Crb class:
      - scapy_append
      - scapy_execute
      - scapy_background
      - scapy_foreground
      - scapy_get_result
      - scapy_run
      - scapy_send
      - scapy_exit
      - scapy_check_path
      - restore_interfaces
      - restore_interfaces_freebsd
      - restore_interfaces_linux
      - configure_interface_rhel
      - get_port_cfg
      - configure_interface_ubuntu
      - mk_dir
      - rm_f_dir
      - save_file
      - configure_interface_ubuntu18
      - configure_interface_ubuntu16
      - configure_interface_ubuntu14
      - configure_interface_ubuntu16_14
      - cidr_to_netmask
      - kill
      - free_hugepage
      - to_base_dir
      - setup_memory
      - setup_memory_linux
      - setup_memory_freebsd
      - check_setup
      - check_repo
      - path_exist
      - check_instance_type
      - get_cpu_number
"""

import time
import re
import net_device
import os
import settings
import json
from settings import latency_app, latency_send, latency_echo, reset_app
from config import PortConf
from settings import TIMEOUT, IXIA, FOLDERS
from ssh_connection import SSHConnection
from logger import getLogger
from time import sleep

"""
CRB (customer reference board) basic functions and handlers
"""


class Crb(object):

    """
    Basic module for customer reference board. This module implement functions
    interact with CRB. With these function, we can get the information of
    CPU/PCI/NIC on the board and setup running environment for DPDK.
    """
    SCAPY_PROMPT = ">>> "
    FREE_MEMORY = 2*1024*1024
    SCAPY_FULL_PATH = "/usr/local/bin/scapy"
    SCAPY_SHORT_PATH = "scapy"

    def __init__(self, crb, serializer, name):
        self.crb = crb
        self.read_cache = False
        self.skip_setup = False
        self.serializer = serializer
        self.ports_info = None
        self.sessions = []
        self.stage = 'pre-init'
        self.name = name

        self.logger = getLogger(name)
        self.session = SSHConnection(self.get_ip_address(), name,
                                     self.get_username(),
                                     self.get_password(),
                                     self.get_ssh_key())
        self.session.init_log(self.logger)
        self.alt_session = SSHConnection(
            self.get_ip_address(),
            name + '_alt',
            self.get_username(),
            self.get_password(),
            self.get_ssh_key())
        self.alt_session.init_log(self.logger)
        self.scapyCmds = []
        self.bgProcIsRunning = False
        self.inBg = 0

        self.base_dir = "~/dpdk"
        self.pktgen_dir = self.base_dir+"/pktgen"
        self.dst_dir = "/tmp/"

        self.packages = ["dpdk.tar.gz",
                         "pktgen.tar.gz",
                         latency_app + ".tar.gz",
                         reset_app + ".tar.gz"]
        self.apps = [latency_app + "/" + latency_send,
                     latency_app + "/" + latency_echo,
                     reset_app]

        self.scapy = self.SCAPY_FULL_PATH

        self.conf = PortConf()
        self.conf.load_ports_config(self.crb["section"])

        self.kill()
        self.free_hugepage()

        self.virttype = None
        self.scapy_console_on = False
        self.test_configs = None
        self.used_port = -1
        self.prompt = "# "

    def send_expect(self, cmds, expected, timeout=TIMEOUT,
                    alt_session=False, verify=False):
        """
        Send commands to crb and return string before expected string. If
        there's no expected string found before timeout, TimeoutException will
        be raised.
        """

        if alt_session:
            return self.alt_session.session.send_expect(cmds, expected,
                                                        timeout, verify)

        return self.session.send_expect(cmds, expected, timeout, verify)

    def create_session(self, name=""):
        """
        Create new session for addtional useage. This session will not enable log.
        """
        logger = getLogger(name)
        session = SSHConnection(self.get_ip_address(),
                                name,
                                self.get_username(),
                                self.get_password(),
                                self.get_ssh_key())
        session.init_log(logger)
        self.sessions.append(session)
        return session

    def destroy_session(self, session=None):
        """
        Destroy addtional session.
        """
        for save_session in self.sessions:
            if save_session == session:
                save_session.close()
                logger = getLogger(save_session.name)
                logger.logger_exit()
                self.sessions.remove(save_session)
                break

    def reconnect_session(self, alt_session=False):
        """
        When session can't used anymore, recreate another one for replace
        """
        try:
            if alt_session:
                self.alt_session.close(force=True)
            else:
                self.session.close(force=True)
        except Exception as e:
            self.loggger.error("Session close failed for [%s]" % e)

        if alt_session:
            session = SSHConnection(
                self.get_ip_address(),
                self.name + '_alt',
                self.get_username(),
                self.get_password(),
                self.get_ssh_key())
            self.alt_session = session
        else:
            session = SSHConnection(self.get_ip_address(), self.name,
                                    self.get_username(), self.get_password(), self.get_ssh_key())
            self.session = session

        session.init_log(self.logger)

    def send_command(self, cmds, timeout=TIMEOUT, alt_session=False):
        """
        Send commands to crb and return string before timeout.
        """

        if alt_session:
            return self.alt_session.session.send_command(cmds, timeout)

        return self.session.send_command(cmds, timeout)

    def get_session_output(self, timeout=TIMEOUT):
        """
        Get session output message before timeout
        """
        return self.session.get_session_before(timeout)

    def set_test_types(self, func_tests, perf_tests):
        """
        Enable or disable function/performance test.
        """
        self.want_func_tests = func_tests
        self.want_perf_tests = perf_tests

    def get_total_huge_pages(self):
        """
        Get the huge page number of CRB.
        """
        huge_pages = self.send_expect(
            "awk '/HugePages_Total/ { print $2 }' /proc/meminfo",
            "# ", alt_session=True)
        if huge_pages != "":
            return int(huge_pages)
        return 0

    def mount_huge_pages(self):
        """
        Mount hugepage file system on CRB.
        """
        self.send_expect("umount `awk '/hugetlbfs/ { print $2 }' /proc/mounts`", '# ')
        out = self.send_expect("awk '/hugetlbfs/ { print $2 }' /proc/mounts", "# ")
        # only mount hugepage when no hugetlbfs mounted
        if not len(out):
            self.send_expect('mkdir -p /mnt/huge', '# ')
            self.send_expect('mount -t hugetlbfs nodev /mnt/huge', '# ')

    def strip_hugepage_path(self):
        mounts = self.send_expect("cat /proc/mounts |grep hugetlbfs", "# ")
        infos = mounts.split()
        if len(infos) >= 2:
            return infos[1]
        else:
            return ''

    def set_huge_pages(self, huge_pages, numa=-1):
        """
        Set numbers of huge pages
        """
        page_size = self.send_expect("awk '/Hugepagesize/ {print $2}' /proc/meminfo", "# ")

        if numa == -1:
            self.send_expect('echo %d > /sys/kernel/mm/hugepages/hugepages-%skB/nr_hugepages' % (huge_pages, page_size), '# ', 30)
        else:
            # sometimes we set hugepage on kernel cmdline, so we need clear default hugepage
            self.send_expect('echo 0 > /sys/kernel/mm/hugepages/hugepages-%skB/nr_hugepages' % (page_size), '# ', 30)
            # some platform not support numa, example vm dut
            try:
                self.send_expect('echo %d > /sys/devices/system/node/node%d/hugepages/hugepages-%skB/nr_hugepages' % (huge_pages, numa, page_size), '# ', 30)
            except:
                self.logger.warning("set %d hugepage on socket %d error" % (huge_pages, numa))
                self.send_expect('echo %d > /sys/kernel/mm/hugepages/hugepages-%skB/nr_hugepages' % (huge_pages. page_size), '# ', 30)

    def set_speedup_options(self, read_cache, skip_setup):
        """
        Configure skip network topology scan or skip DPDK packet setup.
        """
        self.read_cache = read_cache
        self.skip_setup = skip_setup

    def set_directory(self, base_dir):
        """
        Set DPDK package folder name.
        """
        self.base_dir = base_dir

    def set_virttype(self, virttype):
        self.virttype = virttype

    def admin_ports(self, port, status):
        """
        Force set port's interface status.
        """
        admin_ports_freebsd = getattr(self, 'admin_ports_freebsd_%s' % self.get_os_type())
        return admin_ports_freebsd()

    def admin_ports_freebsd(self, port, status):
        """
        Force set remote interface link status in FreeBSD.
        """
        eth = self.ports_info[port]['intf']
        self.send_expect("ifconfig %s %s" %
                         (eth, status), "# ", alt_session=True)

    def admin_ports_linux(self, eth, status):
        """
        Force set remote interface link status in Linux.
        """
        self.send_expect("ip link set  %s %s" %
                         (eth, status), "# ", alt_session=True)

    def pci_devices_information(self):
        """
        Scan CRB pci device information and save it into cache file.
        """
        if self.read_cache:
            self.pci_devices_info = self.serializer.load(self.PCI_DEV_CACHE_KEY)

        if not self.read_cache or self.pci_devices_info is None:
            self.pci_devices_information_uncached()
            self.serializer.save(self.PCI_DEV_CACHE_KEY, self.pci_devices_info)

    def pci_devices_information_uncached(self):
        """
        Scan CRB NIC's information on different OS.
        """
        pci_devices_information_uncached = getattr(self, 'pci_devices_information_uncached_%s' % self.get_os_type())
        return pci_devices_information_uncached()

    def pci_devices_information_uncached_linux(self):
        """
        Look for the NIC's information (PCI Id and card type).
        """
        out = self.send_expect(
            "lspci -Dnn | grep -i eth", "# ", alt_session=True)
        rexp = r"([\da-f]{4}:[\da-f]{2}:[\da-f]{2}.\d{1}) .*Eth.*?ernet .*?([\da-f]{4}:[\da-f]{4})"
        pattern = re.compile(rexp)
        match = pattern.findall(out)
        self.pci_devices_info = []
        for i in range(len(match)):
            #check if device is cavium and check its linkspeed, append only if it is 10G
            if "177d:" in match[i][1]:
                linkspeed = "10000"
                nic_linkspeed = self.send_command("cat /sys/bus/pci/devices/%s/net/*/speed" % match[i][0])
                if nic_linkspeed == linkspeed:
                    self.pci_devices_info.append((match[i][0], match[i][1]))
            else:
                self.pci_devices_info.append((match[i][0], match[i][1]))

    def pci_devices_information_uncached_freebsd(self):
        """
        Look for the NIC's information (PCI Id and card type).
        """
        out = self.send_expect("pciconf -l", "# ", alt_session=True)
        rexp = r"pci0:([\da-f]{1,3}:[\da-f]{1,2}:\d{1}):\s*class=0x020000.*chip=0x([\da-f]{4})8086"
        pattern = re.compile(rexp)
        match = pattern.findall(out)

        self.pci_devices_info = []
        for i in range(len(match)):
            card_type = "8086:%s" % match[i][1]
            self.pci_devices_info.append((match[i][0], card_type))

    def get_pci_dev_driver(self, domain_id, bus_id, devfun_id):
        """
        Get the driver of specified pci device.
        """
        get_pci_dev_driver = getattr(
            self, 'get_pci_dev_driver_%s' % self.get_os_type())
        return get_pci_dev_driver(domain_id, bus_id, devfun_id)

    def get_pci_dev_driver_linux(self, domain_id, bus_id, devfun_id):
        """
        Get the driver of specified pci device on linux.
        """
        out = self.send_expect("cat /sys/bus/pci/devices/%s\:%s\:%s/uevent" %
                               (domain_id, bus_id, devfun_id), "# ", alt_session=True)
        rexp = r"DRIVER=(.+?)\r"
        pattern = re.compile(rexp)
        match = pattern.search(out)
        if not match:
            return None
        return match.group(1)

    def get_pci_dev_driver_freebsd(self, domain_id, bus_id, devfun_id):
        """
        Get the driver of specified pci device.
        """
        return True

    def get_pci_dev_id(self, domain_id, bus_id, devfun_id):
        """
        Get the pci id of specified pci device.
        """
        get_pci_dev_id = getattr(
            self, 'get_pci_dev_id_%s' % self.get_os_type())
        return get_pci_dev_id(domain_id, bus_id, devfun_id)

    def get_pci_dev_id_linux(self, domain_id, bus_id, devfun_id):
        """
        Get the pci id of specified pci device on linux.
        """
        out = self.send_expect("cat /sys/bus/pci/devices/%s\:%s\:%s/uevent" %
                               (domain_id, bus_id, devfun_id), "# ", alt_session=True)
        rexp = r"PCI_ID=(.+)"
        pattern = re.compile(rexp)
        match = re.search(out)
        if not match:
            return None
        return match.group(1)

    def get_device_numa(self, domain_id, bus_id, devfun_id):
        """
        Get numa number of specified pci device.
        """
        get_device_numa = getattr(
            self, "get_device_numa_%s" % self.get_os_type())
        return get_device_numa(domain_id, bus_id, devfun_id)

    def get_device_numa_linux(self, domain_id, bus_id, devfun_id):
        """
        Get numa number of specified pci device on Linux.
        """
        numa = self.send_expect(
            "cat /sys/bus/pci/devices/%s\:%s\:%s/numa_node" %
            (domain_id, bus_id, devfun_id), "# ", alt_session=True)

        try:
            numa = int(numa)
        except ValueError:
            numa = -1
            self.logger.warning("NUMA not available")
        return numa

    def get_ipv6_addr(self, intf):
        """
        Get ipv6 address of specified pci device.
        """
        get_ipv6_addr = getattr(self, 'get_ipv6_addr_%s' % self.get_os_type())
        return get_ipv6_addr(intf)

    def get_ipv6_addr_linux(self, intf):
        """
        Get ipv6 address of specified pci device on linux.
        """
        out = self.send_expect("ip -family inet6 address show dev %s | awk '/inet6/ { print $2 }'"
                               % intf, "# ", alt_session=True)
        return out.split('/')[0]

    def get_ipv6_addr_freebsd(self, intf):
        """
        Get ipv6 address of specified pci device on Freebsd.
        """
        out = self.send_expect('ifconfig %s' % intf, '# ', alt_session=True)
        rexp = r"inet6 ([\da-f:]*)%"
        pattern = re.compile(rexp)
        match = pattern.findall(out)
        if len(match) == 0:
            return None

        return match[0]

    def disable_ipv6(self, intf):
        """
        Disable ipv6 of of specified interface
        """
        if intf != 'N/A':
            self.send_expect("sysctl net.ipv6.conf.%s.disable_ipv6=1" %
                             intf, "# ", alt_session=True)

    def enable_ipv6(self, intf):
        """
        Enable ipv6 of of specified interface
        """
        if intf != 'N/A':
            self.send_expect("sysctl net.ipv6.conf.%s.disable_ipv6=0" %
                             intf, "# ", alt_session=True)

            out = self.send_expect(
                "ifconfig %s" % intf, "# ", alt_session=True)
            if "inet6" not in out:
                self.send_expect("ifconfig %s down" %
                                 intf, "# ", alt_session=True)
                self.send_expect(
                    "ifconfig %s up" % intf, "# ", alt_session=True)


    def create_file(self, contents, fileName):
        """
        Create file with contents and copy it to CRB.
        """
        with open(fileName, "w") as f:
            f.write(contents)
        self.session.copy_file_to(fileName, password=self.get_password())

    def kill_all(self, alt_session=True):
        """
        Kill all dpdk applications on CRB.
        """
        self.send_expect("^C", "# ")
        pids = []
        pid_reg = r'p(\d+)'
        cmd = 'lsof -Fp /var/run/.rte_config'
        out = self.send_expect(cmd, "# ", 20, alt_session)
        if len(out):
            lines = out.split('\r\n')
            for line in lines:
                m = re.match(pid_reg, line)
                if m:
                    pids.append(m.group(1))
        for pid in pids:
            self.send_expect('kill -9 %s' % pid, '# ', 20, alt_session)
            self.get_session_output(timeout=2)

        cmd = 'lsof -Fp /var/run/.rte_hugepage_info'
        out = self.send_expect(cmd, "# ", 20, alt_session)
        if len(out) and "No such file or directory" not in out:
            self.logger.warning("There are some dpdk process not free hugepage")
            self.logger.warning("**************************************")
            self.logger.warning(out)
            self.logger.warning("**************************************")
        self.alt_session.send_expect('killall scapy 2>/dev/null; echo tester', '# ', 5)

    def close(self):
        """
        Close ssh session of CRB.
        """
        self.session.close()
        self.alt_session.close()

    def get_os_type(self):
        """
        Get OS type from execution configuration file.
        """
        from dut import Dut
        if isinstance(self, Dut) and 'OS' in self.crb:
            return str(self.crb['OS']).lower()

        return 'linux'

    def check_os_type(self):
        """
        Check real OS type whether match configured type.
        """
        from dut import Dut
        expected = 'Linux.*#'
        if isinstance(self, Dut) and self.get_os_type() == 'freebsd':
            expected = 'FreeBSD.*#'

        self.send_expect('uname', expected, 2, alt_session=True)

    def init_core_list(self):
        """
        Load or create core information of CRB.
        """
        if self.read_cache:
            self.number_of_cores = self.serializer.load(self.NUMBER_CORES_CACHE_KEY)
            self.cores = self.serializer.load(self.CORE_LIST_CACHE_KEY)

        if not self.read_cache or self.cores is None or self.number_of_cores is None:
            self.init_core_list_uncached()
            self.serializer.save(self.NUMBER_CORES_CACHE_KEY, self.number_of_cores)
            self.serializer.save(self.CORE_LIST_CACHE_KEY, self.cores)

    def init_core_list_uncached(self):
        """
        Scan cores on CRB and create core information list.
        """
        init_core_list_uncached = getattr(self, 'init_core_list_uncached_%s' % self.get_os_type())
        init_core_list_uncached()

    def init_core_list_uncached_freebsd(self):
        """
        Scan cores in Freebsd and create core information list.
        """
        self.cores = []

        import xml.etree.ElementTree as ET

        out = self.send_expect("sysctl -n kern.sched.topology_spec", "# ")

        cpu_xml = ET.fromstring(out)

        # WARNING: HARDCODED VALUES FOR CROWN PASS IVB
        thread = 0
        socket_id = 0

        sockets = cpu_xml.findall(".//group[@level='2']")
        for socket in sockets:
            core_id = 0
            core_elements = socket.findall(".//children/group/cpu")
            for core in core_elements:
                threads = [int(x) for x in core.text.split(",")]
                for thread in threads:
                    if thread != 0:
                        self.cores.append({'socket': socket_id,
                                           'core': core_id,
                                           'thread': thread})
                core_id += 1
            socket_id += 1
        self.number_of_cores = len(self.cores)

    def init_core_list_uncached_linux(self):
        """
        Scan cores in linux and create core information list.
        """
        self.cores = []

        cpuinfo = \
            self.send_expect(
                "lscpu -p|grep -v \#",
                "#", alt_session=True)

        cpuinfo = cpuinfo.split()
        # haswell cpu on cottonwood core id not correct
        # need addtional coremap for haswell cpu
        core_id = 0
        coremap = {}
        for line in cpuinfo:
            (thread, core, socket, unused) = line.split(',')[0:4]

            if core not in coremap.keys():
                coremap[core] = core_id
                core_id += 1

            if self.crb['bypass core0'] and core == '0' and socket == '0':
                self.logger.info("Core0 bypassed")
                continue
            self.cores.append(
                    {'thread': thread, 'socket': socket, 'core': coremap[core]})

        self.number_of_cores = len(self.cores)

    def get_all_cores(self):
        """
        Return core information list.
        """
        return self.cores

    def remove_hyper_core(self, core_list, key=None):
        """
        Remove hyperthread locre for core list.
        """
        found = set()
        for core in core_list:
            val = core if key is None else key(core)
            if val not in found:
                yield core
                found.add(val)

    def init_reserved_core(self):
        """
        Remove hyperthread cores from reserved list.
        """
        partial_cores = self.cores
        # remove hyper-threading core
        self.reserved_cores = list(self.remove_hyper_core(partial_cores, key=lambda d: (d['core'], d['socket'])))

    def remove_reserved_cores(self, core_list, args):
        """
        Remove cores from reserved cores.
        """
        indexes = sorted(args, reverse=True)
        for index in indexes:
            del core_list[index]
        return core_list

    def get_reserved_core(self, config, socket):
        """
        Get reserved cores by core config and socket id.
        """
        m = re.match("([1-9]+)C", config)
        nr_cores = int(m.group(1))
        if m is None:
            return []

        partial_cores = [n for n in self.reserved_cores if int(n['socket']) == socket]
        if len(partial_cores) < nr_cores:
            return []

        thread_list = [self.reserved_cores[n]['thread'] for n in range(nr_cores)]

        # remove used core from reserved_cores
        rsv_list = [n for n in range(nr_cores)]
        self.reserved_cores = self.remove_reserved_cores(partial_cores, rsv_list)

        # return thread list
        return map(str, thread_list)

    def get_core_list(self, config, socket=-1):
        """
        Get lcore array according to the core config like "all", "1S/1C/1T".
        We can specify the physical CPU socket by paramter "socket".
        """
        if config == 'all':
            cores = []
            if socket != -1:
                for core in self.cores:
                    if int(core['socket']) == socket:
                        cores.append(core['thread'])
            else:
                cores = [core['thread'] for core in self.cores]
            return cores

        m = re.match("([1234])S/([0-9]+)C/([12])T", config)

        if m:
            nr_sockets = int(m.group(1))
            nr_cores = int(m.group(2))
            nr_threads = int(m.group(3))

            partial_cores = self.cores

            # If not specify socket sockList will be [0,1] in numa system
            # If specify socket will just use the socket
            if socket < 0:
                sockList = set([int(core['socket']) for core in partial_cores])
            else:
                for n in partial_cores:
                    if (int(n['socket']) == socket):
                        sockList = [int(n['socket'])]

            sockList = list(sockList)[:nr_sockets]
            partial_cores = [n for n in partial_cores if int(n['socket'])
                             in sockList]
            core_list = set([int(n['core']) for n in partial_cores])
            core_list = list(core_list)
            thread_list = set([int(n['thread']) for n in partial_cores])
            thread_list = list(thread_list)

            # filter usable core to core_list
            temp = []
            for sock in sockList:
                core_list = set([int(
                    n['core']) for n in partial_cores if int(n['socket']) == sock])
                core_list = list(core_list)[:nr_cores]
                temp.extend(core_list)

            core_list = temp

            # if system core less than request just use all cores in in socket
            if len(core_list) < (nr_cores * nr_sockets):
                partial_cores = self.cores
                sockList = set([int(n['socket']) for n in partial_cores])

                sockList = list(sockList)[:nr_sockets]
                partial_cores = [n for n in partial_cores if int(
                    n['socket']) in sockList]

                temp = []
                for sock in sockList:
                    core_list = list([int(n['thread']) for n in partial_cores if int(
                        n['socket']) == sock])
                    core_list = core_list[:nr_cores]
                    temp.extend(core_list)

                core_list = temp

            partial_cores = [n for n in partial_cores if int(
                n['core']) in core_list]
            temp = []
            if len(core_list) < nr_cores:
                raise ValueError("Cannot get requested core configuration "
                                 "requested {} have {}".format(config, self.cores))
            if len(sockList) < nr_sockets:
                raise ValueError("Cannot get requested core configuration "
                                 "requested {} have {}".format(config, self.cores))
            # recheck the core_list and create the thread_list
            i = 0
            for sock in sockList:
                coreList_aux = [int(core_list[n])for n in range(
                    (nr_cores * i), (nr_cores * i + nr_cores))]
                for core in coreList_aux:
                    thread_list = list([int(n['thread']) for n in partial_cores if (
                        (int(n['core']) == core) and (int(n['socket']) == sock))])
                    thread_list = thread_list[:nr_threads]
                    temp.extend(thread_list)
                    thread_list = temp
                i += 1
            return map(str, thread_list)

    def get_lcore_id(self, config):
        """
        Get lcore id of specified core by config "C{socket.core.thread}"
        """

        m = re.match("C{([01]).(\d).([01])}", config)

        if m:
            sockid = m.group(1)
            coreid = int(m.group(2))
            threadid = int(m.group(3))

            perSocklCs = [_ for _ in self.cores if _['socket'] == sockid]
            coreNum = perSocklCs[coreid]['core']

            perCorelCs = [_ for _ in perSocklCs if _['core'] == coreNum]

            return perCorelCs[threadid]['thread']

    def get_port_info(self, pci):
        """
        return port info by pci id
        """
        for port_info in self.ports_info:
            if port_info['pci'] == pci:
                return port_info

    def get_port_pci(self, port_id):
        """
        return port pci address by port index
        """
        return self.ports_info[port_id]['pci']

    def enable_promisc(self, intf):
        if intf != 'N/A':
            self.send_expect("ifconfig %s promisc" % intf, "# ", alt_session=True)

    def scapy_append(self, cmd):
        """
        Append command into scapy command list.
        """
        self.scapyCmds.append(cmd)

    def scapy_execute(self, timeout=60):
        """
        Execute scapy command list.
        """
        status = 0
        self.kill_all()
        self.send_expect("cd {}".format(self.base_dir), "#")
        self.scapy_check_path()
        self.send_expect(self.scapy, self.SCAPY_PROMPT)
        if self.bgProcIsRunning:
            self.send_expect(
                'subprocess.call("{} -c sniff.py &", shell=True)'.
                    format(self.scapy), self.SCAPY_PROMPT)
            self.bgProcIsRunning = False
        sleep(2)

        for cmd in self.scapyCmds:
            out = self.send_expect(cmd, self.SCAPY_PROMPT, timeout)
            if "Error" in out:
                status = -1
                print("Scapy error")
                print(out)
                break

        sleep(2)
        self.scapyCmds = []
        self.send_expect("exit()", "# ")
        return status

    def scapy_background(self):
        """
        Configure scapy running in background mode which main purpose is
        to save RESULT into scapyResult.txt.
        """
        self.inBg = True

    def scapy_foreground(self):
        """
        Running background scapy and convert to foreground mode.
        """
        self.send_expect("echo -n '' >  scapyResult.txt", "# ")
        if self.inBg:
            self.scapyCmds.append('f = open(\'scapyResult.txt\',\'w\')')
            self.scapyCmds.append('f.write(RESULT)')
            self.scapyCmds.append('f.close()')
            self.scapyCmds.append('exit()')

            outContents = "import os\n" + \
                'conf.color_theme=NoTheme()\n' + 'RESULT=""\n' + \
                "\n".join(self.scapyCmds) + "\n"
            self.create_file(outContents, 'sniff.py')

            self.logger.info('SCAPY Receive setup:\n' + outContents)

            self.bgProcIsRunning = True
            self.scapyCmds = []
        self.inBg = False

    def scapy_get_result(self):
        """
        Return RESULT which saved in scapyResult.txt.
        """
        out = self.send_expect("cat scapyResult.txt", "# ")
        self.logger.info('SCAPY Result:\n' + out + '\n\n\n')

        return out

    def scapy_run(self):
        self.kill_all()
        self.scapy_check_path()
        self.scapy_console_on = True
        self.send_expect(self.scapy, self.SCAPY_PROMPT)

    def scapy_send(self, command, timeout=30):
        return self.send_expect(command, self.SCAPY_PROMPT, timeout=timeout)

    def scapy_exit(self):
        if self.scapy_console_on:
            self.scapy_console_on = False
            self.send_expect("exit()", "# ")

    def scapy_check_path(self):
        out = self.send_expect("ls {}".format(self.SCAPY_FULL_PATH), "# ")
        if "No such" in out:
            self.scapy = self.SCAPY_SHORT_PATH
        else:
            self.scapy = self.SCAPY_FULL_PATH

    def restore_interfaces(self, skip=False):
        """
        Restore all ports's interfaces.
        """
        if skip:
            self.logger.info('SKIPPED restoring interfaces')
            return

        # no need to restore for all info has been recorded
        if self.read_cache:
            return

        restore_interfaces = getattr(self, 'restore_interfaces_%s' % self.get_os_type())
        return restore_interfaces()

    def restore_interfaces_freebsd(self):
        """
        Restore FreeBSD interfaces.
        """
        print("FreeBSD not supported.")

    def restore_interfaces_linux(self):
        """
        Restore Linux interfaces.
        """
        self.kill()
        for (pci_bus, pci_id) in self.pci_devices_info:
            # get device driver
            driver = settings.get_nic_driver(pci_id)
            if driver is not None:
                # unbind device driver
                addr_array = pci_bus.split(':')
                domain_id = addr_array[0]
                bus_id = addr_array[1]
                devfun_id = addr_array[2]

                use_port = self.conf.check_port_available(pci_bus)\
                    if self.crb["My IP"] == self.crb["tester IP"] \
                    else self.conf.check_port_available_peer(pci_bus)

                if not use_port:
                    continue

                is_bind = self.send_expect('ls /sys/bus/pci/drivers/ena/%s\:%s\:%s'
                                           % (domain_id, bus_id, devfun_id), '# ')
                if 'No such file' in is_bind:
                    self.send_expect('echo %s > /sys/bus/pci/devices/%s\:%s\:%s/driver/unbind'
                                     % (pci_bus, domain_id, bus_id, devfun_id), '# ')
                    # bind to linux kernel driver
                    self.send_expect("modprobe ena", '# ')
                    self.send_expect("echo {} > /sys/bus/pci/drivers/ena/bind".
                                     format(pci_bus), '# ')

                port = net_device.GetNicObj(self, domain_id, bus_id, devfun_id)
                itf = port.get_interface_name()
                self.send_expect("ifconfig %s up" % itf, "# ")

                sleep(10)   # wait for port start
                ip = port.get_ipv4_addr()

                static_ip = self.conf.get_port_ip_peer(pci_bus)\
                    if self.crb["My IP"] == self.crb["tester IP"] \
                    else self.conf.get_port_ip(pci_bus)
                if static_ip is not None:
                    self.send_expect("ifconfig {} {}".format(itf, static_ip), self.prompt)
                    continue

                p_ip, mask = self.get_port_cfg(port)
                if p_ip is None:
                    print("Cannot get IP from metadata. Use interface ip: {}".format(ip))
                    continue

                if ip == p_ip:
                    continue

                version = self.send_expect("uname -a", self.prompt)
                if "Ubuntu" in version:
                    self.configure_interface_ubuntu(port, p_ip, mask)
                elif "el7" in version or "amzn" in version:
                    self.configure_interface_rhel(port, p_ip, mask)
                else:
                    raise ValueError("Cannot configure IP for interface {}. "
                                     "Please check your network configuration."
                                     .format(itf))
            else:
                self.logger.info("NOT FOUND DRIVER FOR PORT (%s|%s)!!!" % (pci_bus, pci_id))
        sleep(2)

    def configure_interface_rhel(self, port, ip, mask):
        cmd = "ifconfig {}".format(port.get_interface_name())
        mask = self.cidr_to_netmask(mask)
        self.send_expect("{} {}".format(cmd, ip), self.prompt)
        self.send_expect("{} netmask {}".format(cmd, mask), self.prompt)

    def get_port_cfg(self, port):
        try:
            p = self.prompt
            cmd = "curl http://169.254.169.254/latest/meta-data/" \
                  "network/interfaces/macs/{}/{{}} -w \"\\n\""
            cmd = cmd.format(port.get_mac_addr())
            ip = self.send_expect(cmd.format("local-ipv4s"), p)
            ip = ip.split("\n")[0]
            subnet = self.send_expect(cmd.format("subnet-ipv4-cidr-block"), p)
            subnet = subnet.split("\n")[0]
            mask = subnet.split("/")[1]
        except Exception as e:
            ip = None
            mask = None
        return ip, mask

    # Base on aws.amazon.com/premiumsupport/knowledge-center/
    #           ec2-ubuntu-secondary-network-interface/
    def configure_interface_ubuntu(self, port, ip, mask):
        itf = port.get_interface_name()
        release = self.send_expect("lsb_release -r", self.prompt)
        if "18" in release or "20" in release:
            self.configure_interface_ubuntu18(itf, ip, mask)
        elif "16" in release:
            self.configure_interface_ubuntu16(itf, ip, mask)
        else:
            self.configure_interface_ubuntu14(itf, ip, mask)

    def mk_dir(self, dirname):
        self.send_expect("mkdir -p {}".format(dirname), self.prompt)

    def rm_f_dir(self, dirname):
        self.send_expect("rm -rf {}".format(dirname), self.prompt)

    def save_file(self, name, content):
        self.send_expect("rm {}".format(name), self.prompt)
        for line in content.split("\n"):
            self.send_expect("echo \"{}\" >> {}".format(line, name),
                             self.prompt)

    def configure_interface_ubuntu18(self, itf, ip, mask):
        file_name = "/etc/netplan/51-{}.yaml".format(itf)

        # "Note that Netplan uses YAML format and indentation is crucial."
        file_content = """network:
  version: 2
  renderer: networkd
  ethernets:
    {itf}:
      addresses:
       - {ip}/{mask}
      dhcp4: no
      routes:
       - to: {ip}
         via: 0.0.0.0
         scope: link
         table: 1000
      routing-policy:
        - from: {ip}
          table: 1000
""".format(itf=itf, ip=ip, mask=mask)
        self.save_file(file_name, file_content)
        self.send_expect("netplan --debug apply", self.prompt, timeout=120)

    def configure_interface_ubuntu16(self, itf, ip, mask):
        self.configure_interface_ubuntu16_14(itf, ip, mask)
        self.send_expect("systemctl restart networking",
                         self.prompt, timeout=120)

    def configure_interface_ubuntu14(self, itf, ip, mask):
        self.configure_interface_ubuntu16_14(itf, ip, mask)
        self.send_expect("ifdown {itf} && ifup {itf}".format(itf=itf),
                         self.prompt, timeout=120)

    def configure_interface_ubuntu16_14(self, itf, ip, mask):
        config_name = "/etc/network/interfaces.d/51-{}.cfg".format(itf)
        config_content = """auto {itf}
iface {itf} inet static
address {ip}
netmask {mask}

# Routes and rules
up ip route add {ip} dev {itf} table 1000
up ip rule add from {ip} lookup 1000
""".format(itf=itf, mask=self.cidr_to_netmask(mask), ip=ip)
        self.save_file(config_name, config_content)

    def cidr_to_netmask(self, cidr):
        cidr = int(cidr)
        mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
        return (str((0xff000000 & mask) >> 24) + '.' +
                str((0x00ff0000 & mask) >> 16) + '.' +
                str((0x0000ff00 & mask) >> 8) + '.' +
                str((0x000000ff & mask)))

    def kill(self):
        for process in ["testpmd", "pktgen", "scapy", "ping-echo", "latency",
                        "stress", "reset", "gdb"]:
            self.send_expect("killall {}".format(process), "# ")

    def free_hugepage(self):
        self.send_expect("HUGEPGSZ=`cat /proc/meminfo  | grep Hugepagesize | cut -d : -f 2 | tr -d ' '`", "# ")
        self.send_expect("echo > .echo_tmp", "# ")
        command = 'for d in /sys/devices/system/node/node? ; do echo "echo 0 > $d/hugepages/hugepages-${HUGEPGSZ}/nr_hugepages" >> .echo_tmp; done'
        self.send_expect(command, "# ")
        self.send_expect("sudo sh .echo_tmp", "# ")
        self.send_expect("rm -f .echo_tmp", "# ")

    def to_base_dir(self):
        self.send_expect("cd {}".format(self.base_dir), "# ")

    def setup_memory(self, hugepages=-1):
        """
        Setup hugepage on DUT.
        """
        if self.get_os_type() == 'linux':
            self.setup_memory_linux(hugepages)
        else:
            self.setup_memory_freebsd(hugepages)

    def setup_memory_linux(self, hugepages=-1):
        """
        Setup Linux hugepages.
        """
        if self.virttype == 'XEN':
            return
        hugepages_size = self.send_expect("awk '/Hugepagesize/ {print $2}' /proc/meminfo", "# ")
        total_memory = self.send_expect("awk '/MemTotal/ {print $2}' /proc/meminfo", "# ")
        max_hugepages = (int(total_memory) - self.FREE_MEMORY) / int(hugepages_size)
        max_hugepages = 1 << ((max_hugepages-1).bit_length() - 1)
        force_socket = False

        if int(hugepages_size) < (1024 * 1024):
            if self.architecture == "x86_64":
                arch_huge_pages = hugepages if hugepages > 0 else 4096
                arch_huge_pages = min(arch_huge_pages, max_hugepages)
            elif self.architecture == "i686":
                arch_huge_pages = hugepages if hugepages > 0 else 512
                force_socket = True
            # set huge pagesize for x86_x32 abi target
            elif self.architecture == "x86_x32":
                arch_huge_pages = hugepages if hugepages > 0 else 256
                force_socket = True
            elif self.architecture == "ppc_64":
                arch_huge_pages = hugepages if hugepages > 0 else 512
            elif self.architecture == "arm64":
                if hugepages_size == "524288":
                    arch_huge_pages = hugepages if hugepages > 0 else 8
                else:
                    arch_huge_pages = hugepages if hugepages > 0 else 2048

        if force_socket:
            self.set_huge_pages(arch_huge_pages, 0)
        else:
            self.set_huge_pages(arch_huge_pages)

        self.mount_huge_pages()
        self.hugepage_path = self.strip_hugepage_path()

    def setup_memory_freebsd(self, hugepages=-1):
        """
        Setup Freebsd hugepages.
        """
        if hugepages is -1:
            hugepages = 4096

        num_buffers = hugepages / 1024
        if num_buffers:
            self.send_expect('kenv hw.contigmem.num_buffers=%d' % num_buffers, "#")

        self.send_expect("kldunload contigmem.ko", "#")
        self.send_expect("kldload ./%s/kmod/contigmem.ko" % self.target, "#")

    def check_setup(self, dpdk, pktgen, skip=False):
        if skip is True:
            self.logger.info("SKIPPED repositories check")
            return True

        if self.path_exist(self.base_dir) is False:
            return False

        for path in self.packages[1:]:
            path = path.split(".")[0]
            path = FOLDERS["Depends"] + "/" + path
            if os.path.isfile(path) is True:
                remote_path = "{}/{}".format(self.base_dir, path)
                if self.path_exist(remote_path) is False:
                    return False

        self.send_expect("cd {}".format(self.base_dir), "#")

        if not self.check_repo(dpdk):
            return False

        self.send_expect("cd pktgen", "#")
        if not self.check_repo(pktgen):
            return False

        return True

    def check_repo(self, repo):
        out = self.send_expect("git --no-pager remote -v", "#")
        if repo[0] not in out:
            return False
        if repo[1] is not None:
            out = self.send_expect("git --no-pager branch", "#")
            out += self.send_expect("git --no-pager rev-parse HEAD", "#")
            return repo[1] in out
        return True

    def path_exist(self, path):
        self.send_expect("ls {}".format(path), "#")
        out = self.send_expect("echo $?", "#")
        return out == "0"

    def check_instance_type(self):
        link = "curl http://169.254.169.254/latest/dynamic/instance-identity/document -w '\\n'"
        out = self.send_expect(link, self.prompt)
        data = json.loads(out)
        if "instanceType" in data:
            return data["instanceType"]
        return ""

    def get_cpu_number(self):
        ncpu = self.send_expect("nproc", self.prompt)
        return int(ncpu)
