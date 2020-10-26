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
   * Add functions:
     - tools_path
     - config_ports
     - free_ports
   * Add class LatencyGenerator
   * Add extra constants to the SoftwarePacketGenerator class
   * Extend __init__ method of SoftwarePacketGenerator by adding configurable
     pktgen directory
   * Add methods to the SoftwarePacketGenerator class:
     - send
     - init
     - start
     - reset_all_counts
     - stats_parse
     - stats
     - queue_stats
     - pkt_counts
     - stop
     - quit
     - __kill_parent
     - end
   * Rework packet_generator method of the SoftwarePacketGenerator
"""

from __future__ import unicode_literals
import re
import string
import time
from config import IxiaConf
from ssh_connection import SSHConnection
from settings import SCAPY2IXIA, latency_echo, latency_send, latency_app
from settings import load_global_setting, HOST_DRIVER_SETTING
from settings import HOST_DRIVER_MODE_SETTING
from logger import getLogger
from exception import VerifyFailure
from utils import create_mask, gen_pcap_fpath


def tools_path(tester, prompt):
    out = tester.send_expect("ls usertools", prompt)
    return "usertools" if "No such" not in out else "tools"


def config_ports(tester, prompt, ports):
    drivername = load_global_setting(HOST_DRIVER_SETTING)
    drivermode = load_global_setting(HOST_DRIVER_MODE_SETTING)
    if drivername == "igb_uio":
        wc = "wc_activate=1" if drivermode == "wc" else ""
        tester.send_expect("modprobe uio", prompt)
        tester.send_expect("rmmod igb_uio", prompt)
        tester.send_expect(
            "insmod ./x86_64-native-linuxapp-gcc/build/"
            "lib/librte_eal/linuxapp/igb_uio/igb_uio.ko {}".format(wc), prompt)
        tester.send_expect(
            "insmod ./x86_64-native-linuxapp-gcc/kmod/igb_uio.ko"
            " {}".format(wc), prompt)
        tester.send_expect(
            "insmod ./x86_64-native-linuxapp-gcc/kernel/linux/igb_uio/igb_uio.ko"
            " {}".format(wc), prompt)
    elif drivername == "vfio-pci":
        tester.send_expect("modprobe vfio-pci", prompt)
        if drivermode == "noiommu":
            tester.send_expect(
                "echo 1 > "
                "/sys/module/vfio/parameters/enable_unsafe_noiommu_mode",
                prompt)

    bind_cmd = ""
    for port in ports:
        bind_cmd += " %s" % tester.ports_info[port]['pci']
        tester.send_expect("ifconfig {} down".format(
            tester.ports_info[port]['intf']), prompt)

    tools = tools_path(tester, prompt)
    tester.send_expect("./{}/dpdk-devbind.py --bind={} {}".
                            format(tools, drivername, bind_cmd), prompt)

    tester.setup_memory(16384)


def free_ports(tester, prompt, ports):
    bind_cmd = ""
    for port in ports:
        bind_cmd += " %s" % tester.ports_info[port]['pci']
    tools = tools_path(tester, prompt)
    com = "./{}/dpdk-devbind.py --bind=ena {}".format(tools, bind_cmd)
    tester.send_expect(com, prompt)


class LatencyGenerator:
    PROMPT_SYSTEM = "#"

    def __init__(self, tester, ports, q):
        self.tester = tester
        self.ports = ports
        self.q = q
        self.re_stats = 'P50\s*(\d+)\s*P90\s*(\d+)\s*P99\s*(\d+)\s*Timeouts\s*(\d+)'
        self.echo_started = 0

    def start_echo(self):
        config_ports(self.tester, self.PROMPT_SYSTEM, self.ports)
        self.echo_started = 1
        self.tester.send_expect("{}/{}/{} -- -q {}".format(
            latency_app, latency_echo, latency_echo, self.q), "forwarding packets")

    def stop_echo(self):
        if self.echo_started:
            self.tester.send_expect("^C", self.PROMPT_SYSTEM)
            self.echo_started = 0

    def start_test(self, mac_dst, ip_src, ip_dst, size, cnt):
        config_ports(self.tester, self.PROMPT_SYSTEM, self.ports)
        cmd = "{}/{}/{} -- -m {} -i {} -j {} -s {} -b {} -q {}".format(
            latency_app, latency_send, latency_send, mac_dst, ip_src,
            ip_dst, size, cnt, self.q)
        out = self.tester.send_expect(cmd, "Test ended", 240)

        p50 = -1
        p90 = -1
        p99 = -1
        match = re.search(self.re_stats, out, re.MULTILINE)
        if match is not None:
            p50 = match.group(1)
            p90 = match.group(2)
            p99 = match.group(3)
            loss = (100 * int(match.group(4))) / cnt
        else:
            print("Cannot read stats")
            loss = 100

        if loss != 0:
            return -1, -1, -1, loss
        return p50, p90, p99, loss

    def __kill_parent(self):
        self.tester.kill_all()
        super(type(self.tester), self.tester).kill_all()

    def end(self):
        free_ports(self.tester, self.PROMPT_SYSTEM, self.ports)
        self.__kill_parent()
        self.tester.restore_interfaces()


class SoftwarePacketGenerator():
    PROMPT_SYSTEM = "#"
    PROMPT_PKTGEN = "Pktgen:/>"
    NOT_USED_CPUS = 3
    MEMORY = 2000

    """
    Software WindRiver packet generator for performance measurement.
    """

    def __init__(self, tester, pktgen_dir=None):
        self.tester = tester
        self.pktgen_dir = pktgen_dir if pktgen_dir is not None \
            else self.tester.pktgen_dir
        self.port_configured = False
        self.bind_cmd = ""
        self.on = False
        self.ports = []

    def send(self, command, timeout=500):
        return self.tester.send_expect(command, self.PROMPT_PKTGEN, timeout)

    def packet_generator(self, portList, rate_percent):
        self.init(portList, rate_percent)
        self.start()
        time.sleep(2)
        stats = self.stats()
        self.stop()
        return stats

    # This function is called twice. Firstly - to detect queues properly, then
    # to run an actual traffic.
    # flows - specifies the number of generated pcap files, 0 for the first
    # case.
    def init(self, rx_port, tx_port, conf_d, rate_percent, ports_list=None):

        if ports_list is None:
            flows = 0
        else:
            flows = len(ports_list)
        tx_ports = []

        f_pcap = conf_d['f_pcap']
        q_nb = conf_d['queue_nb']
        mode = conf_d['mode']
        tx_flow = conf_d['tx_flow']

        # The test_perf_pcap provides custom pcap_cmd_cb
        if 'pcap_cmd' in conf_d.keys():
            pcap_cmd_cb = conf_d['pcap_cmd']
        else:
            pcap_cmd_cb = None

        if tx_port not in self.ports:
            self.ports.append(tx_port)
            tx_ports.append(tx_port)
        if rx_port not in self.ports:
            self.ports.append(rx_port)

        if not self.port_configured:
            # Rebind the card to other interface
            config_ports(self.tester, self.PROMPT_SYSTEM, self.ports)
            self.port_configured = True

        # assgin core for ports
        port_index = range(len(self.ports))
        port_map = dict(zip(self.ports, port_index))
        self.tester.init_reserved_core()

        cpu = self.tester.get_cpu_number()
        # One core for pktgen management, two cores for Linux to ensure
        # better system stability.
        cpu -= self.NOT_USED_CPUS

        # Increase maximum number of open files:
        self.tester.send_expect("ulimit -n 32768", self.tester.prompt)

        if cpu <= 0:
            raise VerifyFailure("Not enough cores for performance!!!")

        # flows == 0 means we are preparing pcap files, not using them
        _q = q_nb
        if flows != 0:
            _q = min(q_nb, flows)

        if mode == "bi":
            _q = min(cpu/2, _q)
            if _q == 0:
                map_cmd = "\"[1:1].[0]\""
                _q = 1
            else:
                map_cmd = "\"[1-{}:{}-{}].[0]\"".format(_q, _q+1, 2*_q)
        else:
            _q = min(cpu, _q)
            if mode == "tx":
                map_cmd = "\"[1:1-{}].[0]\"".format(_q)
            else:
                map_cmd = "\"[1-{}:1].[0]\"".format(_q)

        # create pcap for every port
        pcap_cmd = ""
        if f_pcap is not None:
            if tx_flow:
                assert ports_list is not None, "Ports list not known"
                pcap_cmd += "-s {}:".format(port_map[tx_port])

                if pcap_cmd_cb is None:
                    _d = conf_d['d_pcap']
                    for i in range(flows):
                        pcap_cmd += "../{},".format(
                                gen_pcap_fpath(ports_list[i], i, _d))
                    else:
                        # remove the trailing comma
                        pcap_cmd = pcap_cmd[:-1]
                else:
                    # Branch used by test_perf_pcap only
                    pcap_cmd += pcap_cmd_cb()

        # Selected 2 for -n to optimize results on Burage
        cores_mask = create_mask(self.tester.get_core_list("all"))

        self.tester.send_expect("cd {}".format(self.pktgen_dir), "#")

        pktgen_dir = self.tester.send_expect("find . -name pktgen", "#")
        assert pktgen_dir, "Cannot find pktgen executable."

        # In case build system created multiple pktgen executables,
        # use only the first one.
        pktgen_dir = pktgen_dir.splitlines()[0]
        pktgen_cmd = "{} --log-level 1 -n 4 --proc-type auto " \
            "-m {} -- -P -m {} {} ".format(pktgen_dir, self.MEMORY, map_cmd,
                    pcap_cmd)
	pktgen_cmd += "-q \"{}\"".format(conf_d['tx_rates'])

        self.send(pktgen_cmd)

        self.send("disable screen")

        self.send("set all rate %s" % rate_percent)

        self.send("lua 'require \"Pktgen\"'")

        self.on = True
        return _q

    def start(self):
        self.send("start all")

    def reset_all_counts(self):
        self.send("reset all")

    def stats_parse(self, re_s, out):
        re_s = r"\[\"{}\"\] = (\d+),".format(re_s)
        m = re.search(re_s, out, re.MULTILINE)
        if m is None:
            print("Cannot get stats from pktgen.")
            return -1
        try:
            data = m.group(1)
            return int(data)
        except:
            assert 0, "Cannot parse stats from pktgen."

    def stats(self):
        get_s = "lua \"prints('portRates', pktgen.portStats('all', 'rate'))\""
        out = self.send(get_s)

        rx_bps = self.stats_parse("mbits_rx", out)
        rx_pps = self.stats_parse("pkts_rx", out)
        tx_bps = self.stats_parse("mbits_tx", out)
        tx_pps = self.stats_parse("pkts_tx", out)

        return rx_bps, rx_pps, tx_bps, tx_pps

    def queue_stats(self):
        get_stats = "lua \"prints('', pktgen.queueStats())\""
        out = self.send(get_stats)
        return out

    def pkt_counts(self):
        get_s = "lua \"prints('portStats', pktgen.portStats('all', 'port'));\""
        out = self.send(get_s)
        data = {
            "rx_pkt": self.stats_parse("ipackets", out),
            "tx_pkt": self.stats_parse("opackets", out),
            "rx_err": self.stats_parse("ierrors", out),
            "tx_err": self.stats_parse("oerrors", out),
            "rx_drops": self.stats_parse("imissed", out),
            "rx_bytes": self.stats_parse("ibytes", out),
            "tx_bytes": self.stats_parse("obytes", out),
            "tx_delay_sec": self.stats_parse("o_sts_delay_sec", out),
            "rx_delay_sec": self.stats_parse("i_sts_delay_sec", out),
            }

        inter_frame_gap = 12
        preamble_size = 8
        crc_len = 4
        bytes_per_pkt = inter_frame_gap + preamble_size + crc_len
        data["rx_bytes"] += bytes_per_pkt * data["rx_pkt"]
        data["tx_bytes"] += bytes_per_pkt * data["tx_pkt"]
        return data

    def stop(self):
        self.send("stop all")

    def quit(self):
        if self.on:
            self.on = False
            self.tester.send_expect("quit", self.PROMPT_SYSTEM)
            self.tester.send_expect("stty -echo", self.PROMPT_SYSTEM)
            self.tester.send_expect("cd {}".format(self.tester.base_dir), self.PROMPT_SYSTEM)

    def __kill_parent(self):
        self.tester.kill_all()
        super(type(self.tester), self.tester).kill_all()

    def end(self):
        free_ports(self.tester, self.PROMPT_SYSTEM, self.ports)
        self.__kill_parent()
        self.tester.restore_interfaces()
        self.port_configured = False

    def throughput(self, portList, rate_percent=100):
        (bps_rx, _, pps_rx, _) = self.packet_generator(portList, rate_percent)
        return bps_rx, pps_rx

    def loss(self, portList, ratePercent):
        (bps_rx, bps_tx, _, _) = self.packet_generator(portList, ratePercent)
        assert bps_tx != 0
        return (float(bps_tx) - float(bps_rx)) / float(bps_tx)


class IxiaPacketGenerator(SSHConnection):

    """
    IXIA packet generator for performance measurement.
    """

    def __init__(self, tester):
        self.tester = tester
        self.NAME = 'ixia'
        self.logger = getLogger(self.NAME)
        super(IxiaPacketGenerator, self).__init__(self.get_ip_address(),
                                                  self.NAME, self.tester.get_username(),
                                                  self.get_password())
        super(IxiaPacketGenerator, self).init_log(self.logger)

        self.tcl_cmds = []
        self.chasId = None
        self.conRelation = {}

        ixiaRef = self.tester.get_external_traffic_generator()

        ixiacfg = IxiaConf()
        ixiaPorts = ixiacfg.load_ixia_config()
        if ixiaRef is None or ixiaRef not in ixiaPorts:
            return

        self.ixiaVersion = ixiaPorts[ixiaRef]["Version"]
        self.ports = ixiaPorts[ixiaRef]["Ports"]

        if ixiaPorts[ixiaRef].has_key('force100g'):
            self.enable100g = ixiaPorts[ixiaRef]['force100g']
        else:
            self.enable100g = 'disable'

        self.logger.info(self.ixiaVersion)
        self.logger.info(self.ports)

        self.tclServerIP = ixiaPorts[ixiaRef]["IP"]

        # prepare tcl shell and ixia library
        self.send_expect("tclsh", "% ")
        self.send_expect("source ./IxiaWish.tcl", "% ")
        self.send_expect("set ::env(IXIA_VERSION) %s" % self.ixiaVersion, "% ")
        out = self.send_expect("package req IxTclHal", "% ")
        self.logger.debug("package req IxTclHal return:" + out)
        if self.ixiaVersion in out:
            if not self.tcl_server_login():
                self.close()
                self.session = None
            for port in self.ports:
                port['speed'] = self.get_line_rate(self.chasId, port)

    def get_line_rate(self, chasid, port):
        return self.send_expect("stat getLineSpeed %s %s %s" % (chasid, port['card'], port['port']), '%')

    def get_ip_address(self):
        return self.tester.get_ip_address()

    def get_password(self):
        return self.tester.get_password()

    def add_tcl_cmd(self, cmd):
        """
        Add one tcl command into command list.
        """
        self.tcl_cmds.append(cmd)

    def clean(self):
        """
        Clean ownership of IXIA devices and logout tcl session.
        """
        self.close()
        self.send_expect("clearOwnershipAndLogout", "% ")

    def parse_pcap(self, fpcap):
        dump_str1 = "cmds = []\n"
        dump_str2 = "for i in rdpcap('%s', -1):\n" % fpcap
        dump_str3 = "    if 'Vxlan' in i.command():\n" + \
                    "        vxlan_str = ''\n" + \
                    "        l = len(i[Vxlan])\n" + \
                    "        vxlan = str(i[Vxlan])\n" + \
                    "        first = True\n" + \
                    "        for j in range(l):\n" + \
                    "            if first:\n" + \
                    "                vxlan_str += \"Vxlan(hexval='%02X\" %ord(vxlan[j])\n" + \
                    "                first = False\n" + \
                    "            else:\n" + \
                    "                vxlan_str += \" %02X\" %ord(vxlan[j])\n" + \
                    "        vxlan_str += \"\')\"\n" + \
                    "        command = re.sub(r\"Vxlan(.*)\", vxlan_str, i.command())\n" + \
                    "    else:\n" + \
                    "        command = i.command()\n" + \
                    "    cmds.append(command)\n" + \
                    "print cmds\n" + \
                    "exit()"

        f = open("dumppcap.py", "w")
        f.write(dump_str1)
        f.write(dump_str2)
        f.write(dump_str3)
        f.close()

        self.session.copy_file_to("dumppcap.py")
        out = self.send_expect("scapy -c dumppcap.py 2>/dev/null", "% ", 120)
        flows = eval(out)
        return flows

    def ether(self, port, src, dst, type):
        """
        Configure Ether protocol.
        """
        self.add_tcl_cmd("protocol config -ethernetType ethernetII")
        self.add_tcl_cmd('stream config -sa "%s"' % self.macToTclFormat(src))
        self.add_tcl_cmd('stream config -da "%s"' % self.macToTclFormat(dst))

    def ip(self, port, frag, src, proto, tos, dst, chksum, len, version, flags, ihl, ttl, id, options=None):
        """
        Configure IP protocol.
        """
        self.add_tcl_cmd("protocol config -name ip")
        self.add_tcl_cmd('ip config -sourceIpAddr "%s"' % src)
        self.add_tcl_cmd('ip config -destIpAddr "%s"' % dst)
        self.add_tcl_cmd("ip config -ttl %d" % ttl)
        self.add_tcl_cmd("ip config -totalLength %d" % len)
        self.add_tcl_cmd("ip config -fragment %d" % frag)
        self.add_tcl_cmd("ip config -ipProtocol %d" % proto)
        self.add_tcl_cmd("ip config -identifier %d" % id)
        self.add_tcl_cmd("stream config -framesize %d" % (len + 18))
        self.add_tcl_cmd("ip set %d %d %d" % (self.chasId, port['card'], port['port']))

    def macToTclFormat(self, macAddr):
        """
        Convert normal mac adress format into IXIA's format.
        """
        macAddr = macAddr.upper()
        return "%s %s %s %s %s %s" % (macAddr[:2], macAddr[3:5], macAddr[6:8], macAddr[9:11], macAddr[12:14], macAddr[15:17])

    def ipv6(self, port, version, tc, fl, plen, nh, hlim, src, dst):
        """
        Configure IPv6 protocol.
        """
        self.add_tcl_cmd("protocol config -name ipV6")
        self.add_tcl_cmd('ipV6 setDefault')
        self.add_tcl_cmd('ipV6 config -destAddr "%s"' % self.ipv6_to_tcl_format(dst))
        self.add_tcl_cmd('ipV6 config -sourceAddr "%s"' % self.ipv6_to_tcl_format(src))
        self.add_tcl_cmd('ipV6 config -flowLabel %d' % fl)
        self.add_tcl_cmd('ipV6 config -nextHeader %d' % nh)
        self.add_tcl_cmd('ipV6 config -hopLimit %d' % hlim)
        self.add_tcl_cmd('ipV6 config -trafficClass %d' % tc)
        self.add_tcl_cmd("ipV6 clearAllExtensionHeaders")
        self.add_tcl_cmd("ipV6 addExtensionHeader %d" % nh)

        self.add_tcl_cmd("stream config -framesize %d" % (plen + 40 + 18))
        self.add_tcl_cmd("ipV6 set %d %d %d" % (self.chasId, port['card'], port['port']))

    def udp(self, port, dport, sport, len, chksum):
        """
        Configure UDP protocol.
        """
        self.add_tcl_cmd("udp setDefault")
        self.add_tcl_cmd("udp config -sourcePort %d" % sport)
        self.add_tcl_cmd("udp config -destPort %d" % dport)
        self.add_tcl_cmd("udp config -length %d" % len)
        self.add_tcl_cmd("udp set %d %d %d" %
                         (self.chasId, port['card'], port['port']))

    def vxlan(self, port, hexval):
        self.add_tcl_cmd("protocolPad setDefault")
        self.add_tcl_cmd("protocol config -enableProtocolPad true")
        self.add_tcl_cmd("protocolPad config -dataBytes \"%s\"" % hexval)
        self.add_tcl_cmd("protocolPad set %d %d %d" %
                         (self.chasId, port['card'], port['port']))

    def tcp(self, port, sport, dport, seq, ack, dataofs, reserved, flags, window, chksum, urgptr, options=None):
        """
        Configure TCP protocol.
        """
        self.add_tcl_cmd("tcp setDefault")
        self.add_tcl_cmd("tcp config -sourcePort %d" % sport)
        self.add_tcl_cmd("tcp config -destPort %d" % dport)
        self.add_tcl_cmd("tcp set %d %d %d" % (self.chasId, port['card'], port['port']))

    def sctp(self, port, sport, dport, tag, chksum):
        """
        Configure SCTP protocol.
        """
        self.add_tcl_cmd("tcp config -sourcePort %d" % sport)
        self.add_tcl_cmd("tcp config -destPort %d" % dport)
        self.add_tcl_cmd("tcp set %d %d %d" % (self.chasId, port['card'], port['port']))

    def dot1q(self, port, prio, id, vlan, type):
        """
        Configure 8021Q protocol.
        """
        self.add_tcl_cmd("protocol config -enable802dot1qTag true")
        self.add_tcl_cmd("vlan config -vlanID %d" % vlan)
        self.add_tcl_cmd("vlan config -userPriority %d" % prio)
        self.add_tcl_cmd("vlan set %d %d %d" % (self.chasId, port['card'], port['port']))

    def config_stream(self, fpcap, txport, rate_percent, stream_id=1, latency=False):
        """
        Configure IXIA stream and enable mutliple flows.
        """
        flows = self.parse_pcap(fpcap)

        self.add_tcl_cmd("ixGlobalSetDefault")
        self.config_ixia_stream(rate_percent, flows, latency)

        pat = re.compile(r"(\w+)\((.*)\)")
        for flow in flows:
            for header in flow.split('/'):
                match = pat.match(header)
                params = eval('dict(%s)' % match.group(2))
                method_name = match.group(1)
                if method_name == 'Vxlan':
                    method = getattr(self, method_name.lower())
                    method(txport, **params)
                    break
                if method_name in SCAPY2IXIA:
                    method = getattr(self, method_name.lower())
                    method(txport, **params)

            self.add_tcl_cmd("stream set %d %d %d %d" % (self.chasId, txport[
                                                         'card'], txport['port'], stream_id))
            stream_id += 1

        if len(flows) > 1:
            stream_id -= 1
            self.add_tcl_cmd("stream config -dma gotoFirst")
            self.add_tcl_cmd("stream set %d %d %d %d" %
                             (self.chasId, txport['card'], txport['port'], stream_id))

    def config_ixia_stream(self, rate_percent, flows, latency):
        """
        Configure IXIA stream with rate and latency.
        Override this method if you want to add custom stream configuration.
        """
        self.add_tcl_cmd("stream config -rateMode usePercentRate")
        self.add_tcl_cmd("stream config -percentPacketRate %s" % rate_percent)
        self.add_tcl_cmd("stream config -numFrames 1")
        if len(flows) == 1:
            self.add_tcl_cmd("stream config -dma contPacket")
        else:
            self.add_tcl_cmd("stream config -dma advance")
        # request by packet Group
        if latency is not False:
            self.add_tcl_cmd("stream config -fir true")

    def tcl_server_login(self):
        """
        Connect to tcl server and take ownership of all the ports needed.
        """
        out = self.send_expect("ixConnectToTclServer %s" % self.tclServerIP, "% ", 30)
        self.logger.debug("ixConnectToTclServer return:" + out)
        if out.strip()[-1] != '0':
            return False

        self.send_expect("ixLogin IxiaTclUser", "% ")

        out = self.send_expect("ixConnectToChassis %s" % self.tclServerIP, "% ", 30)
        if out.strip()[-1] != '0':
            return False

        out = self.send_expect("set chasId [ixGetChassisID %s]" % self.tclServerIP, "% ")
        self.chasId = int(out.strip())

        self.send_expect("ixClearOwnership [list %s]" % string.join(
            ['[list %d %d %d]' % (self.chasId, item['card'], item['port']) for item in self.ports], ' '), "% ", 10)
        self.send_expect("ixTakeOwnership [list %s] force" % string.join(
            ['[list %d %d %d]' % (self.chasId, item['card'], item['port']) for item in self.ports], ' '), "% ", 10)

        return True

    def tcl_server_logout(self):
        """
        Disconnect to tcl server and make sure has been logged out.
        """
        self.send_expect("ixDisconnectFromChassis %s" % self.tclServerIP, "%")
        self.send_expect("ixLogout", "%")
        self.send_expect("ixDisconnectTclServer %s" % self.tclServerIP, "%")

    def config_port(self, pList):
        """
        Configure ports and make them ready for performance validation.
        """
        pl = list()
        for item in pList:
            self.add_tcl_cmd("port setFactoryDefaults chasId %d %d" % (
                item['card'], item['port']))
            # if the line rate is 100G and we need this port work in 100G mode,
            # we need to add some configure to make it so.
            if int(self.get_line_rate(self.chasId, item).strip()) == 100000 and self.enable100g == 'enable':
                self.add_tcl_cmd("port config -ieeeL1Defaults 0")
                self.add_tcl_cmd("port config -autonegotiate false")
                self.add_tcl_cmd("port config -enableRsFec true")
                self.add_tcl_cmd("port set %d %d %d" % (self.chasId, item['card'], item['port']))

            pl.append('[list %d %d %d]' % (self.chasId, item['card'], item['port']))

        self.add_tcl_cmd("set portList [list %s]" % string.join(pl, ' '))

        self.add_tcl_cmd("ixClearTimeStamp portList")
        self.add_tcl_cmd("ixWritePortsToHardware portList")
        self.add_tcl_cmd("ixCheckLinkState portList")

    def set_ixia_port_list(self, pList):
        """
        Implement ports/streams configuration on specified ports.
        """
        self.add_tcl_cmd("set portList [list %s]" %
                         string.join(['[list %d %d %d]' %
                                      (self.chasId, item['card'], item['port']) for item in pList], ' '))

    def send_ping6(self, pci, mac, ipv6):
        """
        Send ping6 packet from IXIA ports.
        """
        self.send_expect("source ./ixTcl1.0/ixiaPing6.tcl", "% ")
        out = self.send_expect('ping6 "%s" "%s" %d %d %d' %
                               (self.ipv6_to_tcl_format(ipv6), self.macToTclFormat(mac), self.chasId, self.pci_to_port(pci)['card'], self.pci_to_port(pci)['port']), "% ", 90)
        return out

    def ipv6_to_tcl_format(self, ipv6):
        """
        Convert normal IPv6 address to IXIA format.
        """
        ipv6 = ipv6.upper()
        singleAddr = ipv6.split(":")
        if '' == singleAddr[0]:
            singleAddr = singleAddr[1:]
        if '' in singleAddr:
            tclFormatAddr = ''
            addStr = '0:' * (8 - len(singleAddr)) + '0'
            for i in range(len(singleAddr)):
                if singleAddr[i] == '':
                    tclFormatAddr += addStr + ":"
                else:
                    tclFormatAddr += singleAddr[i] + ":"
            tclFormatAddr = tclFormatAddr[0:len(tclFormatAddr) - 1]
            return tclFormatAddr
        else:
            return ipv6

    def get_ports(self):
        """
        API to get ixia ports
        """
        plist = list()
        if self.session is None:
            return plist

        for p in self.ports:
            plist.append({'type': 'ixia', 'pci': 'IXIA:%d.%d' % (p['card'], p['port'])})
        return plist

    def pci_to_port(self, pci):
        """
        Convert IXIA fake pci to IXIA port.
        """
        ixia_pci_regex = "IXIA:(\d*).(\d*)"
        m = re.match(ixia_pci_regex, pci)
        if m is None:
            return {'card': -1, 'port': -1}

        return {'card': int(m.group(1)), 'port': int(m.group(2))}

    def loss(self, portList, ratePercent, delay=5):
        """
        Run loss performance test and return loss rate.
        """
        rxPortlist, txPortlist = self._configure_everything(portList, ratePercent)
        return self.get_loss_packet_rate(rxPortlist, txPortlist, delay)

    def get_loss_packet_rate(self, rxPortlist, txPortlist, delay=5):
        """
        Get RX/TX packet statistics and calculate loss rate.
        """
        time.sleep(delay)

        self.send_expect("ixStopTransmit portList", "%", 10)
        time.sleep(2)
        sendNumber = 0
        for port in txPortlist:
            self.stat_get_stat_all_stats(port)
            sendNumber += self.get_frames_sent()
            time.sleep(0.5)

        self.logger.info("send :%f" % sendNumber)

        assert sendNumber != 0

        revNumber = 0
        for port in rxPortlist:
            self.stat_get_stat_all_stats(port)
            revNumber += self.get_frames_received()
        self.logger.info("rev  :%f" % revNumber)

        return float(sendNumber - revNumber) / sendNumber, sendNumber, revNumber

    def latency(self, portList, ratePercent, delay=5):
        """
        Run latency performance test and return latency statistics.
        """
        rxPortlist, txPortlist = self._configure_everything(portList, ratePercent, True)
        return self.get_packet_latency(rxPortlist)

    def get_packet_latency(self, rxPortlist):
        """
        Stop IXIA transmit and return latency statistics.
        """
        latencyList = []
        time.sleep(10)
        self.send_expect("ixStopTransmit portList", "%", 10)
        for rx_port in rxPortlist:
            self.pktGroup_get_stat_all_stats(rx_port)
            latency = {"port": rx_port,
                       "min": self.get_min_latency(),
                       "max": self.get_max_latency(),
                       "average": self.get_average_latency()}
            latencyList.append(latency)
        return latencyList

    def throughput(self, port_list, rate_percent=100, delay=5):
        """
        Run throughput performance test and return throughput statistics.
        """
        rxPortlist, txPortlist = self._configure_everything(port_list, rate_percent)
        return self.get_transmission_results(rxPortlist, txPortlist, delay)

    """
    This function could be used to check the packets' order whether same as the receive sequence.
    Please notice that this function only support single-stream mode.
    """
    def is_packet_ordered(self, port_list, delay):
        rxPortlist, txPortlist = self.prepare_port_list(port_list)
        self.prepare_ixia_for_transmission(txPortlist, rxPortlist)
        self.send_expect('port config -receiveMode [expr $::portCapture|$::portRxSequenceChecking|$::portRxModeWidePacketGroup]', '%')
        self.send_expect('port config -autonegotiate true', '%')
        self.send_expect('ixWritePortsToHardware portList', '%')
        self.send_expect('set streamId 1', '%')
        self.send_expect('stream setDefault', '%')
        self.send_expect('ixStartPortPacketGroups %d %d %d' % (self.chasId, self.ports[0]['card'], self.ports[0]['port']), '%')
        self.send_expect('ixStartTransmit portList', '%')
        self.send_expect('after 1000 * %d' % delay, '%')
        self.send_expect('ixStopTransmit portList', '%')
        self.send_expect('ixStopPortPacketGroups %d %d %d' % (self.chasId, self.ports[0]['card'], self.ports[0]['port']), '%')
        self.send_expect('packetGroupStats get %d %d %d 1 1' % (self.chasId, self.ports[0]['card'], self.ports[0]['port']), '%')
        self.send_expect('packetroupStats getGroup 1', '%')
        self.send_expect('set reverseSequenceError [packetGroupStats cget -reverseSequenceError]]', '%')
        output = self.send_expect('puts $reverseSequenceError', '%')
        return int(output[:-2])

    def _configure_everything(self, port_list, rate_percent, latency=False):
        """
        Prepare and configure IXIA ports for performance test.
        """
        rxPortlist, txPortlist = self.prepare_port_list(port_list, rate_percent, latency)
        self.prepare_ixia_for_transmission(txPortlist, rxPortlist)
        self.configure_transmission()
        self.start_transmission()
        self.clear_tcl_commands()
        return rxPortlist, txPortlist

    def clear_tcl_commands(self):
        """
        Clear all commands in command list.
        """
        del self.tcl_cmds[:]

    def start_transmission(self):
        """
        Run commands in command list.
        """
        fileContent = "\n".join(self.tcl_cmds) + "\n"
        self.tester.create_file(fileContent, 'ixiaConfig.tcl')
        self.send_expect("source ixiaConfig.tcl", "% ", 75)

    def configure_transmission(self, latency=False):
        """
        Start IXIA ports transmition.
        """
        self.add_tcl_cmd("ixStartTransmit portList")

    def prepare_port_list(self, portList, rate_percent=100, latency=False):
        """
        Configure stream and flow on every IXIA ports.
        """
        txPortlist = set()
        rxPortlist = set()

        for (txPort, rxPort, pcapFile) in portList:
            txPortlist.add(txPort)
            rxPortlist.add(rxPort)

        # port init
        self.config_port([self.pci_to_port(
            self.tester.get_pci(port)) for port in txPortlist.union(rxPortlist)])

        # stream/flow setting
        for (txPort, rxPort, pcapFile) in portList:
            self.config_stream(pcapFile, self.pci_to_port(self.tester.get_pci(txPort)), rate_percent, 1, latency)

        # config stream before packetGroup
        if latency is not False:
            for (txPort, rxPort, pcapFile) in portList:
                flow_num = len(self.parse_pcap(pcapFile))
                self.config_pktGroup_rx(self.pci_to_port(self.tester.get_pci(rxPort)))
                self.config_pktGroup_tx(self.pci_to_port(self.tester.get_pci(txPort)))
        return rxPortlist, txPortlist

    def prepare_ixia_for_transmission(self, txPortlist, rxPortlist):
        """
        Clear all statistics and implement configuration to IXIA hareware.
        """
        self.add_tcl_cmd("ixClearStats portList")
        self.set_ixia_port_list([self.pci_to_port(self.tester.get_pci(port)) for port in txPortlist])
        self.add_tcl_cmd("ixWriteConfigToHardware portList")
        for port in txPortlist:
            self.start_pktGroup(self.pci_to_port(self.tester.get_pci(port)))
        for port in rxPortlist:
            self.start_pktGroup(self.pci_to_port(self.tester.get_pci(port)))

    def hook_transmission_func(self):
        pass

    def get_transmission_results(self, rx_port_list, tx_port_list, delay=5):
        """
        Override this method if you want to change the way of getting results
        back from IXIA.
        """
        time.sleep(delay)
        bpsRate = 0
        rate = 0
        oversize = 0
        for port in rx_port_list:
            self.stat_get_rate_stat_all_stats(port)
            out = self.send_expect("stat cget -framesReceived", '%', 10)
            rate += int(out.strip())
            out = self.send_expect("stat cget -bitsReceived", '% ', 10)
            self.logger.debug("port %d bits rate:" % (port) + out)
            bpsRate += int(out.strip())
            out = self.send_expect("stat cget -oversize", '%', 10)
            oversize += int(out.strip())

        self.logger.info("Rate: %f Mpps" % (rate * 1.0 / 1000000))
        self.logger.info("Mbps rate: %f Mbps" % (bpsRate * 1.0 / 1000000))

        self.hook_transmission_func()

        self.send_expect("ixStopTransmit portList", "%", 30)

        if rate == 0 and oversize > 0:
            return (bpsRate, oversize)
        else:
            return (bpsRate, rate)

    def config_ixia_dcb_init(self, rxPort, txPort):
        """
        Configure Ixia for DCB.
        """
        self.send_expect("source ./ixTcl1.0/ixiaDCB.tcl", "% ")
        self.send_expect("configIxia %d %s" % (self.chasId, string.join(["%s" % (
            repr(self.conRelation[port][n])) for port in [rxPort, txPort] for n in range(3)])), "% ", 100)

    def config_port_dcb(self, direction, tc):
        """
        Configure Port for DCB.
        """
        self.send_expect("configPort %s %s" % (direction, tc), "% ", 100)

    def cfgStreamDcb(self, stream, rate, prio, types):
        """
        Configure Stream for DCB.
        """
        self.send_expect("configStream %s %s %s %s" % (stream, rate, prio, types), "% ", 100)

    def get_connection_relation(self, dutPorts):
        """
        Get the connect relations between DUT and Ixia.
        """
        for port in dutPorts:
            info = self.tester.get_pci(self.tester.get_local_port(port)).split('.')
            self.conRelation[port] = [int(info[0]), int(info[1]), repr(self.tester.dut.get_mac_address(port).replace(':', ' ').upper())]
        return self.conRelation

    def config_pktGroup_rx(self, rxport):
        """
        Sets the transmit Packet Group configuration of the stream
        Default streamID is 1
        """
        self.add_tcl_cmd("port config -receiveMode $::portRxModeWidePacketGroup")
        self.add_tcl_cmd("port set %d %d %d" % (self.chasId, rxport['card'], rxport['port']))
        self.add_tcl_cmd("packetGroup setDefault")
        self.add_tcl_cmd("packetGroup config -latencyControl cutThrough")
        self.add_tcl_cmd("packetGroup setRx %d %d %d" % (self.chasId, rxport['card'], rxport['port']))
        self.add_tcl_cmd("packetGroup setTx %d %d %d 1" % (self.chasId, rxport['card'], rxport['port']))

    def config_pktGroup_tx(self, txport):
        """
        Configure tx port pktGroup for latency.
        """
        self.add_tcl_cmd("packetGroup setDefault")
        self.add_tcl_cmd("packetGroup config -insertSignature true")
        self.add_tcl_cmd("packetGroup setTx %d %d %d 1" % (self.chasId,
                                                           txport['card'], txport['port']))

    def start_pktGroup(self, port):
        """
        Start tx port pktGroup for latency.
        """
        self.add_tcl_cmd("ixStartPortPacketGroups %d %d %d" % (self.chasId,
                                                               port['card'], port['port']))

    def pktGroup_get_stat_all_stats(self, port_number):
        """
        Stop Packet Group operation on port and get current Packet Group
        statistics on port.
        """
        port = self.pci_to_port(self.tester.get_pci(port_number))
        self.send_expect("ixStopPortPacketGroups %d %d %d" % (self.chasId, port['card'], port['port']), "%", 100)
        self.send_expect("packetGroupStats get %d %d %d 0 16384" % (self.chasId, port['card'], port['port']), "%", 100)
        self.send_expect("packetGroupStats getGroup 0", "%", 100)

    def close(self):
        """
        We first close the tclsh session opened at the beggining,
        then the SSH session.
        """
        if self.isalive():
            self.send_expect('exit', '# ')
            super(IxiaPacketGenerator, self).close()

    def stat_get_stat_all_stats(self, port_number):
        """
        Sends a IXIA TCL command to obtain all the stat values on a given port.
        """
        port = self.pci_to_port(self.tester.get_pci(port_number))
        command = 'stat get statAllStats {0} {1} {2}'
        command = command.format(self.chasId, port['card'], port['port'])
        self.send_expect(command, '% ', 10)

    def prepare_ixia_internal_buffers(self, port_number):
        """
        Tells IXIA to prepare the internal buffers were the frames were captured.
        """
        port = self.pci_to_port(self.tester.get_pci(port_number))
        command = 'capture get {0} {1} {2}'
        command = command.format(self.chasId, port['card'], port['port'])
        self.send_expect(command, '% ', 30)

    def stat_get_rate_stat_all_stats(self, port_number):
        """
        All statistics of specified IXIA port.
        """
        port = self.pci_to_port(self.tester.get_pci(port_number))
        command = 'stat getRate statAllStats {0} {1} {2}'
        command = command.format(self.chasId, port['card'], port['port'])
        self.send_expect(command, '% ', 30)
        out = self.send_expect(command, '% ', 30)

    def ixia_capture_buffer(self, port_number, first_frame, last_frame):
        """
        Tells IXIA to load the captured frames into the internal buffers.
        """
        port = self.pci_to_port(self.tester.get_pci(port_number))
        command = 'captureBuffer get {0} {1} {2} {3} {4}'
        command = command.format(self.chasId, port['card'], port['port'],
                                 first_frame, last_frame)
        self.send_expect(command, '%', 60)

    def ixia_export_buffer_to_file(self, frames_filename):
        """
        Tells IXIA to dump the frames it has loaded in its internal buffer to a
        text file.
        """
        command = 'captureBuffer export %s' % frames_filename
        self.send_expect(command, '%', 30)

    def _stat_cget_value(self, requested_value):
        """
        Sends a IXIA TCL command to obtain a given stat value.
        """
        command = "stat cget -" + requested_value
        result = self.send_expect(command, '%', 10)
        return int(result.strip())

    def _capture_cget_value(self, requested_value):
        """
        Sends a IXIA TCL command to capture certain number of packets.
        """
        command = "capture cget -" + requested_value
        result = self.send_expect(command, '%', 10)
        return int(result.strip())

    def _packetgroup_cget_value(self, requested_value):
        """
        Sends a IXIA TCL command to get pktGroup stat value.
        """
        command = "packetGroupStats cget -" + requested_value
        result = self.send_expect(command, '%', 10)
        return int(result.strip())

    def number_of_captured_packets(self):
        """
        Returns the number of packets captured by IXIA on a previously set
        port. Call self.stat_get_stat_all_stats(port) before.
        """
        return self._capture_cget_value('nPackets')

    def get_frames_received(self):
        """
        Returns the number of packets captured by IXIA on a previously set
        port. Call self.stat_get_stat_all_stats(port) before.
        """
        if self._stat_cget_value('framesReceived') != 0:
            return self._stat_cget_value('framesReceived')
        else:
            # if the packet size is large than 1518, this line will avoid return
            # a wrong number
            return self._stat_cget_value('oversize')

    def get_flow_control_frames(self):
        """
        Returns the number of control frames captured by IXIA on a
        previously set port. Call self.stat_get_stat_all_stats(port) before.
        """
        return self._stat_cget_value('flowControlFrames')

    def get_frames_sent(self):
        """
        Returns the number of packets sent by IXIA on a previously set
        port. Call self.stat_get_stat_all_stats(port) before.
        """
        return self._stat_cget_value('framesSent')

    def get_transmit_duration(self):
        """
        Returns the duration in nanosecs of the last transmission on a
        previously set port. Call self.stat_get_stat_all_stats(port) before.
        """
        return self._stat_cget_value('transmitDuration')

    def get_min_latency(self):
        """
        Returns the minimum latency in nanoseconds of the frames in the
        retrieved capture buffer. Call packetGroupStats get before.
        """
        return self._packetgroup_cget_value('minLatency')

    def get_max_latency(self):
        """
        Returns the maximum latency in nanoseconds of the frames in the
        retrieved capture buffer. Call packetGroupStats get before.
        """
        return self._packetgroup_cget_value('maxLatency')

    def get_average_latency(self):
        """
        Returns the average latency in nanoseconds of the frames in the
        retrieved capture buffer. Call packetGroupStats get before.
        """
        return self._packetgroup_cget_value('averageLatency')

    def _transmission_pre_config(self, port_list, rate_percent, latency=False):
        """
        Prepare and configure IXIA ports for performance test. And remove the transmission step in this config sequence.
        This function is set only for function send_number_packets for nic_single_core_perf test case use
        """
        rxPortlist, txPortlist = self.prepare_port_list(port_list, rate_percent, latency)
        self.prepare_ixia_for_transmission(txPortlist, rxPortlist)
        self.start_transmission()
        self.clear_tcl_commands()
        return rxPortlist, txPortlist

    def send_number_packets(self, portList, ratePercent, packetNum):
        """
        Configure ixia to send fixed number of packets
        Note that this function is only set for test_suite nic_single_core_perf,
        Not for common use
        """
        rxPortlist, txPortlist = self._transmission_pre_config(portList, ratePercent)

        self.send_expect("stream config -numFrames %s" % packetNum, "%", 5)
        self.send_expect("stream config -dma stopStream", "%", 5)
        for txPort in txPortlist:
            port = self.pci_to_port(self.tester.get_pci(txPort))
            self.send_expect("stream set %d %d %d 1" % (self.chasId, port['card'], port['port']), "%", 5)

        self.send_expect("ixWritePortsToHardware portList", "%", 5)
        self.send_expect("ixClearStats portList", "%", 5)
        self.send_expect("ixStartTransmit portList", "%", 5)
        time.sleep(10)

        rxPackets = 0
        for port in txPortlist:
            self.stat_get_stat_all_stats(port)
            txPackets = self.get_frames_sent()
            while txPackets != packetNum:
                time.sleep(10)
                self.stat_get_stat_all_stats(port)
                txPackets = self.get_frames_sent()
            rxPackets += self.get_frames_received()
        self.logger.info("Received packets :%s" % rxPackets)

        return rxPackets
