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
   * Add 'patches' folder
   * Remove all NICs except ENA
   * Assign igb module to the ENA
   * Add ICMP packet header size
   * Add constants for the PCAPs
   * Add constant for Tx queue rate
   * Add latency app support
   * Add reset app support
   * Add tester prefix string
"""

"""
Folders for framework running enviornment.
"""
import os
import sys
import re
import socket

FOLDERS = {
    'Framework': 'framework',
    'Testscripts': 'tests',
    'Configuration': 'conf',
    'Depends': 'dep',
    'Output': 'output',
    'NicDriver': 'nics',
    'Patches': 'patches'
}

"""
Nics and its identifiers supported by the framework.
"""
NICS = {
    'ena': '1d0f:ec20',
}

DRIVERS = {
    'ena': 'igb',
}

"""
List used to translate scapy packets into Ixia TCL commands.
"""
SCAPY2IXIA = [
    'Ether',
    'Dot1Q',
    'IP',
    'IPv6',
    'TCP',
    'UDP',
    'SCTP'
]

USERNAME = 'root'


"""
Helpful header sizes.
"""
HEADER_SIZE = {
    'eth': 18,
    'ip': 20,
    'ipv6': 40,
    'udp': 8,
    'tcp': 20,
    'vxlan': 8,
    'icmp':  8,
}
"""
dpdk send protocol packet size.
"""
PROTOCOL_PACKET_SIZE = {
    'lldp': [110, 100],
}

"""
Default session timeout.
"""
TIMEOUT = 15


"""
Global macro for dts.
"""
IXIA = "ixia"

"""
The log name seperater.
"""
LOG_NAME_SEP = '.'

"""
Section name for suite level configuration
"""
SUITE_SECTION_NAME = "suite"

"""
DTS global environment variable
"""
DTS_ENV_PAT = r"DTS_*"
PERF_SETTING = "DTS_PERF_ONLY"
FUNC_SETTING = "DTS_FUNC_ONLY"
HOST_DRIVER_SETTING = "DTS_HOST_DRIVER"
HOST_DRIVER_MODE_SETTING = "DTS_HOST_DRIVER_MODE"
HOST_NIC_SETTING = "DTS_HOST_NIC"
DEBUG_SETTING = "DTS_DEBUG_ENABLE"
DEBUG_CASE_SETTING = "DTS_DEBUGCASE_ENABLE"
DPDK_RXMODE_SETTING = "DTS_DPDK_RXMODE"
DTS_ERROR_ENV = "DTS_RUNNING_ERROR"
DTS_CFG_FOLDER = "DTS_CFG_FOLDER"


"""
DTS global error table
"""
DTS_ERR_TBL = {
    "GENERIC_ERR": 1,
    "DPDK_BUILD_ERR" : 2,
    "DUT_SETUP_ERR" : 3,
    "TESTER_SETUP_ERR" : 4,
    "SUITE_SETUP_ERR": 5,
    "SUITE_EXECUTE_ERR": 6,
}

PCAP_DIR = "pcap"
PCAP_TESTER = "pcap_tester.pcap"
PCAP_DUT = "pcap_dut.pcap"

PCAP_FILENAME_SUFFIX = 'ena_test.pcap'

DEFAULT_QUEUE_TX_RATE = '3500'

def get_nic_name(type):
    """
    strip nic code name by nic type
    """
    for name, nic_type in NICS.items():
        if nic_type == type:
            return name
    return 'Unknown'


def get_nic_driver(pci_id):
    """
    Return linux driver for specified pci device
    """
    driverlist = dict(zip(NICS.values(), DRIVERS.keys()))
    try:
        driver = DRIVERS[driverlist[pci_id]]
    except Exception as e:
        driver = None
    return driver


def get_netdev(crb, pci):
    for port in crb.ports_info:
        if pci == port['pci']:
            return port['port']
        if 'vfs_port' in port.keys():
            for vf in port['vfs_port']:
                if pci == vf.pci:
                    return vf

    return None


def get_host_ip(address):
    ip_reg = r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}'
    m = re.match(ip_reg, address)
    if m:
        return address
    else:
        try:
            result = socket.gethostbyaddr(address)
            return result[2][0]
        except:
            print "couldn't look up %s" % address
            return ''


def save_global_setting(key, value):
    """
    Save DTS global setting
    """
    if re.match(DTS_ENV_PAT, key):
        env_key = key
    else:
        env_key = "DTS_" + key

    os.environ[env_key] = value


def load_global_setting(key):
    """
    Load DTS global setting
    """
    if re.match(DTS_ENV_PAT, key):
        env_key = key
    else:
        env_key = "DTS_" + key

    if env_key in os.environ.keys():
        return os.environ[env_key]
    else:
        return ''


def report_error(error):
    """
    Report error when error occurred
    """
    if error in DTS_ERR_TBL.keys():
        os.environ[DTS_ERROR_ENV] = error
    else:
        os.environ[DTS_ERROR_ENV] = "GENERIC_ERR"


def exit_error():
    """
    Set system exit value when error occurred
    """
    if DTS_ERROR_ENV in os.environ.keys():
        ret_val = DTS_ERR_TBL[os.environ[DTS_ERROR_ENV]]
        sys.exit(ret_val)
    else:
        sys.exit(0)


def accepted_nic(pci_id):
    """
    Return True if the pci_id is a known NIC card in the settings file and if
    it is selected in the execution file, otherwise it returns False.
    """
    nic = load_global_setting(HOST_NIC_SETTING)
    if pci_id not in NICS.values():
        return False

    if nic is 'any':
        return True

    else:
        if pci_id == NICS[nic]:
            return True

    return False

"""
The root path of framework configs.
"""
dts_cfg_folder = load_global_setting(DTS_CFG_FOLDER)
if dts_cfg_folder != '':
    CONFIG_ROOT_PATH = dts_cfg_folder
else:
    CONFIG_ROOT_PATH = "./conf"

latency_app = "latency"
latency_send = "latency"
latency_echo = "ping-echo"

reset_app = "reset"

tester_prefix = "Tester_"
