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
    * Rework error logs
    * Add methods to the PortConf:
      - check_port_available_peer()
      - get_port_ip()
      - get_port_ip_peer()
    * Prase from crbs ssh key and values for 2nd tester host
"""

"""
Generic port and crbs configuration file load function
"""
import os
import re
import ConfigParser  # config parse module
import argparse      # prase arguments module
from settings import IXIA, CONFIG_ROOT_PATH, SUITE_SECTION_NAME
from settings import load_global_setting, DTS_CFG_FOLDER
from exception import ConfigParseException, VirtConfigParseException, PortConfigParseException
from utils import RED

PORTCONF = "%s/ports.cfg" % CONFIG_ROOT_PATH
CRBCONF = "%s/crbs.cfg" % CONFIG_ROOT_PATH
VIRTCONF = "%s/virt_global.cfg" % CONFIG_ROOT_PATH
IXIACONF = "%s/ixia.cfg" % CONFIG_ROOT_PATH
SUITECONF_SAMPLE = "%s/suite_sample.cfg" % CONFIG_ROOT_PATH
GLOBALCONF = "%s/global_suite.cfg" % CONFIG_ROOT_PATH


class UserConf():

    def __init__(self, config):
        self.conf = ConfigParser.SafeConfigParser()
        load_files = self.conf.read(config)
        if load_files == []:
            self.conf = None
            raise ConfigParseException(config)

    def get_sections(self):
        if self.conf is None:
            return None

        return self.conf.sections()

    def load_section(self, section):
        if self.conf is None:
            return None

        items = None
        for conf_sect in self.conf.sections():
            if conf_sect == section:
                items = self.conf.items(section)

        return items

    def load_config(self, item):
        confs = [conf.strip() for conf in item.split(';')]
        if '' in confs:
            confs.remove('')
        return confs

    def load_param(self, conf):
        paramDict = dict()

        for param in conf.split(','):
            (key, _, value) = param.partition('=')
            paramDict[key] = value
        return paramDict

class GlobalConf(UserConf):
    def __init__(self):
        self.global_cfg = {}
        try:
            self.global_conf = UserConf(GLOBALCONF)
        except ConfigParseException:
            self.global_conf = None

        # load global configuration
        self.global_cfg = self.load_global_config()

    def load_global_config(self, section_name='global'):
        global_cfg = self.global_cfg.copy()
        try:
            section_confs = self.global_conf.load_section(section_name)
        except:
            print RED("Failed to find section[%s] in the global config" % section_name)
            return global_cfg

        if section_confs is None:
            return global_cfg

        global_cfg = dict(section_confs)

        return global_cfg

class SuiteConf(UserConf):
    def __init__(self, suite_name=""):
        self.suite_cfg = GlobalConf().load_global_config()
        self.config_file = CONFIG_ROOT_PATH + os.sep + suite_name + ".cfg"
        try:
            self.suite_conf = UserConf(self.config_file)
        except ConfigParseException:
            self.suite_conf = None

        # load default suite configuration
        self.suite_cfg = self.load_case_config(SUITE_SECTION_NAME)

    def load_case_config(self, case_name=""):
        case_cfg = self.suite_cfg.copy()
        if self.suite_conf is None:
            return case_cfg

        try:
            case_confs = self.suite_conf.load_section(case_name)
        except:
            print RED("Failed to find case[%s] in the case config" % section_name)
            return case_cfg

        if case_confs is None:
            return case_cfg

        conf = dict(case_confs)
        for key, data_string in conf.items():
            if data_string.startswith("value_int:"):
                value = data_string[len("value_int:"):]
                case_cfg[key] = int(value)
            elif data_string.startswith("value_hex:"):
                value = data_string[len("value_hex:"):]
                case_cfg[key] = int(value, 16)
            elif data_string.startswith("list_int:"):
                value = data_string[len("list_int:"):]
                datas = value.split(',')
                int_list = map(lambda x: int(x), datas)
                case_cfg[key] = int_list
            elif data_string.startswith("list_str:"):
                value = data_string[len("list_str:"):]
                str_list = value.split(',')
                case_cfg[key] = str_list
            else:
                case_cfg[key] = data_string

        return case_cfg


class VirtConf(UserConf):

    def __init__(self, virt_conf=VIRTCONF):
        self.config_file = virt_conf
        self.virt_cfg = {}
        try:
            self.virt_conf = UserConf(self.config_file)
        except ConfigParseException:
            self.virt_conf = None
            raise VirtConfigParseException

    def load_virt_config(self, name):
        self.virt_cfgs = []

        try:
            virt_confs = self.virt_conf.load_section(name)
        except:
            print RED("Failed to find section[%s] in the virt config" % section_name)
            return

        for virt_conf in virt_confs:
            virt_cfg = {}
            virt_params = []
            key, config = virt_conf
            confs = self.virt_conf.load_config(config)
            for config in confs:
                virt_params.append(self.load_virt_param(config))
            virt_cfg[key] = virt_params
            self.virt_cfgs.append(virt_cfg)

    def get_virt_config(self):
        return self.virt_cfgs

    def load_virt_param(self, config):
        cfg_params = self.virt_conf.load_param(config)
        return cfg_params


class PortConf(UserConf):

    def __init__(self, port_conf=PORTCONF):
        self.config_file = port_conf
        self.ports_cfg = {}
        self.pci_regex = "([\da-f]{4}:[\da-f]{2}:[\da-f]{2}.\d{1})$"
        try:
            self.port_conf = UserConf(self.config_file)
        except ConfigParseException:
            self.port_conf = None
            raise PortConfigParseException

    def load_ports_config(self, crbIP):
        self.ports_cfg = {}
        if self.port_conf is None:
            return

        ports = self.port_conf.load_section(crbIP)
        if ports is None:
            return
        key, config = ports[0]
        confs = self.port_conf.load_config(config)

        for config in confs:
            port_param = self.port_conf.load_param(config)

            # port config for vm in virtualization scenario
            if 'dev_idx' in port_param:
                keys = port_param.keys()
                keys.remove('dev_idx')
                self.ports_cfg[port_param['dev_idx']] = {
                    key: port_param[key] for key in keys}
                continue

            # check pci BDF validity
            if 'pci' not in port_param:
                print RED("PCI configuration could not be found")
                continue
            m = re.match(self.pci_regex, port_param['pci'])
            if m is None:
                print RED("Invalid PCI address configuration")
                continue

            keys = port_param.keys()
            keys.remove('pci')
            self.ports_cfg[port_param['pci']] = {
                key: port_param[key] for key in keys}
            if 'numa' in self.ports_cfg[port_param['pci']]:
                numa_str = self.ports_cfg[port_param['pci']]['numa']
                self.ports_cfg[port_param['pci']]['numa'] = int(numa_str)

    def get_ports_config(self):
        return self.ports_cfg

    def check_port_available(self, pci_addr):
        if pci_addr in self.ports_cfg.keys():
            return True
        else:
            return False

    def check_port_available_peer(self, pci_addr):
        return pci_addr in [d["peer"] for d in self.ports_cfg.values()]

    def get_port_ip(self, pci_addr):
        if pci_addr in self.ports_cfg.keys():
            if 'ip' in self.ports_cfg[pci_addr]:
                return self.ports_cfg[pci_addr]['ip']
            else:
                return None

    def get_port_ip_peer(self, pci_addr):
        for d in self.ports_cfg.values():
            if pci_addr == d['peer']:
                if 'peer_ip' in d:
                    return d['peer_ip']
                else:
                    return None
        return None


class CrbsConf(UserConf):
    DEF_CRB = {'IP': '', 'board': 'default', 'user': '',
               'pass': '', 'tester IP': '', 'tester pass': '',
               IXIA: None, 'memory channels': 4,
               'bypass core0': True}

    def __init__(self, crbs_conf=CRBCONF):
        self.config_file = crbs_conf
        self.crbs_cfg = []
        try:
            self.crbs_conf = UserConf(self.config_file)
        except ConfigParseException:
            self.crbs_conf = None
            raise ConfigParseException

    def load_crbs_config(self):
        sections = self.crbs_conf.get_sections()
        if not sections:
            return self.crbs_cfg

        for name in sections:
            crb = self.DEF_CRB.copy()
            crb['section'] = name
            crb_confs = self.crbs_conf.load_section(name)
            if not crb_confs:
                continue

            # covert file configuration to dts crbs
            for conf in crb_confs:
                key, value = conf
                if key == 'dut_ip':
                    crb['IP'] = value
                elif key == 'dut_user':
                    crb['user'] = value
                elif key == 'dut_passwd':
                    crb['pass'] = value
                elif key == 'os':
                    crb['OS'] = value
                elif key == 'tester_ip':
                    crb['tester IP'] = value
                elif key == 'tester_passwd':
                    crb['tester pass'] = value
                elif key == 'ixia_group':
                    crb[IXIA] = value
                elif key == 'channels':
                    crb['memory channels'] = int(value)
                elif key == 'bypass_core0':
                    if value == 'True':
                        crb['bypass core0'] = True
                    else:
                        crb['bypass core0'] = False
                elif key == 'board':
                    crb['board'] = value
                elif key == 'dut_ssh_key':
                    crb['dut_ssh_key'] = value
                elif key == 'tester_user':
                    crb['tester_user'] = value
                elif key == 'tester_ssh_key':
                    crb['tester_ssh_key'] = value
                elif key == 'tester2_ip':
                    crb['tester2 IP'] = value
                elif key == 'tester2_user':
                    crb['tester2_user'] = value
                elif key == 'tester2_ssh_key':
                    crb['tester2_ssh_key'] = value

            self.crbs_cfg.append(crb)
        return self.crbs_cfg


class IxiaConf(UserConf):

    def __init__(self, ixia_conf=IXIACONF):
        self.config_file = ixia_conf
        self.ixia_cfg = {}
        try:
            self.ixia_conf = UserConf(self.config_file)
        except ConfigParseException:
            self.ixia_conf = None
            raise ConfigParseException

    def load_ixia_config(self):
        port_reg = r'card=(\d+),port=(\d+)'
        groups = self.ixia_conf.get_sections()
        if not groups:
            return self.ixia_cfg

        for group in groups:
            ixia_group = {}
            ixia_confs = self.ixia_conf.load_section(group)
            if not ixia_confs:
                continue

            # convert file configuration to dts ixiacfg
            for conf in ixia_confs:
                key, value = conf
                if key == 'ixia_version':
                    ixia_group['Version'] = value
                elif key == 'ixia_ip':
                    ixia_group['IP'] = value
                elif key == 'ixia_ports':
                    ports = self.ixia_conf.load_config(value)
                    ixia_ports = []
                    for port in ports:
                        m = re.match(port_reg, port)
                        if m:
                            ixia_port = {}
                            ixia_port["card"] = int(m.group(1))
                            ixia_port["port"] = int(m.group(2))
                            ixia_ports.append(ixia_port)
                    ixia_group['Ports'] = ixia_ports
                elif key == 'ixia_enable_rsfec':
                    ixia_group['enable_rsfec'] = value

            if 'Version' not in ixia_group:
                print RED('ixia configuration file requires ixia_version option')
                continue
            if 'IP' not in ixia_group:
                print RED('ixia configuration file requires ixia_ip option')
                continue
            if 'Ports' not in ixia_group:
                print RED('ixia configuration file requires ixia_ports option')
                continue

            self.ixia_cfg[group] = ixia_group

        return self.ixia_cfg

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Load DTS configuration files")
    parser.add_argument("-p", "--portconf", default=PORTCONF)
    parser.add_argument("-c", "--crbconf", default=CRBCONF)
    parser.add_argument("-v", "--virtconf", default=VIRTCONF)
    parser.add_argument("-i", "--ixiaconf", default=IXIACONF)
    args = parser.parse_args()

    # not existed configuration file
    try:
        VirtConf('/tmp/not-existed.cfg')
    except VirtConfigParseException:
        print "Capture config parse failure"

    # example for basic use configuration file
    conf = UserConf(PORTCONF)
    for section in conf.get_sections():
        items = conf.load_section(section)
        key, value = items[0]
        confs = conf.load_config(value)
        for config in confs:
            conf.load_param(config)

    # example for port configuration file
    portconf = PortConf(PORTCONF)
    portconf.load_ports_config('DUT IP')
    print portconf.get_ports_config()
    portconf.check_port_available('86:00.0')

    # example for global virtualization configuration file
    virtconf = VirtConf(VIRTCONF)
    virtconf.load_virt_config('LIBVIRT')
    print virtconf.get_virt_config()

    # example for crbs configuration file
    crbsconf = CrbsConf(CRBCONF)
    print crbsconf.load_crbs_config()

    # example for ixia configuration file
    ixiaconf = IxiaConf(IXIACONF)
    print ixiaconf.load_ixia_config()

    # example for suite configure file
    suiteconf = SuiteConf(SUITECONF_SAMPLE)
    print suiteconf.load_case_config("case1")
    print suiteconf.load_case_config("case2")
