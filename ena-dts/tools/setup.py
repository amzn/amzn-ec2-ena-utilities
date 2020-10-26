#!/usr/bin/python
import sys
import os
import parse_opt
import re
import time
import ConfigParser

exec_file = os.path.realpath(__file__)
DTS_PATH = exec_file.replace('/tools/setup.py', '')

# generate file path
DTS_FRAMEWORK = DTS_PATH + '/framework'
DTS_TOOLS = DTS_PATH + '/tools'
DTS_SUITES = DTS_PATH + '/tests'
DTS_EXECS = DTS_PATH + '/executions'

DTS_EXEC_CFG = DTS_PATH + '/execution.cfg'
DTS_CRBS_CFG = DTS_PATH + '/conf/crbs.cfg'
DTS_PORTS_CFG = DTS_PATH + '/conf/ports.cfg'
DTS_IXIA_CFG = DTS_PATH + '/conf/ixia.cfg'

sys.path.append(DTS_FRAMEWORK)
sys.path.append(DTS_TOOLS)

import utils
from parse_opt import Option
from settings import NICS
from utils import GREEN, RED

global def_opt
global dut_ip
global tester_ip
global os_type
global dut_pass
global tester_pass
global dut_user
global ixia
global channel
global bypass
global suites
global executions

def_opt = '0'
dut_ip = None
tester_ip = None
ixia = None


def scan_suites():
    global suites
    suite_reg = r'TestSuite_(.*).py$'

    suites = []
    files = os.listdir(DTS_SUITES)
    for file_name in files:
        m = re.match(suite_reg, file_name)
        if m:
            suites.append(m.group(1))

    suites = sorted(suites)


def scan_executions():
    global executions
    exec_reg = r'.*.cfg'

    executions = []
    files = os.listdir(DTS_EXECS)
    for file_name in files:
        m = re.match(exec_reg, file_name)
        if m:
            executions.append(file_name)


def config_crbs():
    global dut_ip
    global tester_ip
    global os_type
    global dut_pass
    global tester_pass
    global dut_user
    global ixia
    global channel
    global bypass
    global perf_execution

    print ('============================================================')
    print "Setting DUT and Tester crb information"
    ip_option = {'prompt': 'DUT IP address',
                 'type': 'ip',
                 'help': 'Please input ip address of DUT crb',
                 'default': '127.0.0.1'}
    opt = Option(**ip_option)
    dut_ip = opt.parse_input()

    ip_option = {'prompt': 'Tester IP address',
                 'type': 'ip',
                 'help': 'Please input ip address of Tester crb',
                 'default': dut_ip}
    opt = Option(**ip_option)
    tester_ip = opt.parse_input()

    dut_user = 'root'

    passwd_option = {'prompt': 'DUT root password',
                     'type': 'string',
                     'help': 'Please input password of DUT crb',
                     'default': ''}
    opt = Option(**passwd_option)
    dut_pass = opt.parse_input()

    os_option = {'prompt': 'OS type',
                 'type': 'choice',
                 'help': 'Please choose dut operation system type',
                 'options': ['linux', 'freebsd'],
                 'default': '0'}
    opt = Option(**os_option)
    os_type = opt.parse_input()

    passwd_option = {'prompt': 'Tester root password',
                     'type': 'string',
                     'help': 'Please input password of Tester crb',
                     'default': ''}
    opt = Option(**passwd_option)
    tester_pass = opt.parse_input()

    perf_option = {'prompt': 'Whether run performance execution',
                   'type': 'bool',
                   'help': 'Run performance test or not',
                   'default': 'No'}
    opt = Option(**perf_option)
    perf_execution = opt.parse_input()

    if perf_execution:
        ixia = 'ixia group0'

    channel_option = {'prompt': 'Choice channel number',
                      'type': 'choice',
                      'help': 'Please input channel number',
                      'options': ['4', '3', '2', '1'],
                      'default': '0'}
    opt = Option(**channel_option)
    channel = opt.parse_input()

    bypass_option = {'prompt': 'Whether bypass core0',
                     'type': 'bool',
                     'help': 'If need bypass input "yes", ' +
                             'otherwise input "No"',
                     'default': 'Yes'}
    opt = Option(**bypass_option)
    bypass = opt.parse_input()


def write_crbs_cfg():
    separator = '\n'
    content = ''
    section = '[%s]' % dut_ip
    content += section
    content += separator

    crb_conf = [('dut_ip', dut_ip),
                ('dut_user', dut_user),
                ('dut_passwd', dut_pass),
                ('os', os_type),
                ('tester_ip', tester_ip),
                ('tester_passwd', tester_pass),
                ('ixia_group', ixia),
                ('channels', channel),
                ('bypass_core0', bypass)]

    for conf in crb_conf:
        key, value = conf
        conf_str = '%s=%s' % (key, value)
        content += conf_str
        content += separator

    with open(DTS_CRBS_CFG, "w") as f:
        f.write(content)


def load_execution(file_name):
    global perf_execution
    global target
    global suites
    global nic_type

    config = ConfigParser.SafeConfigParser()
    config.read(file_name)
    section = config.sections()[0]
    parameters = config.get(section, 'parameters').split(':')
    paramDict = dict()
    for param in parameters:
        (key, _, value) = param.partition('=')
        paramDict[key] = value

    targets = [target.strip()
               for target in config.get(section, 'targets').split(',')]

    target = targets[0]

    suites = [suite.strip()
              for suite in config.get(section, 'test_suites').split(',')]
    # remove useless suite
    for suite in suites:
        if suite == '':
            suites.remove(suite)

    nic_type = [_.strip() for _ in paramDict['nic_type'].split(',')][0]


def config_execution():
    global driver_name
    global suites
    global target
    global nic_type

    print ('============================================================')
    print "Setting execution plan"
    if not dut_ip:
        print RED("Need to configure 'DUT&Tester crb' first!!!")
        return False
    # default execution
    driver_name = 'igb_uio'
    target = 'x86_64-native-linuxapp-gcc'
    targets = ['x86_64-native-linuxapp-gcc', 'x86_64-native-linuxapp-icc',
               'i686-native-linuxapp-gcc', 'i686-native-linuxapp-icc',
               'x86_64-native-bsdapp-gcc', 'x86_64-native-bsdapp-clang',
               'arm64-armv8a-linuxapp-gcc', 'arm64-dpaa2-linuxapp-gcc',
               'arm64-thunderx-linuxapp-gcc', 'arm64-xgene1-linuxapp-gcc']
    nic_type = 'cfg'

    exec_option = {'prompt': 'Choose default or manually',
                   'type': 'choice',
                   'help': 'Gernerate execution file base on default or ' +
                           'manually configured',
                   'options': ['default execution file',
                               'manually configure execution file'],
                   'default': '0'}
    opt = Option(**exec_option)
    opt.parse_input()
    index = opt.choice
    if index == 0:
        autoexec_option = {'prompt': 'Choose one of them',
                           'type': 'choice',
                           'help': 'Choose one of below reference ' +
                                   'configuration file',
                           'options': executions,
                           'default': '3'}
        opt = Option(**autoexec_option)
        auto_execution = opt.parse_input()
        load_execution('executions/' + auto_execution)
    else:
        suites_option = {'prompt': 'Choose suites to run',
                         'type': 'multichoice',
                         'help': 'Suites in DTS',
                         'options': suites,
                         'default': 'all'}
        opt = Option(**suites_option)
        suites = opt.parse_input()

    nics = ['cfg']
    nics += NICS.keys()
    nic_option = {'prompt': 'Choose one of nics',
                  'type': 'choice',
                  'help': 'Choose one of dpdk support NIC',
                  'options': nics,
                  'default': '0'}
    opt = Option(**nic_option)
    nic_type = opt.parse_input()

    target_option = {'prompt': 'Choose target for execution',
                     'type': 'choice',
                     'help': 'Choose one of dpdk targets',
                     'options': targets,
                     'default': '0'}
    opt = Option(**target_option)
    target = opt.parse_input()

    driver_option = {'prompt': 'Choose one of them',
                     'type': 'choice',
                     'help': 'Choose one of dpdk support driver',
                     'options': ['igb_uio', 'vfio-pci', 'vfio-pci:noiommu'],
                     'default': '0'}
    opt = Option(**driver_option)
    driver_name = opt.parse_input()

    return True


def write_exec_cfg():
    separator = '\n'
    content = ''

    section = '[%s]' % dut_ip
    content += section
    content += separator

    crb_conf = [('crbs', dut_ip),
                ('drivername', driver_name)]

    for conf in crb_conf:
        key, value = conf
        conf_str = '%s=%s' % (key, value)
        content += conf_str
        content += separator

    content += 'test_suites='
    content += separator
    for suite in suites:
        content += '    %s,' % suite
        content += separator

    content += 'targets='
    content += separator
    content += '    %s' % target
    content += separator

    content += 'parameters='
    content += 'nic_type=%s:' % nic_type

    if perf_execution:
        content += 'perf=true'
    else:
        content += 'func=true'

    with open(DTS_EXEC_CFG, "w") as f:
        f.write(content)


def config_ixia():
    global version
    global ixia_ip
    global ixia_ports

    print ('============================================================')
    print 'Setting IXIA port for performance validation'
    ixia_ports = []
    if ixia is None or ixia == '':
        print RED("Performance request configure IXIA group in "
                  "'DUT&Tester crb' first!!!")
        return False

    version_option = {'prompt': 'IXIA Server version',
                      'type': 'string',
                      'help': 'Please input version of IxServer',
                      'default': '6.62'}
    opt = Option(**version_option)
    version = opt.parse_input()

    ixiaip_option = {'prompt': 'IXIA ip address',
                     'type': 'ip',
                     'help': 'Please input ip address of IXIA',
                     'default': '127.0.0.1'}
    opt = Option(**ixiaip_option)
    ixia_ip = opt.parse_input()

    ixiaport_option = {'prompt': 'IXIA ports which are members of this ' +
                                 'ports group',
                       'type': 'string',
                       'help': 'Please input IXIA ports, format is ' +
                               'card1.port1,card2.port2',
                       'default': ''}
    opt = Option(**ixiaport_option)
    port_opt = opt.parse_input()
    ports = port_opt.split(',')
    for port in ports:
        ixia_port = port.split('.')
        if len(ixia_port) == 2:
            ixia_ports.append((ixia_port[0], ixia_port[1]))

    return True


def write_ixia_cfg():
    separator = '\n'
    content = ''

    section = '[%s]' % ixia
    content += section
    content += separator

    content += 'ixia_version=%s' % version
    content += separator

    content += 'ixia_ip=%s' % ixia_ip
    content += separator

    content += 'ixia_ports='
    content += separator

    for ixia_port in ixia_ports:
        card, port = ixia_port
        content += '    card=%s,port=%s;' % (card, port)
        content += separator

    with open(DTS_IXIA_CFG, "w") as f:
        f.write(content)


def config_ports():
    global dut_ports
    dut_ports = []
    add_more = True
    pci_regex = "([\da-f]{4}:[\da-f]{2}:[\da-f]{2}.\d{1})$"
    ixia_regex = r'(\d).(\d)'

    print ('============================================================')
    print ("Manually configure DUT port mapping")
    if not dut_ip:
        print RED("Need to configuure 'DUT&Tester crb' first!!!")
        return False

    while add_more:
        pci_option = {'prompt': 'DUT port pci address',
                      'type': 'string',
                      'help': 'Please input DUT pci address xxxx:xx:xx.x',
                      'default': ''}
        opt = Option(**pci_option)
        dut_addr = opt.parse_input()
        m = re.match(pci_regex, dut_addr)
        if not m:
            print RED("Pci address should follow Domain+BDF format!!!")
            continue

        if ixia and ixia != '':
            pci_option = {'prompt': 'Choose Tester IXIA port',
                          'type': 'choice',
                          'options': ixia_ports,
                          'help': 'Please choice IXIA port',
                          'default': '0'}
            opt = Option(**pci_option)
            test_addr = opt.parse_input()
            card, port = test_addr
            test_addr = 'IXIA%s.%s' % (card, port)
        else:
            pci_option = {'prompt': 'Tester port pci address',
                          'type': 'string',
                          'help': 'Please input tester pci address xxxx:xx:xx.x',
                          'default': ''}
            opt = Option(**pci_option)
            test_addr = opt.parse_input()
            m = re.match(pci_regex, test_addr)
            if not m:
                print RED("Pci address should follow Domain+BDF format!!!")
                continue

        dut_port = {}
        dut_port[dut_addr] = test_addr
        dut_ports.append(dut_port)

        add_option = {'prompt': 'Whether configure another dut port',
                      'type': 'bool',
                      'help': 'If need more port input "Yes", otherwise ' +
                              'input "No"',
                      'default': 'No'}
        opt = Option(**add_option)
        add_more = opt.parse_input()

        if not add_more:
            continue

    return True


def write_ports_cfg():
    separator = '\n'
    content = ''

    section = '[%s]' % dut_ip
    content += section
    content += separator

    content += 'ports='
    content += separator

    for port in dut_ports:
        pci_addr = port.keys()[0]
        test_addr = port[pci_addr]
        content += '    pci=%s,peer=%s;' % (pci_addr, test_addr)
        content += separator

    with open(DTS_PORTS_CFG, "w") as f:
        f.write(content)


def get_next_opt():
    global nic_type
    global def_opt
    if def_opt == '0':
        def_opt = '1'
    elif def_opt == '1':
        if perf_execution:
            def_opt = '2'
        else:
            if nic_type == 'cfg':
                def_opt = '3'
            else:
                def_opt = '4'
    elif def_opt == '2':
        if nic_type == 'cfg':
            def_opt = '3'
        else:
            def_opt = '4'
    elif def_opt == '3':
        def_opt = '4'


def run_dts():
    print ('============================================================')
    print "Ready to run DTS"
    git_option = {'prompt': 'Whether pull latest git code',
                  'type': 'bool',
                  'help': 'If need input "Yes", otherwise ' +
                          'input "No"',
                  'default': 'No'}
    opt = Option(**git_option)
    git_pull = opt.parse_input()

    skip_option = {'prompt': 'Whether skip setup dpdk',
                   'type': 'bool',
                   'help': 'If need input "Yes", otherwise ' +
                   'input "No"',
                   'default': 'No'}
    opt = Option(**skip_option)
    skip_setup = opt.parse_input()

    debug_option = {'prompt': 'Whether enable debug option',
                    'type': 'bool',
                    'help': 'If need input "Yes", otherwise ' +
                    'input "No"',
                    'default': 'No'}
    opt = Option(**debug_option)
    debug_dts = opt.parse_input()

    cmd = './dts'
    if git_pull:
        cmd += ' --git=master'
    if skip_setup:
        cmd += '  --skip-setup'
    if debug_dts:
        cmd += ' --debug'

    os.system(cmd)


def main():
    config_done = False

    scan_suites()
    scan_executions()

    while not config_done:
        config_option = {'prompt': 'Choose preparation steps for running dts',
                         'type': 'choice',
                         'help': 'Running DTS request preparation few ' +
                                 'configurations',
                         'options': ['DUT&Tester crb', 'execution plan',
                                     'ixia port for performance',
                                     'port config for manually assign ports',
                                     'start running DTS'],
                         'default': def_opt}

        opt = Option(**config_option)
        choice = opt.parse_input()
        index = opt.choice
        if index == 0:
            config_crbs()
            write_crbs_cfg()
        elif index == 1:
            if not config_execution():
                continue
            write_exec_cfg()
        elif index == 2:
            if not config_ixia():
                continue
            write_ixia_cfg()
        elif index == 3:
            if not config_ports():
                continue
            write_ports_cfg()
        elif index == 4:
            config_done = True
            run_dts()

        print GREEN("Waiting for preparation ready...")
        time.sleep(2)
        get_next_opt()

if __name__ == "__main__":
    main()
