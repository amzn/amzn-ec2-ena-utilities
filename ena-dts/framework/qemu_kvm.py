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
   * Rework documentation of the method add_vm_enable_kvm
"""

import time
import re
import os

from virt_base import VirtBase
from virt_base import ST_NOTSTART, ST_PAUSE, ST_RUNNING, ST_UNKNOWN
from exception import StartVMFailedException
from settings import get_host_ip

# This name is derictly defined in the qemu guest serivce
# So you can not change it except it is changed by the service
QGA_DEV_NAME = 'org.qemu.guest_agent.0'
# This path defines an socket path on the host connected with
# a specified VM
QGA_SOCK_PATH_TEMPLATE = '/tmp/%(vm_name)s_qga0.sock'


class QEMUKvm(VirtBase):

    DEFAULT_BRIDGE = 'br0'
    QEMU_IFUP = "#!/bin/sh\n\n" + \
                "set -x\n\n" + \
                "switch=%(switch)s\n\n" + \
                "if [ -n '$1' ];then\n" + \
                "   tunctl -t $1\n" + \
                "   ip link set $1 up\n" + \
                "   sleep 0.5s\n" + \
                "   brctl addif $switch $1\n" + \
                "   exit 0\n" + \
                "else\n" + \
                "   echo 'Error: no interface specified'\n" + \
                "   exit 1\n" + \
                "fi"

    QEMU_IFUP_PATH = '/etc/qemu-ifup'

    def __init__(self, dut, vm_name, suite_name):
        super(QEMUKvm, self).__init__(dut, vm_name, suite_name)

        # initialize qemu emulator, example: qemu-system-x86_64
        self.qemu_emulator = self.get_qemu_emulator()

        # initialize qemu boot command line
        # example: qemu-system-x86_64 -name vm1 -m 2048 -vnc :1 -daemonize
        self.qemu_boot_line = ''

        # initialize some resource used by guest.
        self.init_vm_request_resource()

        QGA_CLI_PATH = '-r dep/QMP/'
        self.host_session.copy_file_to(QGA_CLI_PATH)

        # charater and network device default index
        self.char_idx = 0
        self.netdev_idx = 0
        self.pt_idx = 0
        self.cuse_id = 0
        # devices pass-through into vm
        self.pt_devices = []
        self.pci_maps = []

        # default login user,password
        self.username = dut.crb['user']
        self.password = dut.crb['pass']

        # internal variable to track whether default nic has been added
        self.__default_nic = False

        # arch info for multi-paltform init
        self.arch = self.host_session.send_expect('uname -m', '# ')

        # set some default values for vm,
        # if there is not the values of the specified options
        self.set_vm_default()

    def set_vm_default(self):
        self.set_vm_name(self.vm_name)
        if self.arch == 'aarch64':
            self.set_vm_machine('virt')
        self.set_vm_enable_kvm()
        self.set_vm_pid_file()
        self.set_vm_qga()
        self.set_vm_daemon()
        self.set_vm_monitor()

        if not self.__default_nic:
            # add default control interface
            def_nic = {'type': 'nic', 'opt_vlan': '0', 'opt_addr': '1f'}
            self.set_vm_net(**def_nic)
            def_net = {'type': 'user', 'opt_vlan': '0'}
            self.set_vm_net(**def_net)
            self.__default_nic = True

    def init_vm_request_resource(self):
        """
        initialize some resource used by VM.
        examples: CPU, PCIs, so on.
        CPU:
        initialize vcpus what will be pinned to the VM.
        If specify this param, the specified vcpus will
        be pinned to VM by the command 'taskset' when
        starting the VM.
        example:
            vcpus_pinned_to_vm = '1 2 3 4'
            taskset -c 1,2,3,4 qemu-boot-command-line
        """
        self.vcpus_pinned_to_vm = ''

        # initialize assigned PCI
        self.assigned_pcis = []

    def get_virt_type(self):
        """
        Get the virtual type.
        """
        return 'KVM'

    def get_qemu_emulator(self):
        """
        Get the qemu emulator based on the crb.
        """
        arch = self.host_session.send_expect('uname -m', '# ')
        return 'qemu-system-' + arch

    def set_qemu_emulator(self, qemu_emulator_path):
        """
        Set the qemu emulator in the specified path explicitly.
        """
        out = self.host_session.send_expect(
            'ls %s' % qemu_emulator_path, '# ')
        if 'No such file or directory' in out:
            self.host_logger.error("No emulator [ %s ] on the DUT [ %s ]" %
                                   (qemu_emulator_path, self.host_dut.get_ip_address()))
            return None
        out = self.host_session.send_expect(
            "[ -x %s ];echo $?" % qemu_emulator_path, '# ')
        if out != '0':
            self.host_logger.error(
                "Emulator [ %s ] not executable on the DUT [ %s ]" %
                                   (qemu_emulator_path, self.host_dut.get_ip_address()))
            return None
        self.qemu_emulator = qemu_emulator_path

    def add_vm_qemu(self, **options):
        """
        path: absolute path for qemu emulator
        """
        if 'path' in options.keys():
            self.set_qemu_emulator(options['path'])

    def has_virtual_ability(self):
        """
        Check if host has the virtual ability.
        """
        out = self.host_session.send_expect(
            'cat /proc/cpuinfo | grep flags', '# ')
        rgx = re.search(' vmx ', out)
        if rgx:
            pass
        else:
            self.host_logger.warning(
                "Hardware virtualization disabled on host!!!")
            return False

        out = self.host_session.send_expect('lsmod | grep kvm', '# ')
        if 'kvm' in out and 'kvm_intel' in out:
            return True
        else:
            self.host_logger.warning("kvm or kvm_intel not insmod!!!")
            return False

    def enable_virtual_ability(self):
        """
        Load the virutal module of kernel to enable the virutal ability.
        """
        self.host_session.send_expect('modprobe kvm', '# ')
        self.host_session.send_expect('modprobe kvm_intel', '# ')
        return True

    def disk_image_is_ok(self, image):
        """
        Check if the image is OK and no error.
        """
        pass

    def image_is_used(self, image_path):
        """
        Check if the image has been used on the host.
        """
        qemu_cmd_lines = self.host_session.send_expect(
            "ps aux | grep qemu | grep -v grep", "# ")

        image_name_flag = '/' + image_path.strip().split('/')[-1] + ' '
        if image_path in qemu_cmd_lines or \
                image_name_flag in qemu_cmd_lines:
            return True
        return False

    def __add_boot_line(self, option_boot_line):
        """
        Add boot option into the boot line.
        """
        separator = ' '
        self.qemu_boot_line += separator + option_boot_line

    def set_vm_enable_kvm(self, enable='yes'):
        """
        Set VM boot option to enable the option 'enable-kvm'.
        """
        index = self.find_option_index('enable_kvm')
        if index:
            self.params[index] = {'enable_kvm': [{'enable': '%s' % enable}]}
        else:
            self.params.append({'enable_kvm': [{'enable': '%s' % enable}]})

    def add_vm_enable_kvm(self, **options):
        """
        Add 'enable-kvm' to VM boot arguments if the options says so.
        """
        if 'enable' in options.keys() and \
                options['enable'] == 'yes':
            enable_kvm_boot_line = '-enable-kvm'
            self.__add_boot_line(enable_kvm_boot_line)

    def set_vm_machine(self, machine):
        """
        Set VM boot option to specify the option 'machine'.
        """
        index = self.find_option_index('machine')
        if index:
            self.params[index] = {'machine': [{'machine': '%s' % machine}]}
        else:
            self.params.append({'machine': [{'machine': '%s' % machine}]})

    def add_vm_machine(self, **options):
        """
        'machine': 'virt'
        """
        if 'machine' in options.keys() and \
                options['machine']:
            machine_boot_line = '-machine %s' % options['machine']
            self.__add_boot_line(machine_boot_line)

    def set_vm_pid_file(self):
        """
        Set VM pidfile option for manage qemu process
        """
        self.__pid_file = '/tmp/.%s.pid' % self.vm_name
        index = self.find_option_index('pid_file')
        if index:
            self.params[index] = {
                'pid_file': [{'name': '%s' % self.__pid_file}]}
        else:
            self.params.append(
                {'pid_file': [{'name': '%s' % self.__pid_file}]})

    def add_vm_pid_file(self, **options):
        """
        'name' : '/tmp/.qemu_vm0.pid'
        """
        if 'name' in options.keys():
            self.__add_boot_line('-pidfile %s' % options['name'])

    def set_vm_name(self, vm_name):
        """
        Set VM name.
        """
        index = self.find_option_index('name')
        if index:
            self.params[index] = {'name': [{'name': '%s' % vm_name}]}
        else:
            self.params.append({'name': [{'name': '%s' % vm_name}]})

    def add_vm_name(self, **options):
        """
        name: vm1
        """
        if 'name' in options.keys() and \
                options['name']:
            name_boot_line = '-name %s' % options['name']
            self.__add_boot_line(name_boot_line)

    def add_vm_cpu(self, **options):
        """
        model: [host | core2duo | ...]
               usage:
                    choose model value from the command
                        qemu-system-x86_64 -cpu help
        number: '4' #number of vcpus
        cpupin: '3 4 5 6' # host cpu list
        """
        if 'model' in options.keys() and \
                options['model']:
            cpu_boot_line = '-cpu %s' % options['model']
            self.__add_boot_line(cpu_boot_line)
        if 'number' in options.keys() and \
                options['number']:
            smp_cmd_line = '-smp %d' % int(options['number'])
            self.__add_boot_line(smp_cmd_line)
        if 'cpupin' in options.keys() and \
                options['cpupin']:
            self.vcpus_pinned_to_vm = str(options['cpupin'])

    def add_vm_mem(self, **options):
        """
        size: 1024
        """
        if 'size' in options.keys():
            mem_boot_line = '-m %s' % options['size']
            self.__add_boot_line(mem_boot_line)
        if 'hugepage' in options.keys():
            if options['hugepage'] == 'yes':
                mem_boot_huge = '-object memory-backend-file,' \
                                + 'id=mem,size=%sM,mem-path=%s,share=on' \
                                % (options['size'], self.host_dut.hugepage_path)

                self.__add_boot_line(mem_boot_huge)
                mem_boot_huge_opt = "-numa node,memdev=mem -mem-prealloc"
                self.__add_boot_line(mem_boot_huge_opt)

    def add_vm_disk(self, **options):
        """
        file: /home/image/test.img
        opt_format: raw
        opt_if: virtio
        opt_index: 0
        opt_media: disk
        """
        separator = ','
        if 'file' in options.keys() and \
                options['file']:
            disk_boot_line = '-drive file=%s' % options['file']
        if 'opt_format' in options.keys() and \
                options['opt_format']:
            disk_boot_line += separator + 'format=%s' % options['opt_format']
        if 'opt_if' in options.keys() and \
                options['opt_if']:
            disk_boot_line += separator + 'if=%s' % options['opt_if']
        if 'opt_index' in options.keys() and \
                options['opt_index']:
            disk_boot_line += separator + 'index=%s' % options['opt_index']
        if 'opt_media' in options.keys() and \
                options['opt_media']:
            disk_boot_line += separator + 'media=%s' % options['opt_media']

        if self.__string_has_multi_fields(disk_boot_line, separator):
            self.__add_boot_line(disk_boot_line)

    def add_vm_pflash(self, **options):
        """
        file: /home/image/flash0.img
        """
        if 'file' in options.keys():
            pflash_boot_line = '-pflash %s' % options['file']
            self.__add_boot_line(pflash_boot_line)

    def add_vm_login(self, **options):
        """
        user: login username of virtual machine
        password: login password of virtual machine
        """
        if 'user' in options.keys():
            user = options['user']
            self.username = user

        if 'password' in options.keys():
            password = options['password']
            self.password = password

    def get_vm_login(self):
        return (self.username, self.password)

    def set_vm_net(self, **options):
        index = self.find_option_index('net')
        if index:
            self.params[index]['net'].append(options)
        else:
            self.params.append({'net': [options]})

    def add_vm_net(self, **options):
        """
        Add VM net device.
        type: [nic | user | tap | bridge | ...]
        opt_[vlan | fd | br | mac | ...]
            note:the sub-option will be decided according to the net type.
        """
        if 'type' in options.keys():
            if 'opt_vlan' not in options.keys():
                options['opt_vlan'] = '0'
            if options['type'] == 'nic':
                self.__add_vm_net_nic(**options)
            if options['type'] == 'user':
                self.__add_vm_net_user(**options)
            if options['type'] == 'tap':
                self.__add_vm_net_tap(**options)

            if options['type'] == 'user':
                self.net_type = 'hostfwd'
            elif options['type'] in ['tap', 'bridge']:
                self.net_type = 'bridge'

    def __add_vm_net_nic(self, **options):
        """
        type: nic
        opt_vlan: 0
            note: Default is 0.
        opt_macaddr: 00:00:00:00:01:01
            note: if creating a nic, it`s better to specify a MAC,
                  else it will get a random number.
        opt_model:["e1000" | "virtio" | "i82551" | ...]
            note: Default is e1000.
        opt_name: 'nic1'
        opt_addr: ''
            note: PCI cards only.
        opt_vectors:
            note: This option currently only affects virtio cards.
        """
        net_boot_line = '-net nic'
        separator = ','
        if 'opt_vlan' in options.keys() and \
                options['opt_vlan']:
            net_boot_line += separator + 'vlan=%s' % options['opt_vlan']

        # add MAC info
        if 'opt_macaddr' in options.keys() and \
                options['opt_macaddr']:
            mac = options['opt_macaddr']
        else:
            mac = self.generate_unique_mac()
        net_boot_line += separator + 'macaddr=%s' % mac

        if 'opt_model' in options.keys() and \
                options['opt_model']:
            model = options['opt_model']
        else:
            model = 'e1000'
        net_boot_line += separator + 'model=%s' % model

        if 'opt_name' in options.keys() and \
                options['opt_name']:
            net_boot_line += separator + 'name=%s' % options['opt_name']
        if 'opt_addr' in options.keys() and \
                options['opt_addr']:
            net_boot_line += separator + 'addr=%s' % options['opt_addr']
        if 'opt_vectors' in options.keys() and \
                options['opt_vectors']:
            net_boot_line += separator + 'vectors=%s' % options['opt_vectors']

        if self.__string_has_multi_fields(net_boot_line, separator):
            self.__add_boot_line(net_boot_line)

    def __add_vm_net_user(self, **options):
        """
        type: user
        opt_vlan: 0
            note: default is 0.
        opt_hostfwd: [tcp|udp]:[hostaddr]:hostport-[guestaddr]:guestport
        """
        net_boot_line = '-net user'
        separator = ','
        if 'opt_vlan' in options.keys() and \
                options['opt_vlan']:
            net_boot_line += separator + 'vlan=%s' % options['opt_vlan']
        if 'opt_hostfwd' in options.keys() and \
                options['opt_hostfwd']:
            self.__check_net_user_opt_hostfwd(options['opt_hostfwd'])
            opt_hostfwd = options['opt_hostfwd']
        else:
            opt_hostfwd = '::-:'
        hostfwd_line = self.__parse_net_user_opt_hostfwd(opt_hostfwd)
        net_boot_line += separator + 'hostfwd=%s' % hostfwd_line

        if self.__string_has_multi_fields(net_boot_line, separator):
            self.__add_boot_line(net_boot_line)

    def __check_net_user_opt_hostfwd(self, opt_hostfwd):
        """
        Use regular expression to check if hostfwd value format is correct.
        """
        regx_ip = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        regx_hostfwd = r'["tcp" | "udp"]?:%s?:\d+-%s?:\d+' % (regx_ip, regx_ip)
        if not re.match(regx_hostfwd, opt_hostfwd):
            raise Exception("Option opt_hostfwd format is not correct,\n" +
                            "it is %s,\n " % opt_hostfwd +
                            "it should be [tcp|udp]:[hostaddr]:hostport-" +
                            "[guestaddr]:guestport.\n")

    def __parse_net_user_opt_hostfwd(self, opt_hostfwd):
        """
        Parse the boot option 'hostfwd'.
        """
        separator = ':'
        field = lambda option, index, separator=':': \
            option.split(separator)[index]

        # get the forword type
        fwd_type = field(opt_hostfwd, 0)
        if not fwd_type:
            fwd_type = 'tcp'

        # get the host addr
        host_addr = field(opt_hostfwd, 1)
        if not host_addr:
            addr = str(self.host_dut.get_ip_address())
            host_addr = get_host_ip(addr)

        # get the host port in the option
        host_port = field(opt_hostfwd, 2).split('-')[0]
        if not host_port:
            host_port = str(self.virt_pool.alloc_port(self.vm_name))
        self.redir_port = host_port

        # get the guest addr
        try:
            guest_addr = str(field(opt_hostfwd, 2).split('-')[1])
        except IndexError as e:
            guest_addr = ''

        # get the guest port in the option
        guest_port = str(field(opt_hostfwd, 3))
        if not guest_port:
            guest_port = '22'

        hostfwd_line = fwd_type + separator + \
            host_addr + separator + \
            host_port + \
            '-' + \
            guest_addr + separator + \
            guest_port

        # init the redirect incoming TCP or UDP connections
        # just combine host address and host port, it is enough
        # for using ssh to connect with VM
        self.hostfwd_addr = host_addr + separator + host_port

        return hostfwd_line

    def __add_vm_net_tap(self, **options):
        """
        type: tap
        opt_vlan: 0
            note: default is 0.
        opt_br: br0
            note: if choosing tap, need to specify bridge name,
                  else it will be br0.
        opt_script: QEMU_IFUP_PATH
            note: if not specified, default is self.QEMU_IFUP_PATH.
        opt_downscript: QEMU_IFDOWN_PATH
            note: if not specified, default is self.QEMU_IFDOWN_PATH.
        """
        net_boot_line = '-net tap'
        separator = ','

        # add bridge info
        if 'opt_br' in options.keys() and \
                options['opt_br']:
            bridge = options['opt_br']
        else:
            bridge = self.DEFAULT_BRIDGE
        self.__generate_net_config_script(str(bridge))

        if 'opt_vlan' in options.keys() and \
                options['opt_vlan']:
            net_boot_line += separator + 'vlan=%s' % options['opt_vlan']

        # add network configure script path
        if 'opt_script' in options.keys() and \
                options['opt_script']:
            script_path = options['opt_script']
        else:
            script_path = self.QEMU_IFUP_PATH
        net_boot_line += separator + 'script=%s' % script_path

        # add network configure downscript path
        if 'opt_downscript' in options.keys() and \
                options['opt_downscript']:
            net_boot_line += separator + \
                'downscript=%s' % options['opt_downscript']

        if self.__string_has_multi_fields(net_boot_line, separator):
            self.__add_boot_line(net_boot_line)

    def __generate_net_config_script(self, switch=DEFAULT_BRIDGE):
        """
        Generate a script for qemu emulator to build a tap device
        between host and guest.
        """
        qemu_ifup = self.QEMU_IFUP % {'switch': switch}
        file_name = os.path.basename(self.QEMU_IFUP_PATH)
        tmp_file_path = '/tmp/%s' % file_name
        self.host_dut.create_file(qemu_ifup, tmp_file_path)
        self.host_session.send_expect('mv -f ~/%s %s' % (file_name,
                                                         self.QEMU_IFUP_PATH), '# ')
        self.host_session.send_expect(
            'chmod +x %s' % self.QEMU_IFUP_PATH, '# ')

    def set_vm_device(self, driver='pci-assign', **opts):
        """
        Set VM device with specified driver.
        """
        opts['driver'] = driver
        index = self.find_option_index('device')
        if index:
            self.params[index]['device'].append(opts)
        else:
            self.params.append({'device': [opts]})

    def add_vm_device(self, **options):
        """
        driver: [pci-assign | virtio-net-pci | ...]
        opt_[host | addr | ...]: value
            note:the sub-opterty will be decided according to the driver.
        """
        if 'driver' in options.keys() and \
                options['driver']:
            if options['driver'] == 'pci-assign':
                self.__add_vm_pci_assign(**options)
            elif options['driver'] == 'virtio-net-pci':
                self.__add_vm_virtio_net_pci(**options)
            elif options['driver'] == 'vhost-user':
                self.__add_vm_virtio_user_pci(**options)
            elif options['driver'] == 'vhost-cuse':
                self.__add_vm_virtio_cuse_pci(**options)
            if options['driver'] == 'vfio-pci':
                self.__add_vm_pci_vfio(**options)

    def __add_vm_pci_vfio(self, **options):
        """
        driver: vfio-pci
        opt_host: 08:00.0
        opt_addr: 00:00:00:00:01:02
        """
        dev_boot_line = '-device vfio-pci'
        separator = ','
        if 'opt_host' in options.keys() and \
                options['opt_host']:
            dev_boot_line += separator + 'host=%s' % options['opt_host']
            dev_boot_line += separator + 'id=pt_%d' % self.pt_idx
            self.pt_idx += 1
            self.pt_devices.append(options['opt_host'])
        if 'opt_addr' in options.keys() and \
                options['opt_addr']:
            dev_boot_line += separator + 'addr=%s' % options['opt_addr']
            self.assigned_pcis.append(options['opt_addr'])

        if self.__string_has_multi_fields(dev_boot_line, separator):
            self.__add_boot_line(dev_boot_line)

    def __add_vm_pci_assign(self, **options):
        """
        driver: pci-assign
        opt_host: 08:00.0
        opt_addr: 00:00:00:00:01:02
        """
        dev_boot_line = '-device pci-assign'
        separator = ','
        if 'opt_host' in options.keys() and \
                options['opt_host']:
            dev_boot_line += separator + 'host=%s' % options['opt_host']
            dev_boot_line += separator + 'id=pt_%d' % self.pt_idx
            self.pt_idx += 1
            self.pt_devices.append(options['opt_host'])
        if 'opt_addr' in options.keys() and \
                options['opt_addr']:
            dev_boot_line += separator + 'addr=%s' % options['opt_addr']
            self.assigned_pcis.append(options['opt_addr'])

        if self.__string_has_multi_fields(dev_boot_line, separator):
            self.__add_boot_line(dev_boot_line)

    def __add_vm_virtio_user_pci(self, **options):
        """
        driver virtio-net-pci
        opt_path: /tmp/vhost-net
        opt_mac: 00:00:20:00:00:00
        """
        separator = ','
        # chardev parameter
        if 'opt_path' in options.keys() and options['opt_path']:
            dev_boot_line = '-chardev socket'
            char_id = 'char%d' % self.char_idx
            if 'opt_server' in options.keys() and options['opt_server']:
                dev_boot_line += separator + 'id=%s' % char_id + separator + \
                    'path=%s' % options[
                        'opt_path'] + separator + '%s' % options['opt_server']
                self.char_idx += 1
                self.__add_boot_line(dev_boot_line)
            else:
                dev_boot_line += separator + 'id=%s' % char_id + \
                    separator + 'path=%s' % options['opt_path']
                self.char_idx += 1
                self.__add_boot_line(dev_boot_line)
            # netdev parameter
            netdev_id = 'netdev%d' % self.netdev_idx
            self.netdev_idx += 1
            if 'opt_queue' in options.keys() and options['opt_queue']:
                queue_num = options['opt_queue']
                dev_boot_line = '-netdev type=vhost-user,id=%s,chardev=%s,vhostforce,queues=%s' % (
                    netdev_id, char_id, queue_num)
            else:
                dev_boot_line = '-netdev type=vhost-user,id=%s,chardev=%s,vhostforce' % (
                    netdev_id, char_id)
            self.__add_boot_line(dev_boot_line)
            # device parameter
            opts = {'opt_netdev': '%s' % netdev_id}
            if 'opt_mac' in options.keys() and \
                    options['opt_mac']:
                opts['opt_mac'] = options['opt_mac']
            if 'opt_settings' in options.keys() and options['opt_settings']:
                opts['opt_settings'] = options['opt_settings']
        self.__add_vm_virtio_net_pci(**opts)

    def __add_vm_virtio_cuse_pci(self, **options):
        """
        driver virtio-net-pci
        opt_mac: 52:54:00:00:00:01
        """
        separator = ','
        dev_boot_line = '-netdev tap'
        if 'opt_tap' in options.keys():
            cuse_id = options['opt_tap']
        else:
            cuse_id = 'vhost%d' % self.cuse_id
            self.cuse_id += 1
        dev_boot_line += separator + 'id=%s' % cuse_id + separator + \
            'ifname=tap_%s' % cuse_id + separator + \
            "vhost=on" + separator + "script=no"
        self.__add_boot_line(dev_boot_line)
        # device parameter
        opts = {'opt_netdev': '%s' % cuse_id,
                'opt_id': '%s_net' % cuse_id}
        if 'opt_mac' in options.keys() and options['opt_mac']:
            opts['opt_mac'] = options['opt_mac']
        if 'opt_settings' in options.keys() and options['opt_settings']:
            opts['opt_settings'] = options['opt_settings']

        self.__add_vm_virtio_net_pci(**opts)

    def __add_vm_virtio_net_pci(self, **options):
        """
        driver: virtio-net-pci
        opt_netdev: mynet1
        opt_id: net1
        opt_mac: 00:00:00:00:01:03
        opt_bus: pci.0
        opt_addr: 0x3
        opt_settings: csum=off,gso=off,guest_csum=off
        """
        dev_boot_line = '-device virtio-net-pci'
        separator = ','
        if 'opt_netdev' in options.keys() and \
                options['opt_netdev']:
            dev_boot_line += separator + 'netdev=%s' % options['opt_netdev']
        if 'opt_id' in options.keys() and \
                options['opt_id']:
            dev_boot_line += separator + 'id=%s' % options['opt_id']
        if 'opt_mac' in options.keys() and \
                options['opt_mac']:
            dev_boot_line += separator + 'mac=%s' % options['opt_mac']
        if 'opt_bus' in options.keys() and \
                options['opt_bus']:
            dev_boot_line += separator + 'bus=%s' % options['opt_bus']
        if 'opt_addr' in options.keys() and \
                options['opt_addr']:
            dev_boot_line += separator + 'addr=%s' % options['opt_addr']
        if 'opt_settings' in options.keys() and \
                options['opt_settings']:
            dev_boot_line += separator + '%s' % options['opt_settings']

        if self.__string_has_multi_fields(dev_boot_line, separator):
            self.__add_boot_line(dev_boot_line)

    def __string_has_multi_fields(self, string, separator, field_num=2):
        """
        Check if string has multiple fields which is splited with
        specified separator.
        """
        fields = string.split(separator)
        number = 0
        for field in fields:
            if field:
                number += 1
        if number >= field_num:
            return True
        else:
            return False

    def set_vm_monitor(self):
        """
        Set VM boot option to enable qemu monitor.
        """
        index = self.find_option_index('monitor')
        if index:
            self.params[index] = {'monitor': [{'path': '/tmp/%s_monitor.sock' %
                                              (self.vm_name)}]}
        else:
            self.params.append({'monitor': [{'path': '/tmp/%s_monitor.sock' %
                               (self.vm_name)}]})

    def add_vm_monitor(self, **options):
        """
        path: if adding monitor to vm, need to specify unix socket patch
        """
        if 'path' in options.keys():
            monitor_boot_line = '-monitor unix:%s,server,nowait' % options[
                'path']
            self.__add_boot_line(monitor_boot_line)
            self.monitor_sock_path = options['path']
        else:
            self.monitor_sock_path = None

    def set_vm_qga(self, enable='yes'):
        """
        Set VM qemu-guest-agent.
        """
        index = self.find_option_index('qga')
        if index:
            self.params[index] = {'qga': [{'enable': '%s' % enable}]}
        else:
            self.params.append({'qga': [{'enable': '%s' % enable}]})
        QGA_SOCK_PATH = QGA_SOCK_PATH_TEMPLATE % {'vm_name': self.vm_name}
        self.qga_sock_path = QGA_SOCK_PATH

    def add_vm_qga(self, **options):
        """
        enable: 'yes'
        Make sure qemu-guest-agent servie up in vm
        """
        QGA_DEV_ID = '%(vm_name)s_qga0' % {'vm_name': self.vm_name}
        QGA_SOCK_PATH = QGA_SOCK_PATH_TEMPLATE % {'vm_name': self.vm_name}

        separator = ' '

        if 'enable' in options.keys():
            if options['enable'] == 'yes':
                qga_boot_block = '-chardev socket,path=%(SOCK_PATH)s,server,nowait,id=%(ID)s' + \
                                 separator + '-device virtio-serial' + separator + \
                                 '-device virtserialport,chardev=%(ID)s,name=%(DEV_NAME)s'
                qga_boot_line = qga_boot_block % {'SOCK_PATH': QGA_SOCK_PATH,
                                                  'DEV_NAME': QGA_DEV_NAME,
                                                  'ID': QGA_DEV_ID}
                self.__add_boot_line(qga_boot_line)
                self.qga_sock_path = QGA_SOCK_PATH
            else:
                self.qga_sock_path = ''

    def add_vm_migration(self, **options):
        """
        enable: yes
        port: tcp port for live migration
        """
        migrate_cmd = "-incoming tcp::%(migrate_port)s"

        if 'enable' in options.keys():
            if options['enable'] == 'yes':
                if 'port' in options.keys():
                    self.migrate_port = options['port']
                else:
                    self.migrate_port = str(
                        self.virt_pool.alloc_port(self.vm_name))
                migrate_boot_line = migrate_cmd % {
                    'migrate_port': self.migrate_port}
                self.__add_boot_line(migrate_boot_line)

    def add_vm_serial_port(self, **options):
        """
        enable: 'yes'
        """
        if 'enable' in options.keys():
            if options['enable'] == 'yes':
                self.serial_path = "/tmp/%s_serial.sock" % self.vm_name
                serial_boot_line = '-serial unix:%s,server,nowait' % self.serial_path
                self.__add_boot_line(serial_boot_line)
            else:
                pass

    def connect_serial_port(self, name="", first=True):
        """
        Connect to serial port and return connected session for usage
        if connected failed will return None
        """
        if getattr(self, 'serial_path', None):
            self.serial_session = self.host_dut.new_session(suite=name)
            self.serial_session.send_command("nc -U %s" % self.serial_path)
            if first:
                # login into Fedora os, not sure can work on all distributions
                self.serial_session.send_expect("", "login:")
                self.serial_session.send_expect(
                    "%s" % self.username, "Password:")
                self.serial_session.send_expect("%s" % self.password, "# ")
            return self.serial_session

        return None

    def close_serial_port(self):
        """
        Close serial session if it existed
        """
        if getattr(self, 'serial_session', None):
            # exit from nc first
            self.serial_session.send_expect("^C", "# ")
            self.host_dut.close_session(self.serial_session)

    def add_vm_vnc(self, **options):
        """
        displayNum: 1
        """
        if 'displayNum' in options.keys() and \
                options['displayNum']:
            display_num = options['displayNum']
        else:
            display_num = self.virt_pool.alloc_vnc_num(self.vm_name)

        vnc_boot_line = '-vnc :%d' % int(display_num)
        self.__add_boot_line(vnc_boot_line)

    def set_vm_daemon(self, enable='yes'):
        """
        Set VM daemon option.
        """
        index = self.find_option_index('daemon')
        if index:
            self.params[index] = {'daemon': [{'enable': '%s' % enable}]}
        else:
            self.params.append({'daemon': [{'enable': '%s' % enable}]})

    def add_vm_daemon(self, **options):
        """
        enable: 'yes'
            note:
                By default VM will start with the daemonize status.
                Not support starting it on the stdin now.
        """
        if 'daemon' in options.keys() and \
                options['enable'] == 'no':
            pass
        else:
            daemon_boot_line = '-daemonize'
            self.__add_boot_line(daemon_boot_line)

    def add_vm_usercmd(self, **options):
        """
        usercmd: user self defined command line.
                 This command will be add into qemu boot command.
        """
        if 'cmd' in options.keys():
            cmd = options['cmd']
        self.__add_boot_line(cmd)

    def _start_vm(self):
        """
        Start VM.
        """
        self.__alloc_assigned_pcis()

        qemu_boot_line = self.generate_qemu_boot_line()

        # Start VM using the qemu command
        ret = self.host_session.send_expect(qemu_boot_line, '# ', verify=True)
        if type(ret) is int and ret != 0:
            raise StartVMFailedException('Start VM failed!!!')

        self.__get_pci_mapping()

        # query status
        self.update_status()

        # when vm is waiting for migration, can't ping
        if self.vm_status is not ST_PAUSE:
            # if VM waiting for migration, can't return ping
            out = self.__control_session('ping', '120')
            if "Not responded" in out:
                raise StartVMFailedException('Not response in 120 seconds!!!')

            self.__wait_vmnet_ready()

    def start_migration(self, remote_ip, remote_port):
        """
        Send migration command to host and check whether start migration
        """
        # send migration command
        migration_port = 'tcp:%(IP)s:%(PORT)s' % {
            'IP': remote_ip, 'PORT': remote_port}

        self.__monitor_session('migrate', '-d', migration_port)
        time.sleep(2)
        out = self.__monitor_session('info', 'migrate')
        if "Migration status: active" in out:
            return True
        else:
            return False

    def wait_migration_done(self):
        """
        Wait for migration done. If not finished after three minutes
        will raise exception.
        """
        # wait for migration done
        count = 30
        while count:
            out = self.__monitor_session('info', 'migrate')
            if "completed" in out:
                self.host_logger.info("%s" % out)
                # after migration done, status is pause
                self.vm_status = ST_PAUSE
                return True

            time.sleep(6)
            count -= 1

        raise StartVMFailedException(
            'Virtual machine can not finished in 180 seconds!!!')

    def generate_qemu_boot_line(self):
        """
        Generate the whole QEMU boot line.
        """
        qemu_emulator = self.qemu_emulator

        if self.vcpus_pinned_to_vm.strip():
            vcpus = self.__alloc_vcpus()

            if vcpus.strip():
                qemu_boot_line = 'taskset -c %s ' % vcpus + \
                    qemu_emulator + ' ' + \
                    self.qemu_boot_line
        else:
            qemu_boot_line = qemu_emulator + ' ' + \
                self.qemu_boot_line

        return qemu_boot_line

    def __wait_vmnet_ready(self):
        """
        wait for 120 seconds for vm net ready
        10.0.2.* is the default ip address allocated by qemu
        """
        count = 40
        while count:
            out = self.__control_session('ifconfig')
            if "10.0.2" in out:
                return True
            time.sleep(6)
            count -= 1

        raise StartVMFailedException(
            'Virtual machine control net not ready in 120 seconds!!!')

    def __alloc_vcpus(self):
        """
        Allocate virtual CPUs for VM.
        """
        req_cpus = self.vcpus_pinned_to_vm.split()
        cpus = self.virt_pool.alloc_cpu(vm=self.vm_name, corelist=req_cpus)

        if len(req_cpus) != len(cpus):
            self.host_logger.warning(
                "VCPUs not enough, required [ %s ], just [ %s ]" %
                                     (req_cpus, cpus))
            raise Exception("No enough required vcpus!!!")

        vcpus_pinned_to_vm = ''
        for cpu in cpus:
            vcpus_pinned_to_vm += ',' + cpu
        vcpus_pinned_to_vm = vcpus_pinned_to_vm.lstrip(',')

        return vcpus_pinned_to_vm

    def __alloc_assigned_pcis(self):
        """
        Record the PCI device info
        Struct: {dev pci: {'is_vf': [True | False],
                            'pf_pci': pci}}
        example:
            {'08:10.0':{'is_vf':True, 'pf_pci': 08:00.0}}
        """
        assigned_pcis_info = {}
        for pci in self.assigned_pcis:
            assigned_pcis_info[pci] = {}
            if self.__is_vf_pci(pci):
                assigned_pcis_info[pci]['is_vf'] = True
                pf_pci = self.__map_vf_to_pf(pci)
                assgined_pcis_info[pci]['pf_pci'] = pf_pci
                if self.virt_pool.alloc_vf_from_pf(vm=self.vm_name,
                                                   pf_pci=pf_pci,
                                                   *[pci]):
                    port = self.__get_vf_port(pci)
                    port.unbind_driver()
                    port.bind_driver('pci-stub')
            else:
                # check that if any VF of specified PF has been
                # used, raise exception
                vf_pci = self.__vf_has_been_assinged(pci, **assinged_pcis_info)
                if vf_pci:
                    raise Exception(
                        "Error: A VF [%s] generated by PF [%s] has " %
                        (vf_pci, pci) +
                        "been assigned to VM, so this PF can not be " +
                        "assigned to VM again!")
                # get the port instance of PF
                port = self.__get_net_device_by_pci(pci)

                if self.virt_pool.alloc_pf(vm=self.vm_name,
                                           *[pci]):
                    port.unbind_driver()

    def __is_vf_pci(self, dev_pci):
        """
        Check if the specified PCI dev is a VF.
        """
        for port_info in self.host_dut.ports_info:
            if 'sriov_vfs_pci' in port_info.keys():
                if dev_pci in port_info['sriov_vfs_pci']:
                    return True
        return False

    def __map_vf_to_pf(self, dev_pci):
        """
        Map the specified VF to PF.
        """
        for port_info in self.host_dut.ports_info:
            if 'sriov_vfs_pci' in port_info.keys():
                if dev_pci in port_info['sriov_vfs_pci']:
                    return port_info['pci']
        return None

    def __get_vf_port(self, dev_pci):
        """
        Get the NetDevice instance of specified VF.
        """
        for port_info in self.host_dut.ports_info:
            if 'vfs_port' in port_info.keys():
                for port in port_info['vfs_port']:
                    if dev_pci == port.pci:
                        return port
        return None

    def __vf_has_been_assigned(self, pf_pci, **assigned_pcis_info):
        """
        Check if the specified VF has been used.
        """
        for pci in assigned_pcis_info.keys():
            if assigned_pcis_info[pci]['is_vf'] and \
                    assigned_pcis_info[pci]['pf_pci'] == pf_pci:
                return pci
        return False

    def __get_net_device_by_pci(self, net_device_pci):
        """
        Get NetDevice instance by the specified PCI bus number.
        """
        port_info = self.host_dut.get_port_info(net_device_pci)
        return port_info['port']

    def get_vm_ip(self):
        """
        Get VM IP.
        """
        get_vm_ip = getattr(self, "get_vm_ip_%s" % self.net_type)
        return get_vm_ip()

    def get_vm_ip_hostfwd(self):
        """
        Get IP which VM is connected by hostfwd.
        """
        return self.hostfwd_addr

    def get_vm_ip_bridge(self):
        """
        Get IP which VM is connected by bridge.
        """
        out = self.__control_session('ping', '60')
        if not out:
            time.sleep(10)
            out = self.__control_session('ifconfig')
            ips = re.findall(r'inet (\d+\.\d+\.\d+\.\d+)', out)

            if '127.0.0.1' in ips:
                ips.remove('127.0.0.1')

            num = 3
            for ip in ips:
                out = self.host_session.send_expect(
                    'ping -c %d %s' % (num, ip), '# ')
                if '0% packet loss' in out:
                    return ip
        return ''

    def __get_pci_mapping(self):
        devices = self.__strip_guest_pci()
        for hostpci in self.pt_devices:
            index = self.pt_devices.index(hostpci)
            pt_id = 'pt_%d' % index
            pci_map = {}
            for device in devices:
                if device['id'] == pt_id:
                    pci_map['hostpci'] = hostpci
                    pci_map['guestpci'] = device['pci']
                    self.pci_maps.append(pci_map)

    def get_pci_mappings(self):
        """
        Return guest and host pci devices mapping structure
        """
        return self.pci_maps

    def __monitor_session(self, command, *args):
        """
        Connect the qemu montior session, send command and return output message.
        """
        if not self.monitor_sock_path:
            self.host_logger.info(
                "No monitor between on host [ %s ] for guest [ %s ]" %
                (self.host_dut.NAME, self.vm_name))
            return None

        self.host_session.send_expect(
            'nc -U %s' % self.monitor_sock_path, '(qemu)')

        cmd = command
        for arg in args:
            cmd += ' ' + str(arg)

        # after quit command, qemu will exit
        if 'quit' in cmd:
            self.host_session.send_command('%s' % cmd)
            out = self.host_session.send_expect(' ', '#')
        else:
            out = self.host_session.send_expect('%s' % cmd, '(qemu)', 30)
        self.host_session.send_expect('^C', "# ")
        return out

    def update_status(self):
        """
        Query and update VM status
        """
        out = self.__monitor_session('info', 'status')
        self.host_logger.info("Virtual machine status: %s" % out)

        if 'paused' in out:
            self.vm_status = ST_PAUSE
        elif 'running' in out:
            self.vm_status = ST_RUNNING
        else:
            self.vm_status = ST_UNKNOWN

        info = self.host_session.send_expect('cat %s' % self.__pid_file, "# ")
        try:
            pid = int(info)
            # save pid into dut structure
            self.host_dut.virt_pids.append(pid)
        except:
            self.host_logger.info("Failed to capture pid!!!")

    def __strip_guest_pci(self):
        """
        Strip all pci-passthrough device information, based on qemu monitor
        """
        pci_reg = r'^.*Bus(\s+)(\d+), device(\s+)(\d+), function (\d+)'
        id_reg = r'^.*id \"(.*)\"'

        pcis = []
        out = self.__monitor_session('info', 'pci')

        if out is None:
            return pcis

        lines = out.split("\r\n")

        for line in lines:
            m = re.match(pci_reg, line)
            n = re.match(id_reg, line)
            if m:
                pci = "%02d:%02d.%d" % (
                    int(m.group(2)), int(m.group(4)), int(m.group(5)))
            if n:
                dev_id = n.group(1)
                if dev_id != '':
                    pt_dev = {}
                    pt_dev['pci'] = pci
                    pt_dev['id'] = dev_id
                    pcis.append(pt_dev)

        return pcis

    def __control_session(self, command, *args):
        """
        Use the qemu guest agent service to control VM.
        Note:
            :command: there are these commands as below:
                       cat, fsfreeze, fstrim, halt, ifconfig, info,\
                       ping, powerdown, reboot, shutdown, suspend
            :args: give different args by the different commands.
        """
        if not self.qga_sock_path:
            self.host_logger.info(
                "No QGA service between host [ %s ] and guest [ %s ]" %
                (self.host_dut.NAME, self.vm_name))
            return None

        cmd_head = '~/QMP/' + \
            "qemu-ga-client " + \
            "--address=%s %s" % \
            (self.qga_sock_path, command)

        cmd = cmd_head
        for arg in args:
            cmd = cmd_head + ' ' + str(arg)

        if command is "ping":
            out = self.host_session.send_expect(cmd, '# ', int(args[0]))
        else:
            out = self.host_session.send_expect(cmd, '# ')

        return out

    def _stop_vm(self):
        """
        Stop VM.
        """
        if self.vm_status is ST_RUNNING:
            self.__control_session('powerdown')
        else:
            self.__monitor_session('quit')
        time.sleep(5)
