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

import time
import re
import os

import utils
from dut import Dut
from ssh_connection import SSHConnection
from virt_base import VirtBase
from virt_resource import VirtResource
from logger import getLogger
from config import VirtConf
from config import VIRTCONF
from exception import StartVMFailedException
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ElementTree


class LibvirtKvm(VirtBase):

    def __init__(self, dut, name, suite):
        # initialize virtualization base module
        super(LibvirtKvm, self).__init__(dut, name, suite)

        # initialize qemu emulator, example: qemu-system-x86_64
        self.qemu_emulator = self.get_qemu_emulator()

        # disk and pci device default index
        self.diskindex = 'a'
        self.pciindex = 10

        # configure root element
        self.root = ElementTree()
        self.domain = ET.Element('domain')
        # replace root element
        self.root._setroot(self.domain)
        # add xml header
        self.domain.set('type', 'kvm')
        self.domain.set('xmlns:qemu',
                        'http://libvirt.org/schemas/domain/qemu/1.0')
        ET.SubElement(self.domain, 'name').text = name

        # devices pass-through into vm
        self.pci_maps = []

        # default login user,password
        self.username = self.host_dut.crb['user']
        self.password = self.host_dut.crb['pass']

        # internal variable to track whether default nic has been added
        self.__default_nic = False

        # set some default values for vm,
        # if there is not the values of the specified options
        self.set_vm_default()

    def get_qemu_emulator(self):
        """
        Get the qemu emulator based on the crb.
        """
        arch = self.host_session.send_expect('uname -m', '# ')
        return '/usr/bin/qemu-system-' + arch

    def get_virt_type(self):
        return 'LIBVIRT'

    def has_virtual_ability(self):
        """
        check and setup host virtual ability
        """
        out = self.host_session.send_expect('cat /proc/cpuinfo | grep flags',
                                            '# ')
        rgx = re.search(' vmx ', out)
        if rgx:
            pass
        else:
            self.host_logger.warning("Hardware virtualization "
                                     "disabled on host!!!")
            return False

        out = self.host_session.send_expect('lsmod | grep kvm', '# ')
        if 'kvm' not in out or 'kvm_intel' not in out:
            return False

        out = self.host_session.send_expect('service libvirtd status', "# ")
        if 'active (running)' not in out:
            return False

        return True

    def load_virtual_mod(self):
        self.host_session.send_expect('modprobe kvm', '# ')
        self.host_session.send_expect('modprobe kvm_intel', '# ')

    def unload_virtual_mod(self):
        self.host_session.send_expect('rmmod kvm_intel', '# ')
        self.host_session.send_expect('rmmod kvm', '# ')

    def disk_image_is_ok(self, image):
        """
        Check if the image is OK and no error.
        """
        pass

    def add_vm_mem(self, **options):
        """
        Options:
            size : memory size, measured in MB
            hugepage : guest memory allocated using hugepages
        """
        if 'size' in options.keys():
            memory = ET.SubElement(self.domain, 'memory', {'unit': 'MB'})
            memory.text = options['size']
        if 'hugepage' in options.keys():
            memoryBacking = ET.SubElement(self.domain, 'memoryBacking')
            ET.SubElement(memoryBacking, 'hugepages')

    def set_vm_cpu(self, **options):
        """
        Set VM cpu.
        """
        index = self.find_option_index('cpu')
        if index:
            self.params[index] = {'cpu': [options]}
        else:
            self.params.append({'cpu': [options]})

    def add_vm_cpu(self, **options):
        """
        'number' : '4' #number of vcpus
        'cpupin' : '3 4 5 6' # host cpu list
        """
        vcpu = 0
        if 'number' in options.keys():
            vmcpu = ET.SubElement(self.domain, 'vcpu', {'placement': 'static'})
            vmcpu.text = options['number']
        if 'cpupin' in options.keys():
            cputune = ET.SubElement(self.domain, 'cputune')
            # cpu resource will be allocated
            req_cpus = options['cpupin'].split()
            cpus = self.virt_pool.alloc_cpu(vm=self.vm_name, corelist=req_cpus)
            for cpu in cpus:
                ET.SubElement(cputune, 'vcpupin', {
                              'vcpu': '%d' % vcpu, 'cpuset': cpu})
                vcpu += 1
        else:  # request cpu from vm resource pool
            cpus = self.virt_pool.alloc_cpu(
                self.vm_name, number=int(options['number']))
            for cpu in cpus:
                ET.SubElement(cputune, 'vcpupin', {
                              'vcpu': '%d' % vcpu, 'cpuset': cpu})
                vcpu += 1

    def get_vm_cpu(self):
        cpus = self.virt_pool.get_cpu_on_vm(self.vm_name)
        return cpus

    def add_vm_qga(self, options):
        qemu = ET.SubElement(self.domain, 'qemu:commandline')
        ET.SubElement(qemu, 'qemu:arg', {'value': '-chardev'})
        ET.SubElement(qemu, 'qemu:arg',
                      {'value': 'socket,path=/tmp/' +
                                '%s_qga0.sock,' % self.vm_name +
                                'server,nowait,id=%s_qga0' % self.vm_name})
        ET.SubElement(qemu, 'qemu:arg', {'value': '-device'})
        ET.SubElement(qemu, 'qemu:arg', {'value': 'virtio-serial'})
        ET.SubElement(qemu, 'qemu:arg', {'value': '-device'})
        ET.SubElement(qemu, 'qemu:arg',
                      {'value': 'virtserialport,' +
                                'chardev=%s_qga0' % self.vm_name +
                                ',name=org.qemu.guest_agent.0'})
        self.qga_sock_path = '/tmp/%s_qga0.sock' % self.vm_name

    def set_vm_default(self):
        os = ET.SubElement(self.domain, 'os')
        type = ET.SubElement(
            os, 'type', {'arch': 'x86_64', 'machine': 'pc-i440fx-1.6'})
        type.text = 'hvm'
        ET.SubElement(os, 'boot', {'dev': 'hd'})
        features = ET.SubElement(self.domain, 'features')
        ET.SubElement(features, 'acpi')
        ET.SubElement(features, 'apic')
        ET.SubElement(features, 'pae')

        ET.SubElement(self.domain, 'cpu', {'mode': 'host-passthrough'})

        # qemu-kvm for emulator
        device = ET.SubElement(self.domain, 'devices')
        ET.SubElement(device, 'emulator').text = self.qemu_emulator

        # graphic device
        ET.SubElement(device, 'graphics', {
                      'type': 'vnc', 'port': '-1', 'autoport': 'yes'})
        # qemu guest agent
        self.add_vm_qga(None)

        # add default control interface
        if not self.__default_nic:
            def_nic = {'type': 'nic', 'opt_hostfwd': '', 'opt_addr': '00:1f.0'}
            self.add_vm_net(**def_nic)
            self.__default_nic = True

    def set_qemu_emulator(self, qemu_emulator_path):
        """
        Set the qemu emulator in the specified path explicitly.
        """
        out = self.host_session.send_expect(
            'ls %s' % qemu_emulator_path, '# ')
        if 'No such file or directory' in out:
            self.host_logger.error("No emulator [ %s ] on the DUT" %
                                   (qemu_emulator_path))
            return None
        out = self.host_session.send_expect("[ -x %s ];echo $?" %
                                            (qemu_emulator_path), '# ')
        if out != '0':
            self.host_logger.error("Emulator [ %s ] " % qemu_emulator_path +
                                   "not executable on the DUT")
            return None
        self.qemu_emulator = qemu_emulator_path

    def add_vm_qemu(self, **options):
        """
        Options:
            path: absolute path for qemu emulator
        """
        if 'path' in options.keys():
            self.set_qemu_emulator(options['path'])
            # update emulator config
            devices = self.domain.find('devices')
            ET.SubElement(devices, 'emulator').text = self.qemu_emulator

    def add_vm_disk(self, **options):
        """
        Options:
            file: absolute path of disk image file
            type: image file formats
        """
        devices = self.domain.find('devices')
        disk = ET.SubElement(
            devices, 'disk', {'type': 'file', 'device': 'disk'})

        if 'file' not in options:
            return False

        ET.SubElement(disk, 'source', {'file': options['file']})
        if 'type' not in options:
            disk_type = 'raw'
        else:
            disk_type = options['type']

        ET.SubElement(disk, 'driver', {'name': 'qemu', 'type': disk_type})

        ET.SubElement(
            disk, 'target', {'dev': 'vd%c' % self.diskindex, 'bus': 'virtio'})

        self.diskindex = chr(ord(self.diskindex) + 1)

    def add_vm_login(self, **options):
        """
        options:
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

    def __parse_pci(self, pci_address):
        pci_regex = r"([0-9a-fA-F]{1,2}):([0-9a-fA-F]{1,2})" + \
            ".([0-9a-fA-F]{1,2})"
        m = re.match(pci_regex, pci_address)
        if m is None:
            return None
        bus = m.group(1)
        slot = m.group(2)
        func = m.group(3)

        return (bus, slot, func)

    def add_vm_device(self, **options):
        """
        options:
            pf_idx: device index of pass-through device
            guestpci: assigned pci address in vm
        """
        devices = self.domain.find('devices')
        hostdevice = ET.SubElement(devices, 'hostdev', {
                                   'mode': 'subsystem', 'type': 'pci',
                                   'managed': 'yes'})

        if 'pf_idx' not in options.keys():
            print utils.RED("Missing device index for device option!!!")
            return False

        pf = int(options['pf_idx'])
        if pf > len(self.host_dut.ports_info):
            print utils.RED("PF device index over size!!!")
            return False

        pci_addr = self.host_dut.ports_info[pf]['pci']

        pci = self.__parse_pci(pci_addr)
        if pci is None:
            return False
        bus, slot, func = pci

        source = ET.SubElement(hostdevice, 'source')
        ET.SubElement(source, 'address', {
                      'domain': '0x0', 'bus': '0x%s' % bus,
                      'slot': '0x%s' % slot,
                      'function': '0x%s' % func})
        if 'guestpci' in options.keys():
            pci = self.__parse_pci(options['guestpci'])
            if pci is None:
                return False
            bus, slot, func = pci
            ET.SubElement(hostdevice, 'address', {
                          'type': 'pci', 'domain': '0x0', 'bus': '0x%s' % bus,
                          'slot': '0x%s' % slot, 'function': '0x%s' % func})
            # save host and guest pci address mapping
            pci_map = {}
            pci_map['hostpci'] = pci_addr
            pci_map['guestpci'] = options['guestpci']
            self.pci_maps.append(pci_map)
        else:
            print utils.RED('Host device pass-through need guestpci option!!!')

    def add_vm_net(self, **options):
        """
        Options:
            default: create e1000 netdev and redirect ssh port
        """
        if 'type' in options.keys():
            if options['type'] == 'nic':
                self.__add_vm_net_nic(**options)

    def __add_vm_net_nic(self, **options):
        """
        type: nic
        opt_model: ["e1000" | "virtio" | "i82551" | ...]
                   Default is e1000.
        opt_addr: ''
            note: PCI cards only.
        """
        if 'opt_model' in options.keys():
            model = options['opt_model']
        else:
            model = 'e1000'

        if 'opt_hostfwd' in options.keys():
            port = self.virt_pool.alloc_port(self.vm_name)
            if port is None:
                return
            dut_ip = self.host_dut.crb['IP']
            self.vm_ip = '%s:%d' % (dut_ip, port)

        qemu = ET.SubElement(self.domain, 'qemu:commandline')
        ET.SubElement(qemu, 'qemu:arg', {'value': '-net'})
        if 'opt_addr' in options.keys():
            pci = self.__parse_pci(options['opt_addr'])
            if pci is None:
                return False
            bus, slot, func = pci
            ET.SubElement(qemu, 'qemu:arg',
                          {'value': 'nic,model=e1000,addr=0x%s' % slot})
        else:
            ET.SubElement(qemu, 'qemu:arg',
                          {'value': 'nic,model=e1000,addr=0x%x'
                           % self.pciindex})
            self.pciindex += 1

        if 'opt_hostfwd' in options.keys():
            ET.SubElement(qemu, 'qemu:arg', {'value': '-net'})
            ET.SubElement(qemu, 'qemu:arg', {'value': 'user,hostfwd='
                                             'tcp:%s:%d-:22' % (dut_ip, port)})

    def add_vm_virtio_serial_channel(self, **options):
        """
        Options:
            path: virtio unix socket absolute path
            name: virtio serial name in vm
        """
        devices = self.domain.find('devices')
        channel = ET.SubElement(devices, 'channel', {'type': 'unix'})
        for opt in ['path', 'name']:
            if opt not in options.keys():
                print "invalid virtio serial channel setting"
                return

        ET.SubElement(
            channel, 'source', {'mode': 'bind', 'path': options['path']})
        ET.SubElement(
            channel, 'target', {'type': 'virtio', 'name': options['name']})
        ET.SubElement(channel, 'address', {'type': 'virtio-serial',
                                           'controller': '0', 'bus': '0',
                                           'port': '%d' % self.pciindex})
        self.pciindex += 1

    def get_vm_ip(self):
        return self.vm_ip

    def get_pci_mappings(self):
        """
        Return guest and host pci devices mapping structure
        """
        return self.pci_maps

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
                (self.host_dut.Name, self.vm_name))
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

    def _start_vm(self):
        xml_file = "/tmp/%s.xml" % self.vm_name
        try:
            os.remove(xml_file)
        except:
            pass
        self.root.write(xml_file)
        self.host_session.copy_file_to(xml_file)
        time.sleep(2)

        self.host_session.send_expect("virsh", "virsh #")
        self.host_session.send_expect(
            "create /root/%s.xml" % self.vm_name, "virsh #")
        self.host_session.send_expect("quit", "# ")
        out = self.__control_session('ping', '120')

        if "Not responded" in out:
            raise StartVMFailedException("Not response in 120 seconds!!!")

        self.__wait_vmnet_ready()

    def __wait_vmnet_ready(self):
        """
        wait for 120 seconds for vm net ready
        10.0.2.* is the default ip address allocated by qemu
        """
        count = 20
        while count:
            out = self.__control_session('ifconfig')
            if "10.0.2" in out:
                return True
            time.sleep(6)
            count -= 1

        raise StartVMFailedException("Virtual machine control net not ready " +
                                     "in 120 seconds!!!")

    def stop(self):
        self.__control_session("shutdown")
        time.sleep(5)
