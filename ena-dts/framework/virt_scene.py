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
import time
import utils

from settings import CONFIG_ROOT_PATH, get_netdev
from config import VirtConf
from config import VIRTCONF
from exception import *
from qemu_kvm import QEMUKvm
from pmd_output import PmdOutput
from utils import create_mask

# scenario module for handling scenario
# 1. load configurations
# config saved in conf/scenarios/name.cfg
# load configurations will saved in vm list
# 2. handle special config
#   pf_idx=0,vf_num=2,driver=default;
#   PF0 igb_uio, create 2VFs by default driver
# 3. create scenario
#   allocate hareware resource for this vm
#   cpu, memory, pf devices, vf devices
#   configuration vm
#   run pre_vm commands
#   create vm
#   run post_vm commands


class VirtScene(object):

    def __init__(self, dut, tester, scene_name):
        self.name = scene_name
        self.host_dut = dut
        self.tester_dut = tester
        self.pre_cmds = []
        self.post_cmds = []

        self.vm_dut_enable = False
        self.auto_portmap = True
        self.vm_type = 'kvm'
        self.def_target = "x86_64-native-linuxapp-gcc"
        self.host_bound = False

        # for vm dut init_log
        self.host_dut.test_classname = 'dts'

    def load_config(self):
        try:
            self.vm_confs = {}
            conf = VirtConf(CONFIG_ROOT_PATH + '/scene/' + self.name + '.cfg')
            self.sections = conf.virt_conf.get_sections()
            for vm in self.sections:
                conf.load_virt_config(vm)
                vm_conf = conf.get_virt_config()
                self.vm_confs[vm] = vm_conf
        except:
            raise VirtConfigParseException

    def prepare_vm(self):
        host_cfg = None
        for conf in self.vm_confs.keys():
            if conf == 'scene':
                for cfg in self.vm_confs['scene']:
                    if 'suite' in cfg.keys():
                        self.prepare_suite(cfg['suite'])
                    if 'host' in cfg.keys():
                        self.host_bound = True
                        host_cfg = cfg['host'][0]
                self.vm_confs.pop('scene')
            else:
                vm_name = conf
                vm_conf = self.vm_confs[vm_name]
                self.prepare_cpu(vm_name, vm_conf)
                self.prepare_devices(vm_conf)
                self.prepare_vmdevice(vm_conf)

        # dpdk should start after vf devices created
        if host_cfg:
            self.prepare_host(**host_cfg)

    def cleanup_vm(self):
        # reload config for has been changed when handle config
        self.load_config()
        for conf in self.vm_confs.keys():
            if conf != 'scene':
                vm_name = conf
                vm_conf = self.vm_confs[vm_name]
                self.cleanup_devices(vm_conf)

    def prepare_suite(self, conf):
        for param in conf:
            if 'dut' in param.keys():
                if param['dut'] == 'vm_dut':
                    self.vm_dut_enable = True
            if 'type' in param.keys():
                if param['type'] == 'xen':
                    self.vm_type = 'xen'
                # not implement yet
                if param['type'] == 'vmware':
                    self.vm_type = 'vmware'
                # not implement yet
                if param['type'] == 'container':
                    self.vm_type = 'container'
            if 'portmap' in param.keys():
                if param['portmap'] == 'cfg':
                    self.auto_portmap = False

    def prepare_host(self, **opts):
        if 'dpdk' not in opts.keys():
            print utils.RED("Scenario host parameter request dpdk option!!!")
            raise VirtConfigParamException('host')

        if 'cores' not in opts.keys():
            print utils.RED("Scenario host parameter request cores option!!!")
            raise VirtConfigParamException('host')

        if 'target' in opts.keys():
            target = opts['target']
        else:
            target = self.def_target

        self.host_dut.set_target(target, bind_dev=True)

        if opts['dpdk'] == 'testpmd':
            self.pmdout = PmdOutput(self.host_dut)
            cores = opts['cores'].split()
            out = self.pmdout.start_testpmd(cores)
            if 'Error' in out:
                raise VirtHostPrepareException()

    def prepare_cpu(self, vm_name, conf):
        cpu_param = {}
        for params in conf:
            if 'cpu' in params.keys():
                cpu_conf = params['cpu'][0]
                break

        if 'skipcores' in cpu_conf.keys():
            cpus = cpu_conf['skipcores'].split()
            # remove invalid configured core
            for cpu in cpus:
                if int(cpu) not in self.host_dut.virt_pool.cores:
                    cpus.remove(cpu)
            # create core mask for reserver cores
            core_mask = create_mask(cpus)
            # reserve those skipped cores
            self.host_dut.virt_pool.reserve_cpu(core_mask)

        if 'numa' in cpu_conf.keys():
            if cpu_conf['numa'] == 'auto':
                numa = self.host_dut.ports_info[0]['port'].socket
            else:
                numa = int(cpu_conf['numa'])
        else:
            numa = 0

        if 'number' in cpu_conf.keys():
            num = int(cpu_conf['number'])
        else:
            num = 2

        if 'model' in cpu_conf.keys():
            model = cpu_conf['model']
        else:
            model = 'host'

        cpu_topo = ''
        if 'cpu_topo' in cpu_conf.keys():
            cpu_topo = cpu_conf['cpu_topo']

        pin_cores = []
        if 'cpu_pin' in cpu_conf.keys():
            pin_cores = cpu_conf['cpu_pin'].split()

        if len(pin_cores):
            cores = self.host_dut.virt_pool.alloc_cpu(vm=vm_name, corelist=pin_cores)
        else:
            cores = self.host_dut.virt_pool.alloc_cpu(vm=vm_name, number=num,
                                                      socket=numa)
        core_cfg = ''
        for core in cores:
            core_cfg += '%s ' % core
        core_cfg = core_cfg[:-1]

        cpu_param['number'] = num
        cpu_param['model'] = model
        cpu_param['cpupin'] = core_cfg
        cpu_param['cputopo'] = cpu_topo

        # replace with allocated cpus
        params['cpu'] = [cpu_param]

    def prepare_devices(self, conf):
        for params in conf:
            if 'dev_gen' in params.keys():
                index = conf.index(params)
                for param in params['dev_gen']:
                    self.handle_dev_gen(**param)
                # remove handled 'dev_gen' configuration
                conf.remove(conf[index])

    def cleanup_devices(self, conf):
        for params in conf:
            if 'dev_gen' in params.keys():
                for param in params['dev_gen']:
                    self.handle_dev_destroy(**param)

    def prepare_vmdevice(self, conf):
        for params in conf:
            if 'device' in params.keys():
                for param in params['device']:
                    if 'vf_idx' in param.keys():
                        new_param = self.prepare_vf_conf(param)
                        index = params['device'].index(param)
                        params['device'][index] = new_param
                    elif 'pf_idx' in param.keys():
                        new_param = self.prepare_pf_conf(param)
                        index = params['device'].index(param)
                        params['device'][index] = new_param

                for param in params['device']:
                    netdev = get_netdev(self.host_dut, param['opt_host'])
                    if netdev is not None:
                        netdev.bind_driver('pci-stub')

    def prepare_pf_conf(self, param):
        pf_param = {}
        # strip pf pci id
        pf = int(param['pf_idx'])
        if pf >= len(self.host_dut.ports_info):
            raise VirtDeviceCreateException
        pf_pci = self.host_dut.ports_info[pf]['pci']
        pf_param['driver'] = 'pci-assign'
        pf_param['opt_host'] = pf_pci
        if param['guestpci'] != 'auto':
            pf_param['opt_addr'] = param['guestpci']

        return pf_param

    def prepare_vf_conf(self, param):
        vf_param = {}
        # strip vf pci id
        if 'pf_dev' in param.keys():
            pf = int(param['pf_dev'])
            pf_net = self.host_dut.ports_info[pf]['port']
            vfs = self.host_dut.ports_info[pf]['vfs_port']
            vf_idx = int(param['vf_idx'])
            if vf_idx >= len(vfs):
                raise VirtDeviceCreateException
            vf_pci = vfs[vf_idx].pci
            vf_param['driver'] = 'pci-assign'
            vf_param['opt_host'] = vf_pci
            if param['guestpci'] != 'auto':
                vf_param['opt_addr'] = param['guestpci']
            if 'mac' in param.keys():
                pf_net.set_vf_mac_addr(vf_idx, param['mac'])
        else:
            print utils.RED("Invalid vf device config, request pf_dev")

        return vf_param

    def reset_pf_cmds(self, port):
        command = {}
        command['type'] = 'host'
        if not self.host_bound:
            intf = self.host_dut.ports_info[port]['intf']
            command['command'] = 'ifconfig %s up' % intf
            self.reg_postvm_cmds(command)

    def handle_dev_gen(self, **opts):
        if 'pf_idx' in opts.keys():
            port = int(opts['pf_idx'])
            if 'vf_num' in opts.keys():
                vf_num = int(opts['vf_num'])
            else:
                print utils.RED("No vf_num for port %d, assum one VF" % port)
                vf_num = 1
            if 'driver' in opts.keys():
                driver = opts['driver']

            try:
                print utils.GREEN("create vf %d %d %s" % (port, vf_num, driver))
                self.host_dut.generate_sriov_vfs_by_port(port, vf_num, driver)
                self.reset_pf_cmds(port)
            except:
                print utils.RED("Failed to create vf as requested!!!")
                raise VirtDeviceCreateException

    def handle_dev_destroy(self, **opts):
        if 'pf_idx' in opts.keys():
            port = int(opts['pf_idx'])

            try:
                print utils.GREEN("destroy vfs on port %d" % port)
                self.host_dut.destroy_sriov_vfs_by_port(port)
            except:
                print utils.RED("Failed to destroy vf as requested!!!")

    def reg_prevm_cmds(self, command):
        """
        command: {'type':'host/tester/vm',
                    define which crb command progress
                  'command':'XXX',
                    command send to crb
                  'expect':'XXX',
                    expected output for command
                  'timeout': 60,
                  'verify': True or False
                    check whether command sucessfully
                 }
        """
        self.pre_cmds.append(command)

    def run_pre_cmds(self):
        for cmd in self.pre_cmds:
            if cmd['type'] == 'vm':
                print utils.RED("Can't run vm command when vm not ready")
            elif cmd['type'] == 'host':
                crb = self.host_dut
            elif cmd['type'] == 'tester':
                crb = self.tester
            else:
                crb = self.host_dut

            if 'expect' not in cmd.keys():
                expect = "# "
            else:
                expect = cmd['expect']

            if 'verify' not in cmd.keys():
                verify = False
            else:
                verify = cmd['verify']

            if 'timeout' not in cmd.keys():
                timeout = 5
            else:
                timeout = cmd['timeout']

            ret = crb.send_expect(cmd['command'], expect, timeout=timeout,
                                  verify=verify)

            if type(ret) is int and ret != 0:
                print utils.RED("Failed to run command %s" % cmd['command'])
                raise VirtVmOperationException

    def reg_postvm_cmds(self, command):
        """
        command: {'type':'host/tester/vm',
                    define which crb command progress
                  'command':'XXX',
                    command send to crb
                  'expect':'XXX',
                    expected output for command
                  'verify':'yes or no'
                    check whether command sucessfully
        """
        self.post_cmds.append(command)
        pass

    def run_post_cmds(self):
        for cmd in self.post_cmds:
            if cmd['type'] == 'vm':
                crb = self.vm_dut
            elif cmd['type'] == 'host':
                crb = self.host_dut
            elif cmd['type'] == 'tester':
                crb = self.tester
            else:
                crb = self.host_dut

            if 'expect' not in cmd.keys():
                expect = "# "
            else:
                expect = cmd['expect']

            if 'verify' not in cmd.keys():
                verify = False
            else:
                verify = cmd['verify']

            if 'timeout' not in cmd.keys():
                timeout = 5
            else:
                timeout = cmd['timeout']

            ret = crb.send_expect(cmd['command'], expect, timeout=timeout,
                                  verify=verify)

            if type(ret) is int and ret != 0:
                print utils.RED("Failed to run command %s" % cmd['command'])
                raise VirtVmOperationException

    def merge_params(self, vm, params):
        for param in params:
            index = vm.find_option_index(param.keys()[0])
            if index is not None:
                vm.params[index] = param
            else:
                vm.params.append(param)
        index = vm.find_option_index('name')
        # update vm name
        vm.params[index]['name'][0]['name'] = vm.vm_name

    def get_cputopo(self, params):
        for param in params:
            if 'cpu' in param.keys():
                cpu_topo = param['cpu'][0]['cputopo']
                return cpu_topo

    def start_vms(self):
        self.vms = []
        if self.vm_type == 'kvm':
            for vm_name in self.vm_confs.keys():
                # tricky here, QEMUKvm based on suite and vm name
                # suite is virt_global, vm_name just the type
                vm = QEMUKvm(self.host_dut, self.vm_type.upper(),
                             'virt_global')
                vm.load_config()
                vm.vm_name = vm_name
                vm.set_vm_default()
                # merge default config and scene config
                scene_params = self.vm_confs[vm_name]
                # reload merged configurations
                self.merge_params(vm, scene_params)
                # get cpu topo
                topo = self.get_cputopo(scene_params)
                try:
                    vm_dut = vm.start(load_config=False, set_target=False,
                                      auto_portmap=self.auto_portmap,
                                      cpu_topo=topo)
                    if vm_dut is None:
                        raise Exception("Set up VM ENV failed!")

                    vm_info = {}
                    vm_info[vm_name] = vm
                    vm_info[vm_name + '_session'] = vm_dut
                    self.vms.append(vm_info)

                except Exception as e:
                    print utils.RED("Failure for %s" % str(e))

    def get_vm_duts(self):
        duts = []
        for vm_info in self.vms:
            for vm_obj in vm_info.keys():
                if 'session' in vm_obj:
                    duts.append(vm_info[vm_obj])

        return duts

    def create_scene(self):
        self.prepare_vm()
        self.run_pre_cmds()
        self.start_vms()
        self.run_post_cmds()
        pass

    def set_target(self, target):
        for vm_info in self.vms:
            for vm_obj in vm_info.keys():
                if 'session' in vm_obj:
                    vm_info[vm_obj].set_target(target)

    def destroy_scene(self):
        for vm_info in self.vms:
            for vm_obj in vm_info.keys():
                if 'session' in vm_obj:
                    vm_info[vm_obj].kill_all()
                    vm_info[vm_obj].close()
                    vm_info[vm_obj].logger.logger_exit()
            for vm_obj in vm_info.keys():
                if 'session' not in vm_obj:
                    vm_info[vm_obj].stop()
                    vm_info[vm_obj] = None
        self.cleanup_vm()


if __name__ == "__main__":

    class QEMUKvm():

        def __init__(self, dut, vm_name, suite_name):
            print vm_name
            print suite_name

        def start(self):
            print self.params
            return True

    class simple_dev(object):

        def __init__(self, pci):
            self.pci = pci
            self.socket = 1

    emu_dev1 = simple_dev("00:00.1")
    emu_dev2 = simple_dev("00:00.2")
    emu_dev3 = simple_dev("00:00.3")
    emu_dev4 = simple_dev("00:00.4")

    class simple_dut(object):

        def __init__(self):
            self.ports_info = [
                {'vfs_port': [emu_dev1, emu_dev2]},
                {'vfs_port': [emu_dev3, emu_dev4]},
            ]
            self.virt_pool = simple_resource()

        def send_expect(self, cmds, expected, timeout=5,
                        alt_session=False, verify=False):
            print cmds + "---" + expected

    class simple_resource(object):

        def __init__(self):
            pass

        def reserve_cpu(self, coremask):
            print "reserve " + coremask

        def alloc_cpu(self, vm='', number=-1, socket=-1, corelist=None):
            print "alloc %s num %d on socket %d" % (vm, number, socket)

    dut = simple_dut()
    scene = VirtScene(dut, None, "vf_passthrough")
    scene.load_config()
    scene.create_scene()
    scene.destroy_scene()
