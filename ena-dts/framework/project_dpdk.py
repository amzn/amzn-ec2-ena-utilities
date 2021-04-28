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
   * Add support for the meson build system
   * Make pktgen directory configurable
   * Pass cmdline arguments to the tests to the DUT/Tester
   * Automatically skip env setup if already performed, unless forced to do so
   * Remove code specific for other PMDs
   * Do not check for "vfio_iommu_type1" when using vfio-pci
   * Check if the driver wants to use write-combining and load igb_uio
     accordingly
   * Pass option to always build IGB_UIO when using Makefile
   * Allow to build the PMD for the debug mode
   * Add methods to the DPDKdut class:
   * Add custom way of conifguring prerequistites, packages, module loading and
     cleanup
   * Remove method for the DPDKtester:
     - setup_memory
     - remove all versions of setup_modules and restore_modules
   * Add method for the DPDKtester:
     - set_target
   * Add functions:
     - check_build
     - check_build_system
     - install_apps
     - install_packages
     - copy_files
     - copy_pcap
     - untar
     - install_epel
     - install_libpcap
     - install_lua
     - install_patched_vfio
     - build_igb_uio
"""

import os
import re
import time

from settings import NICS, load_global_setting, accepted_nic
from settings import DPDK_RXMODE_SETTING, HOST_DRIVER_SETTING, HOST_DRIVER_MODE_SETTING
from settings import PCAP_DIR, PCAP_TESTER
from settings import FOLDERS
from settings import DEBUG_SETTING
from ssh_connection import SSHConnection
from crb import Crb
from dut import Dut
from tester import Tester
from logger import getLogger
from settings import IXIA, DRIVERS
from exception import PcapFileException

MAKE_BUILD = 1
MESON_BUILD_VERSION = 2005
MESON_BUILD = 2

class DPDKdut(Dut):

    """
    DPDK project class for DUT. DTS will call set_target function to setup
    build, memory and kernel module.
    """

    def __init__(self, crb, serializer):
        super(DPDKdut, self).__init__(crb, serializer)
        self.testpmd = None
        self.pktgen_dir = 'pktgen'

    def set_target(self, target, test_configs, bind_dev=True):
        """
        Set env variable, these have to be setup all the time. Some tests
        need to compile example apps by themselves and will fail otherwise.
        Set hugepage on DUT and install modules required by DPDK.
        Configure default ixgbe PMD function.
        """
        self.target = target
        self.set_toolchain(target)

        ver_str = self.send_expect("cat VERSION", "# ");
        self.build_system = check_build_system(ver_str)

        # set env variable
        # These have to be setup all the time. Some tests need to compile
        # example apps by themselves and will fail otherwise.
        self.send_expect("export RTE_TARGET=" + target, "#")
        # May be required by the meson build system for the pktgen

        self.set_rxtx_mode()

        if not test_configs["skip_target_env_setup"]:
            self.build_install_dpdk(target)
            install_apps(self)
            self.setup_memory()
            self.setup_modules()
            self.extra_nic_setup()
        else:
            self.logger.info('SKIPPED target environment setup')

    def set_rxtx_mode(self):
        """
        Set default RX/TX PMD function,
        only i40e support scalar/full RX/TX model.
        ixgbe and fm10k only support vector and no vector model
        all NIC default rx/tx model is vector PMD
        """

        mode = load_global_setting(DPDK_RXMODE_SETTING)
        if mode == 'scalar':
            self.send_expect("sed -i -e 's/CONFIG_RTE_LIBRTE_I40E_INC_VECTOR=.*$/"
                             + "CONFIG_RTE_LIBRTE_I40E_INC_VECTOR=n/' config/common_base", "# ", 30)
            self.send_expect("sed -i -e 's/CONFIG_RTE_LIBRTE_I40E_RX_ALLOW_BULK_ALLOC=.*$/"
                             + "CONFIG_RTE_LIBRTE_I40E_RX_ALLOW_BULK_ALLOC=y/' config/common_base", "# ", 30)
        if mode == 'full':
            self.send_expect("sed -i -e 's/CONFIG_RTE_LIBRTE_I40E_INC_VECTOR=.*$/"
                             + "CONFIG_RTE_LIBRTE_I40E_INC_VECTOR=n/' config/common_base", "# ", 30)
            self.send_expect("sed -i -e 's/CONFIG_RTE_LIBRTE_I40E_RX_ALLOW_BULK_ALLOC=.*$/"
                             + "CONFIG_RTE_LIBRTE_I40E_RX_ALLOW_BULK_ALLOC=n/' config/common_base", "# ", 30)
        if mode == 'novector':
            self.send_expect("sed -i -e 's/CONFIG_RTE_IXGBE_INC_VECTOR=.*$/"
                             + "CONFIG_RTE_IXGBE_INC_VECTOR=n/' config/common_base", "# ", 30)
            self.send_expect("sed -i -e 's/CONFIG_RTE_LIBRTE_I40E_INC_VECTOR=.*$/"
                             + "CONFIG_RTE_LIBRTE_I40E_INC_VECTOR=n/' config/common_base", "# ", 30)
            self.send_expect("sed -i -e 's/CONFIG_RTE_LIBRTE_FM10K_INC_VECTOR=.*$/"
                             + "CONFIG_RTE_LIBRTE_FM10K_INC_VECTOR=n/' config/common_base", "# ", 30)

    def set_package(self, pkg_name="", patch_list=[], pktgen=None):
        self.package = pkg_name
        self.patches = patch_list
        self.pktgen = pktgen

    def build_install_dpdk(self, target, extra_options=''):
        """
        Build DPDK source code with specified target.
        """
        build_install_dpdk = getattr(self, 'build_install_dpdk_%s' % self.get_os_type())
        build_install_dpdk(target, extra_options)

    def build_install_dpdk_linux(self, target, extra_options):
        """
        Build DPDK source code on linux with specified target.
        """
        debug_make = 'EXTRA_CFLAGS="-g -O0" ' \
            if load_global_setting(DEBUG_SETTING) == "yes" else ""
        build_time = 300
        if "icc" in target:
            build_time = 900

        # Remove any previous installed DPDK
        self.send_expect("rm -f $PKG_CONFIG_PATH/libdpdk.pc $PKG_CONFIG_PATH/libdpdk-libs.pc", "# ")
        if self.build_system is MAKE_BUILD:
            # Configure
            out = self.send_expect("make config T=%s O=%s" %
                                   (target, target), "# ", build_time)
            # compile
            out = self.send_expect("%smake -j %d T=%s O=%s %s" %
                                   (debug_make,
                                    self.number_of_cores,
                                    target,
                                    target,
                                    extra_options),
                                   "# ", build_time)
            #should not check test app compile status, because if test compile
            # fail, all unit test can't exec, but others case will exec
            # sucessfull
            self.build_install_dpdk_test_app(target, build_time)

            if("Error" in out or "No rule to make" in out):
                self.logger.error("ERROR - try without '-j'")
                # if Error try to execute make without -j option
                out = self.send_expect("%smake T=%s O=%s %s" %
                                       (debug_make,
                                        target,
                                        target,
                                        extra_options),
                                       "# ", 120)
                self.build_install_dpdk_test_app(target, build_time)
            check_build(out)
        elif self.build_system is MESON_BUILD:
            # configure
            out = self.send_expect("meson {} -Dprefix={}".format(target, self.install_dir),
                                   "# ", build_time)
            check_build(out)
            out = self.send_expect("ninja -C %s" %(target), "# ", build_time)
            check_build(out)
            out = self.send_expect("ninja -C %s install" %(target), "# ", build_time)
            check_build(out)
        else:
            assert False, "Invalid build system detected"

        # Build pktgen
        if self.pktgen is not None:
            include_var = "C_INCLUDE_PATH={}/include".format(self.install_dir)
            self.send_expect("cd {}".format(self.pktgen_dir), "# ")
            if self.build_system is MAKE_BUILD:
                out = self.send_expect("{} {} make".format(debug_make, include_var),
                                       "# ", build_time)
            else:
                out = self.send_expect("meson build -Denable_lua=true",
                                       "#", build_time)
                check_build(out)
                out = self.send_expect("{} ninja -C build".format(include_var), "#", build_time)
            self.send_expect("cd ..", "# ")
            check_build(out)

    def build_install_dpdk_freebsd(self, target, extra_options):
        """
        Build DPDK source code on Freebsd with specified target.
        """
        # clean all
        self.send_expect("rm -rf " + target, "#")
        self.send_expect("rm -rf %s" % r'./app/test/test_resource_c.res.o' , "#")
        self.send_expect("rm -rf %s" % r'./app/test/test_resource_tar.res.o' , "#")
        self.send_expect("rm -rf %s" % r'./app/test/test_pci_sysfs.res.o' , "#")
        build_time = 120

        out = self.send_expect("make config T=%s O=%s" %
            (target, target), "# ", build_time)
        # compile
        out = self.send_expect("make -j %d T=%s O=%s CC=gcc48 %s" %
                               (self.number_of_cores,
                                target,
                                target,
                                extra_options),
                               "#", build_time)
        #should not check test app compile status, because if test compile fail,
        #all unit test can't exec, but others case will exec sucessfull
        self.build_install_dpdk_test_app(target, build_time, os_type="freebsd")

        if("Error" in out or "No rule to make" in out):
            self.logger.error("ERROR - try without '-j'")
            # if Error try to execute make without -j option
            out = self.send_expect("make T=%s O=%s CC=gcc48 %s" %
                                   (target,
                                    target,
                                    extra_options),
                                   "#", build_time)
            self.build_install_dpdk_test_app(target, build_time, os_type="freebsd")

        assert ("Error" not in out), "Compilation error..."
        assert ("No rule to make" not in out), "No rule to make error..."

    def build_install_dpdk_test_app(self, target, build_time, os_type="linux"):
        cmd_build_test = "make -j %d -C test/" % (self.number_of_cores)
        if os_type == "freebsd":
            cmd_build_test = "make -j %d -C test/ CC=gcc48" % (self.number_of_cores)

    def prepare_package(self, test_configs):
        if not self.skip_setup:
            copy_files(self)
        if not test_configs["skip_target_env_setup"]:
            install_packages(self)
            install_patched_vfio(self)
            build_igb_uio(self)
        else:
            self.logger.info('DUT: SKIPPED packages installation')

    def prerequisites(self, test_configs):
        """
        Copy DPDK package to DUT and apply patch files.
        """
        self.set_env()
        self.prepare_package(test_configs)
        self.dut_prerequisites()
        self.stage = "post-init"

    def extra_nic_setup(self):
        """
        Some nic like RRC required additional setup after module installed
        """
        for port_info in self.ports_info:
            netdev = port_info['port']
            netdev.setup()

    def bind_interfaces_linux(self, driver='igb_uio', nics_to_bind=None):
        """
        Bind the interfaces to the selected driver. nics_to_bind can be None
        to bind all interfaces or an array with the port indexes
        """
        binding_list = '--bind=%s ' % driver

        current_nic = 0
        for port_info in self.ports_info:
            if nics_to_bind is None or current_nic in nics_to_bind:
                binding_list += '%s ' % (port_info['pci'])
            current_nic += 1

        bind_script_path = self.get_dpdk_bind_script()
        self.send_expect('%s --force %s' % (bind_script_path, binding_list), '# ')

    def unbind_interfaces_linux(self, nics_to_bind=None):
        """
        Unbind the interfaces
        """

        binding_list = '-u '

        current_nic = 0
        for port_info in self.ports_info:
            if nics_to_bind is None or current_nic in nics_to_bind:
                binding_list += '%s ' % (port_info['pci'])
            current_nic += 1

        bind_script_path = self.get_dpdk_bind_script()
        self.send_expect('%s --force %s' % (bind_script_path, binding_list), '# ')

    def build_dpdk_apps(self, folder, extra_options=''):
        """
        Build dpdk sample applications.
        """
        build_dpdk_apps = getattr(self, 'build_dpdk_apps_%s' % self.get_os_type())
        return build_dpdk_apps(folder, extra_options)

    def build_dpdk_apps_linux(self, folder, extra_options):
        """
        Build dpdk sample applications on linux.
        """
        # icc compile need more time
        if 'icc' in self.target:
            timeout = 300
        else:
            timeout = 90
        return self.send_expect("make -j %d -C %s %s" % (self.number_of_cores,
                                                         folder, extra_options),
                                "# ", timeout)

    def build_dpdk_apps_freebsd(self, folder, extra_options):
        """
        Build dpdk sample applications on Freebsd.
        """
        self.send_expect("rm -rf %s" % r'./app/test/test_resource_c.res.o' , "#")
        self.send_expect("rm -rf %s" % r'./app/test/test_resource_tar.res.o' , "#")
        self.send_expect("rm -rf %s" % r'./app/test/test_pci_sysfs.res.o' , "#")
        return self.send_expect("make -j %d -C %s %s CC=gcc48" % (self.number_of_cores,
                                                                  folder, extra_options),
                                "# ", 180)

    def get_blacklist_string(self, target, nic):
        """
        Get black list command string.
        """
        get_blacklist_string = getattr(self, 'get_blacklist_string_%s' % self.get_os_type())
        return get_blacklist_string(target, nic)

    def get_blacklist_string_linux(self, target, nic):
        """
        Get black list command string on Linux.
        """
        blacklist = ''
        dutPorts = self.get_ports(nic)
        for port in range(0, len(self.ports_info)):
            if(port not in dutPorts):
                blacklist += '-b %s ' % self.ports_info[port]['pci']
        return blacklist

    def get_blacklist_string_freebsd(self, target, nic):
        """
        Get black list command string on Freebsd.
        """
        blacklist = ''
        # No blacklist option in FreeBSD
        return blacklist


class DPDKtester(Tester):

    """
    DPDK project class for tester. DTS will call prerequisites function to setup
    interface and generate port map.
    """

    def __init__(self, crb, serializer):
        self.NAME = "tester"
        super(DPDKtester, self).__init__(crb, serializer)

    def prerequisites(self, test_configs, perf_test=False):
        """
        Setup hugepage on tester and copy validation required files to tester.
        """
        self.kill_all()

        self.set_env()

        if not self.skip_setup:
            copy_files(self)
        if not test_configs["skip_target_env_setup"]:
            install_packages(self)
            install_patched_vfio(self)
            build_igb_uio(self)
        else:
            self.logger.info('TESTER: SKIPPED packages installation')

        self.tester_prerequisites()

        self.set_promisc()
        # use software pktgen for performance test
        if perf_test is True:
            try:
                if self.crb[IXIA] is not None:
                    self.logger.info("Use hardware packet generator")
            except Exception as e:
                self.logger.warning("Use default software pktgen")
                out = self.send_expect("ls /root/igb_uio.ko", "# ")
                assert ("No such file or directory" not in out), "Can not find /root/igb_uio.ko for performance"
                self.setup_memory()

        self.stage = "post-init"

    def set_target(self, target, test_configs):
        build_time = 300
        [arch, _, _, toolchain] = target.split('-')

        debug_make = 'EXTRA_CFLAGS="-g -O0" ' \
            if load_global_setting(DEBUG_SETTING) == "yes" else ""

        self.architecture = arch

        self.send_expect("cd {}".format(self.base_dir), "#")

        ver_str = self.send_expect("cat VERSION", "# ");
        self.build_system = check_build_system(ver_str)

        self.send_expect("export RTE_TARGET=" + target, "#")

        if not test_configs["skip_target_env_setup"]:
            # Remove any previous installed DPDK
            self.send_expect("rm -f $PKG_CONFIG_PATH/libdpdk.pc $PKG_CONFIG_PATH/libdpdk-libs.pc", "# ")

            if self.build_system is MAKE_BUILD:
                self.send_expect("make config T={} O={}".format(target, target),
                                 "# ", build_time)
                out = self.send_expect(
                    "{}make -j {} T={} O={}".format(
                        debug_make, self.number_of_cores, target, target),
                    "# ", build_time)
                check_build(out)
            elif self.build_system is MESON_BUILD:
                # configure
                out = self.send_expect("meson {} -Dprefix={}".format(target, self.install_dir),
                                       "# ", build_time)
                check_build(out)
                out = self.send_expect("ninja -C %s" %(target), "# ", build_time)
                check_build(out)
                out = self.send_expect("ninja -C %s install" %(target), "# ", build_time)
                check_build(out)
            else:
                assert False, "Invalid build system detected"

            self.send_expect("cd {}".format(self.pktgen_dir), "#")
            include_var = "C_INCLUDE_PATH={}/include".format(self.install_dir)
            if self.build_system is MAKE_BUILD:
                out = self.send_expect("{} {} make".format(debug_make, include_var), "# ", build_time)
            else:
                out = self.send_expect("meson build -Denable_lua=true",
                                       "#", build_time)
                check_build(out)
                out = self.send_expect("{} ninja -C build".format(include_var), "#", build_time)
            check_build(out)

            install_apps(self)
            self.setup_modules()
            self.send_expect("cd {}".format(self.base_dir), "#")
        else:
            self.logger.info('SKIPPED target environment setup')

def check_build(msglog):
    msglog_low = msglog.lower()

    for l in msglog_low.splitlines():
        if "cc" not in l and "werror" not in l:
            assert ("error" not in l), "Compilation error..."
            assert ("no rule to make" not in l), "No rule to make error..."

def check_build_system(version_str):
    m = re.match(r'\s*(\d+)\.(\d+)\.\d+', version_str)
    if not m:
        return 0

    version = int(m.group(1) + m.group(2))

    if version < MESON_BUILD_VERSION:
        return MAKE_BUILD
    else:
        return MESON_BUILD

def install_apps(host):
    build_time = 300
    debug_make = 'EXTRA_CFLAGS="-g -O0" ' \
        if load_global_setting(DEBUG_SETTING) == "yes" else ""
    for app in host.apps:
        host.send_expect("cd {}/{}".format(host.base_dir, app), "#")
        out = host.send_expect("echo $?", "#")
        if "0" in out:
            cmd = "{}make".format(debug_make)
            out = host.send_expect(cmd, "# ", build_time)
            check_build(out)
    host.send_expect("cd {}".format(host.base_dir), "#")


def install_packages(host):
    host.to_base_dir()
    kernel = host.send_expect("uname -r", "# ")
    os_type = host.send_expect("uname -a", "# ")
    os_type = os_type.lower()
    if "ubuntu" in os_type or "debian" in os_type:
        host.send_expect("apt-get update", "# ", 300)
        host.send_expect("apt-get install -y libnuma-dev libbsd-dev libpcap0.8-dev"
                         " python build-essential stress git net-tools "
                         "libreadline-dev liblua5.3-dev gdb python3 "
                         "python3-pip",
                         "# ", 300)
    else:
        host.send_expect("yum install -y -q wget", host.prompt, 60)
        install_epel(host)
        host.send_expect("yum install -y -q gcc libbsd-devel numactl-devel.x86_64"
                         " python python-pip patch kernel-{} kernel-devel-{}"
                         " stress pciutils psmisc git readline-devel gdb"
                         " python3 python3-pip python36 python36-pip"
                         .format(kernel, kernel), "# ", 300)
        install_libpcap(host)
    install_lua(host)

    # Alias pip-3.6 as pip3 for the AmazonLinux instances
    host.send_expect("pip3", "# ")
    if host.send_expect("echo $?", "# ") != "0":
        host.send_expect("alias pip3=pip-3.6", "# ")
    host.send_expect("pip3 install scapy -q", "# ", 200)
    host.send_expect("pip3 install ninja meson -q", "# ", 200)


def copy_files(host):
    host.send_expect("rm -rf %s" % host.base_dir, "#")
    for path in host.packages:
        path = FOLDERS["Depends"] + "/" + path
        if os.path.isfile(path) is True:
            host.session.copy_file_to(path, host.dst_dir)
    untar(host, host.packages[0], host.base_dir.split("/")[0])
    for p in host.packages[1:]:
        untar(host, p, host.base_dir)


def copy_pcap(host, pcap_name):
    p = "# "
    path = host.test_configs["BW_pcap_tester"]

    if path is None:
        raise PcapFileException(PcapFileException.ERR_PARAM)

    if os.path.isfile(path) is False:
        raise PcapFileException(PcapFileException.ERR_PATH, path)

    host.send_expect("cd {}".format(host.base_dir), p)
    host.send_expect("mkdir {}".format(PCAP_DIR), p)
    host.session.copy_file_to(path, "{}/{}".format(host.dst_dir, pcap_name), p)
    host.send_expect("\cp -f {}/{} {}/{}".format(host.dst_dir, pcap_name,
                                                 host.base_dir, PCAP_DIR), p)
    out = host.send_expect("ls {}/{}/{}".format(host.base_dir,
                                                PCAP_DIR, pcap_name), p)
    if "No such file" in out:
        raise PcapFileException(PcapFileException.ERR_COPY)

    return out


def untar(host, name, dest):
    host.send_expect("tar zxf %s%s -C %s  >/dev/null 2>&1" %
                     (host.dst_dir, name.split('/')[-1], dest), "# ", 20)


def install_epel(host):
    p = host.prompt
    out = host.send_expect("yum repolist", p)
    if "epel" in out:
        return
    host.send_expect("sudo rm epel-release-latest-7*", p)
    out = "1"
    i = 0
    while out != "0" and i < 5:
        if i > 0:
            time.sleep(10)
        host.send_expect("wget -q -t 5 dl.fedoraproject.org/pub/epel/"
                         "epel-release-latest-7.noarch.rpm", p, 100)
        out = host.send_expect("echo $?", p)
        i += 1
    assert (out == "0"), "Cannot download epel repo. Code: {}".format(out)
    host.send_expect("yum install epel-release-latest-7.noarch.rpm -q -y", p)


def install_libpcap(host):
    p = host.prompt
    url = "https://rpmfind.net/linux/centos/7.6.1810/os/x86_64/Packages/"
    libpcap = "libpcap-1.5.3-11.el7.x86_64.rpm"
    libpcap_devel = "libpcap-devel-1.5.3-11.el7.x86_64.rpm"
    host.send_expect("yum install libpcap-devel -q -y", p, timeout=60)
    out = host.send_expect("echo $?", p)
    if "0" in out:
        return
    host.send_expect("yum remove libpcap -q -y", p)
    host.send_expect("wget {}{} -q".format(url, libpcap), p, 60)
    host.send_expect("wget {}{} -q".format(url, libpcap_devel), p, 60)
    host.send_expect("yum install {} -y -q".format(libpcap), p, 60)
    host.send_expect("yum install {} -y -q".format(libpcap_devel), p, 60)
    out = host.send_expect("echo $?", p)
    assert "0" in out, "Cannot install libpcap"


def install_lua(host):
    host.send_expect("pkg-config lua5.3", host.prompt)
    out = host.send_expect("echo $?", host.prompt)
    if "0" in out:
        return
    host.send_expect("mkdir lua_build", host.prompt)
    host.send_expect("cd lua_build", host.prompt)
    host.send_expect("curl -R -O http://www.lua.org/ftp/lua-5.3.5.tar.gz",
                     host.prompt)
    host.send_expect("tar -zxf lua-5.3.5.tar.gz", host.prompt)
    host.send_expect("cd lua-5.3.5", host.prompt)
    host.send_expect("make linux test", host.prompt)
    host.send_expect("make install INSTALL_TOP={}".format(host.install_dir), host.prompt)
    host.send_expect("ln -s {path}/lib/liblua.a {path}/lib64/liblua5.3.a".format(path=host.install_dir), host.prompt)
    host.send_expect("ln -s {path}/x86_64-linux-gnu/liblua5.3.a {path}/x86_64-linux-gnu/liblua.a".format(
                     path=host.install_dir), host.prompt)

    os_type = host.send_expect("uname -a", "# ")
    os_type = os_type.lower()

    host.send_expect('mkdir -p $PKG_CONFIG_PATH', "#")
    pc_file = host.send_expect("echo $PKG_CONFIG_PATH", host.prompt) + "/lua5.3.pc"
    host.send_expect("make pc INSTALL_TOP={} > {}".format(host.install_dir, pc_file), host.prompt)
    host.send_expect("echo 'Name: lua5.3' >> {}".format(pc_file), host.prompt)
    host.send_expect("echo 'Version: ${{version}}' >> {}".format(pc_file), host.prompt)
    host.send_expect("echo 'Description: lua' >> {}".format(pc_file), host.prompt)
    host.send_expect("echo 'Libs: -L${{libdir}} -llua' >> {}".format(pc_file), host.prompt)
    out = host.send_expect("pkg-config --libs-only-l lua5.3", host.prompt)
    assert ("-llua" in out), "Failed to install lua5.3"

def install_patched_vfio(host):
    # Enable source packages to be enabled (required on Ubuntu)
    host.send_expect("sed -i '/^# deb-src.*main/s/^#//' /etc/apt/sources.list", host.prompt)
    host.send_expect("cd {}/enav2-vfio-patch".format(host.base_dir), host.prompt)
    out = host.send_expect("./get-vfio-with-wc.sh", host.prompt, 600, verify=True)
    assert (not isinstance(out, int)), "Failed to install patched vfio-pci module"
    host.send_expect("rm -rf tmp", host.prompt, 10)

def build_igb_uio(host):
    host.send_expect("cd {}/dpdk-kmods/linux/igb_uio".format(host.base_dir), host.prompt)
    out = host.send_expect("make", host.prompt, 30, verify=True)
    assert (not isinstance(out, int)), "Failed to build igb_uio.ko module"
