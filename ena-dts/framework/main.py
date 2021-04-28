#!/usr/bin/env python2
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
   * Change execution line to "#!/usr/bin/env python"
   * Remove functions:
     - git_build_package
   * Remove arguments:
     - --git
     - -s
   * Add arguments:
     - -f
     - --BW-sizes
     - --BW-flows
     - --BW-types
     - --BW-queue
     - --BW-interval
     - --BW-measurements
     - --BW-direction
     - --BW-pcap-tester
     - --BW-no-tx-flow
     - --BW-port-min
     - --BW-port-max
     - --BW-target-gbps
     - --stress-cpu-inst
     - --stress-vm-inst
     - --stress-vm-size
     - --skip-target-env-setup
     - --try-reuse-pcaps
   * Add default test cases
   * Pass test configuration to the dts
"""

"""
A test framework for testing DPDK.
"""

import os
import sys
import argparse

# change operation directory
os.chdir("../")
cwd = os.getcwd()
sys.path.append(cwd + '/nics')
sys.path.append(cwd + '/framework')
#sys.path.append(cwd + '/tests') # suites module path should be loaded in dts/run_all, not here
sys.path.append(cwd + '/dep')

import dts

# Read cmd-line args
parser = argparse.ArgumentParser(description='DPDK test framework.')

parser.add_argument('--config-file',
                    default='execution.cfg',
                    help='configuration file that describes the test ' +
                    'cases, DUTs and targets')

parser.add_argument('--patch',
                    action='append',
                    help='apply a patch to the package under test')

parser.add_argument('--snapshot',
                    default='dep/dpdk.tar.gz',
                    help='snapshot .tgz file to use as input')

parser.add_argument('--pktgen',
                    default='dep/pktgen.tar.gz',
                    help='pktgen .tgz file to use as input')

parser.add_argument('--output',
                    default='',
                    help='Output directory where dts log and result saved')

parser.add_argument('-f', '--force-setup',
                    action='store_true',
                    help='force all possible setup steps done on both DUT' +
                    ' and tester boards.')

parser.add_argument('-r', '--read-cache',
                    action='store_true',
                    help='reads the DUT configuration from a cache. If not ' +
                    'specified, the DUT configuration will be calculated ' +
                    'as usual and cached.')

parser.add_argument('-p', '--project',
                    default='dpdk',
                    help='specify that which project will be tested')

parser.add_argument('--suite-dir',
                    default='tests',
                    help='Test suite directory where test suites will be imported')

parser.add_argument('-t', '--test-cases',
                    nargs="*",
                    default=['test_perf_bw', 'test_perf_latency'],
                    help='executes only the followings test cases')

parser.add_argument('-d', '--dir',
                    default='~/dpdk',
                    help='Output directory where dpdk package is extracted')

parser.add_argument('-v', '--verbose',
                    action='store_true',
                    help='enable verbose output, all message output on screen')

parser.add_argument('--virttype',
                    default='kvm',
                    help='set virt type,support kvm, libvirtd')

parser.add_argument('--debug',
                    action='store_true',
                    help='enable debug mode, user can enter debug mode in process')

parser.add_argument('--debugcase',
                    action='store_true',
                    help='enable debug mode in the first case, user can further debug')
parser.add_argument('--re_run',
                    default=0,
                    help='when case failed will re-run times, and this value must >= 0')

parser.add_argument('--commands',
                    action='append',
                    help='run command on tester or dut. The command format is ' +
                    '[commands]:dut|tester:pre-init|post-init:check|ignore')

parser.add_argument('--BW-sizes',
                    default="1500,9000",
                    help='configure list of sizes of packets in BW test. '
                         'The command format is n[,n] where n is packet size')

parser.add_argument('--BW-flows',
                    default="AUTO",
                    help='configure number of flows in BW test. The command format '
                         'is n[,n] where n is number of flows in each run')

parser.add_argument('--BW-types',
                    default="TCP,UDP",
                    help='configure types of packets in BW test. The command format '
                         'is t[,t] where t is packet type (TCP or UDP).')

parser.add_argument('--BW-queue',
                    default="AUTO",
                    help='Number of queue to use. '
                         'min(cpu-2, BW-queue) queues will be started.')

parser.add_argument('--BW-interval',
                    default="5",
                    help='Interval between measurements in seconds.')

parser.add_argument('--BW-measurements',
                    default="6",
                    help='Number of measurements.')

parser.add_argument('--BW-direction',
                    default="mono",
                    help='Direction: mono or bi.')

parser.add_argument('--BW-pcap-tester',
                    default=None,
                    help='Absolute path to pcap file for tester.')

parser.add_argument('--BW-no-tx-flow',
                    action='store_true',
                    help='Do not match flow to TX queue')

parser.add_argument('--BW-port-min',
                    default="8000",
                    help='Minimum TCP/UDP port used for creating a flow.')

parser.add_argument('--BW-port-max',
                    default="9000",
                    help='Maximum TCP/UDP port used for creating a flow.')

parser.add_argument('--BW-target-gbps',
                    default="0",
                    help='Gbps limit for the instance. The closest it\'s to a'
                    'real value, the better performance and stability could be'
                    'achieved. 0 value means autodetection, depending on'
                    'instance type.')

parser.add_argument('--stress-cpu-inst',
                    default="AUTO",
                    help='Number of workers spinning on sqrt().')

parser.add_argument('--stress-vm-inst',
                    default="AUTO",
                    help='Number of workers spinning on malloc()/free().')

parser.add_argument('--stress-vm-size',
                    default="AUTO",
                    help='Per VM instance malloc size.')

parser.add_argument('--skip-target-env-setup',
                    action='store_true',
                    help='Skip repository correctness checking, dependencies'
                    'installation, DPDK (and its apps) build, hugepages setup'
                    'and modules load. Skip interfaces and modules restoring'
                    'at the end. Development option.')

parser.add_argument('--try-reuse-pcaps',
                    action='store_true',
                    help='Try to reuse existing pcap files generated in'
                    'previous runs. Will succeed only if these pcap files'
                    'match exactly requested configuration: direction, number'
                    'of flows, traffic type and size of packets.')

args = parser.parse_args()


test_configs = {"BW_size": args.BW_sizes,
                "BW_flows": args.BW_flows,
                "BW_types": args.BW_types,
                "BW_queue": args.BW_queue,
                "BW_interval": args.BW_interval,
                "BW_measurements": args.BW_measurements,
                "BW_direction": args.BW_direction,
                "BW_pcap_tester": args.BW_pcap_tester,
                "BW_tx_flow": not args.BW_no_tx_flow,
                "BW_port_min": args.BW_port_min,
                "BW_port_max": args.BW_port_max,
                "BW_target_gbps": args.BW_target_gbps,
                "stress_cpu_inst": args.stress_cpu_inst,
                "stress_vm_inst": args.stress_vm_inst,
                "stress_vm_size": args.stress_vm_size,
                "skip_target_env_setup": args.skip_target_env_setup,
                "try_reuse_pcaps": args.try_reuse_pcaps and \
                        "test_perf_bw" in args.test_cases,
                }

# Main program begins here
dts.run_all(args.config_file, args.snapshot,
            args.patch, args.force_setup, args.read_cache,
            args.project, args.suite_dir, args.test_cases,
            args.dir, args.output, args.verbose,args.virttype,
            args.debug, args.debugcase, args.re_run, args.commands,
            args.pktgen, test_configs)
