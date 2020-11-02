Introduction
============

This test suite is designed to demonstrate
AWS ENA networking device capabilities with DPDK driver.
It is based on the DPDK Test Suite (dts).

Prerequisites for testing:

 * Two machines DUT (Device Under Test) and Tester are used for traffic generation:
     * Each needs to have two network interfaces - one for management and second for testing.
     * Each needs to have at least 4 cores.
     * Script should be able to perform `sudo` command without giving password.
 * Host machine for executing dts:
     * Exchange of the SSH keys with DUT and Tester to allow ssh access without password.

Below applications must be installed on host:

 * git
 * python 2.7
 * numpy
 * pexpect
 * xlrd
 * xlwt
 * patch

Network architecture
====================

Example setup that can be used for executing:

```
             _________                                         __________
            |         |ena1                               ethY|          |
            |   DUT   |(DUT_INTERNAL_IP)  (TESTER_INTERNAL_IP)|  TESTER  |
            |         |<------------------------------------->|          |
            |_________|                                       |__________|
                 ^ ethZ                                            ^ ethX
                 | (DUT_IP)                                        | (TESTER_IP)
                 |                                                 |
                 |                                                 |
                 |                                                 |
             ___________________________________________________________
            |                                                           |
            |                           HOST                            |
            |                                                           |
            |___________________________________________________________|

```

The DUT (Device Under Test) and Tester machines are used for testing ENA DPDK driver.
They should have two interfaces to do not lose communication with host while running tests.
It is important to use different ports for management and tests, because when the interfaces
is bounded to the DPDK, it is not available to the Linux.

The HOST is the local machine from which the tests are being executed and managed.

Test suite architecture
=======================

Tests are based on DPDK Test Suite. Core scripts are located in `framework`.
Tests are implemented in `tests` directory.
Configuration is located in `execution.cfg` and in `conf` directory (on `HOST`).

Before executing test scenario, script check if setup is configured.
If not the DPDK and Pktgen will be downloaded to `dep` directory, patched and
copied to DUT and Tester. Then it will be compiled. Setup installation could be forced
with `-f` parameter.

Tests results are stored in `out` directory. Its content is overwritten during every run.
Test case report is stored in `output/rst_report/x86_64-native-linuxapp-gcc/ena/TestResult_ENA.rst`.
In the file `ssh_ip_*.log` all commands sent to the DUT and the Tester via ssh with their
outputs are being stored.

Configuration files
===================
Setup configuration is placed in three files. Example configuration with comments is presented below.

conf/crbs.cfg
-------------
Configuration parameters necessary to access DUT and Tester from Host:

```
# Setup name provided in the execution.cfg.
[setup_name]
# DUT IP address on the ethZ interface, achievable from the current host.
# It will be used for the SSH connection.
dut_ip=xxx.xxx.xxx.xxx
# DUT user name used for the SSH connection:
dut_user=<ec2-user or ubuntu>
# Absolute path to the SSH key for the DUT.
dut_ssh_key=<absolute path to the key>
# OS type used for testing (currently only the Linux is supported).
os=linux
# Tester IP address on the ethX interface, achievable from the current host.
# It will be used for the SSH connection:
tester_ip=xxx.xxx.xxx.xxx
# tester user name used for ssh connection:
tester_user=<ec2-user or ubuntu>
# Absolute path to the SSH key for the DUT.
tester_ssh_key==<absolute path to the key>
# Number of memory channels for the DPDK EAL:
channels=2
# Make the DPDK skip the first core.
# If True, the core0 will not be used for traffic generation.
bypass_core0=True
```

conf/ports.cfg
--------------
Configuration of ports used for tests.

```
# Setup name provided in execution.cfg:
[setup_name]
# Configuration of ports used for tests.
# Different AWS instances would have different device assignment.
# For r4/i3 instances:
ports =
    pci=0000:00:04.0,peer=0000:00:04.0;
# For c5/r5/m5 instances:
# ports =
#   pci=0000:00:06.0,peer=0000:00:06.0;
# If needed, the static IPs could be provided:
# ports =
#    pci=0000:00:06.0,peer=0000:00:06.0,ip=10.0.0.2,peer_ip=10.0.0.1;
```

Please check the configuration before executing the tests.

MAC and IP addresses of interfaces are taken from output of the `ifconfig` command.

execution.cfg
-------------
This file configures DTS execution.
It provides links to repositories, tags to checkout and set of patches to apply.

`crbs` parameter should match setup_name from `conf/crbs.cfg` and `conf/ports.cfg`:

```
# Name of setup configuration:
crbs=setup_name
```

Description of other section is provided as a comments in `execution.cfg`.

Usage
=====

To execute tests enter dts directory on `HOST` and type:

```
./dts [-f] [-t tests_to_run]
```

All parameters are optional:

 * `-f` force re-installation of setup.
 * `-t` execute list of test cases. If not provided all tests form ENA_test_suite will be executed.

If not forced by `-f` parameter, before running tests DTS check if setup is needed.

DPDK and Pktgen repositories are cloned from location provided in configuration and
checked out to provided branch. Then patches from configuration list are applied.

After that repositories are compressed to tar.gz archive and copied via scp to Tester and DUT
where they are compiled.

After setup, selected tests are executed. Logs and results are
stored in `outputs` folder. Test report in human readable format is located in:
 `output/rst_report/x86_64-native-linuxapp-gcc/ena/TestResult_ENA.rst`.

For debugging purpose outputs of all commands are located in `output/ssh_*` files.

Tests
=====

test_perf_bw
------------

Check performance for different packet sizes, number of flows and protocols (udp, tcp).
For each case scapy generates pcap file with packets.
Then pktgen is executed on both DUT and Tester.

Command:

```
./dts -t test_perf_bw
```

runs BW test case with default configuration. It could by adjusted by adding
command line parameters:

```
./dts -t test_perf_bw --BW-flows 1,8 --BW-sizes 1500,9000 --BW-types TCP,UDP --BW-queue 1 --BW-direction bi
```

where:
  * `--BW-flows` list of number of flows,
  * `--BW-sizes` list of packet sizes,
  * `--BW-types` list of packet types,
  * `--BW-queue` suggested number of used queues, min(cpu_cores-2, BW-queue) queues will be started.
  * `--BW-direction` mono - use simplex, bi - use duplex.

Sample test output (c5n.18xlarge <-> c5n.18xlarge, same AZ, non-same placement group):

`./dts -t test_perf_bw --BW-flows 1,8,32 --BW-sizes 1500,9000 --BW-types TCP,UDP --BW-queue 32 --BW-direction bi`:

```
+----------------+------+-------+------------------------+------+-----------------+--------------------+----------------+-------------------+
| direction      | size | flows | Tx queues DUT / Tester | type | Rx on DUT, Mb/s | Rx on Tester, Mb/s | Rx on DUT, pps | Rx on Tester, pps |
+================+======+=======+========================+======+=================+====================+================+===================+
| Tester <=> DUT | 1500 | 1     | 1 / 1                  | tcp  | 3406            | 3384               | 280111         | 278333            |
+----------------+------+-------+------------------------+------+-----------------+--------------------+----------------+-------------------+
| Tester <=> DUT | 1500 | 1     | 1 / 1                  | udp  | 3403            | 3503               | 279922         | 288126            |
+----------------+------+-------+------------------------+------+-----------------+--------------------+----------------+-------------------+
| Tester <=> DUT | 1500 | 8     | 8 / 8                  | tcp  | 7730            | 7792               | 635702         | 640843            |
+----------------+------+-------+------------------------+------+-----------------+--------------------+----------------+-------------------+
| Tester <=> DUT | 1500 | 8     | 8 / 8                  | udp  | 27230           | 28642              | 2239356        | 2355461           |
+----------------+------+-------+------------------------+------+-----------------+--------------------+----------------+-------------------+
| Tester <=> DUT | 1500 | 32    | 32 / 32                | tcp  | 8173            | 8138               | 672197         | 669262            |
+----------------+------+-------+------------------------+------+-----------------+--------------------+----------------+-------------------+
| Tester <=> DUT | 1500 | 32    | 32 / 32                | udp  | 44882           | 46415              | 3691003        | 3817026           |
+----------------+------+-------+------------------------+------+-----------------+--------------------+----------------+-------------------+
| Tester <=> DUT | 9000 | 1     | 1 / 1                  | tcp  | 3400            | 3477               | 47125          | 48197             |
+----------------+------+-------+------------------------+------+-----------------+--------------------+----------------+-------------------+
| Tester <=> DUT | 9000 | 1     | 1 / 1                  | udp  | 3412            | 3486               | 47285          | 48314             |
+----------------+------+-------+------------------------+------+-----------------+--------------------+----------------+-------------------+
| Tester <=> DUT | 9000 | 8     | 8 / 8                  | tcp  | 27249           | 28383              | 377628         | 393345            |
+----------------+------+-------+------------------------+------+-----------------+--------------------+----------------+-------------------+
| Tester <=> DUT | 9000 | 8     | 8 / 8                  | udp  | 27436           | 28291              | 380217         | 392067            |
+----------------+------+-------+------------------------+------+-----------------+--------------------+----------------+-------------------+
| Tester <=> DUT | 9000 | 32    | 32 / 32                | tcp  | 48522           | 48519              | 672428         | 672386            |
+----------------+------+-------+------------------------+------+-----------------+--------------------+----------------+-------------------+
| Tester <=> DUT | 9000 | 32    | 32 / 32                | udp  | 81417           | 92100              | 1128294        | 1276339           |
+----------------+------+-------+------------------------+------+-----------------+--------------------+----------------+-------------------+
```

test_perf_latency
-----------------

Measures packet latency. On DUT DPDK application receives ICMP requests and sends responses.
Second DPDK application sends ping requests from Tester and measures time between sending and receiving.
100000 packets are being send. From measurements p50 and p90 and p99 are being calculated.
Test is being run for 3 packet sizes: 64, 1500 and 9000. If any ping packet is lost, test is marked as failed.

Sample test output(c5n.18xlarge <-> c5n.18xlarge, same AZ, non-same placement group):

```
+------+---------+---------+---------+-------------+
| size | p50, us | p90, us | p99, us | pkt loss, % |
+======+=========+=========+=========+=============+
| 64   | 33      | 34      | 37      | 0           |
+------+---------+---------+---------+-------------+
| 1500 | 38      | 39      | 44      | 0           |
+------+---------+---------+---------+-------------+
| 9000 | 56      | 58      | 62      | 0           |
+------+---------+---------+---------+-------------+
```

Test applications are located in `dep/latency`.

test_perf_pcap
------------

Sends pcap from Tester to DUT and provides bandwidth statistics.

Command:

```
./dts -t test_perf_pcap --BW-pcap-tester /absolute/path/to/ena_test.pcap
```

runs pcap test case with default configuration. It could by adjusted by adding
command line parameters:

  * `--BW-queue` suggested number of used queues, min(cpu_cores-3, BW-queue) queues will be started,
  * `--BW-interval` time between measurements,
  * `--BW-measurements` number of measurements.

Test output has the same format as `test_perf_bw`.

Additional notes
================
Tested on c5.2xlarge and c5.18xlarge, c5n.18xlarge instances with Amazon Linux
and Ubuntu.

As the test suite have to install the the DPDK libraries (and possibly overwrite
the currently installed libs) starting from the DPDK v20.05 because of the
meson build system requirements, it may be possible that there will be
linking errors if other, possible newer, DPDK was alredy installed.
To fix that, it may be required to manually remove other DPDK libraries
(especially there may be conflicts with DPDK v20.05 if v20.08 was already
installed).

DTS documentation: http://dpdk.org/doc/dts/gsg/
