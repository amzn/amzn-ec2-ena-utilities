"""
Static configuration data for any CRBs that can be used.
"""
from settings import IXIA

crbs_desc = {
    'CrownPassCRB1':

    """
    - Intel Grizzly Pass Server Board populated with:

      - 2x Intel Xeon CPU E5-2680 @ 2.7GHz with 64 KB L1 D-cache (per
        physical core), 256 KB L2 D-cache (per physical core) and 25 MB of
        L3 D-cache (shared across physical cores).
      - 8x DDR3 DIMMs @ 1333 MHz of 4GB each. Each of the 4 memory channels of each
        CPU is populated with 2 DIMMs.
      - 4x Intel 82599 (Niantic) NICs (2x 10GbE full duplex optical ports per NIC)
        plugged into the available PCIe Gen2 8-lane slots. To avoid PCIe bandwidth
        bottlenecks at high packet rates, a single optical port from each NIC is
        connected to the traffic  generator.

    - BIOS version R02.01.0002 with the following settings:

      - Intel Turbo Boost Technology [Disabled]
      - Enhanced Intel SpeedStep Technology (EIST) [Disabled]
      - Intel Hyper-Threading Technology  [Enabled]
      - Direct Cache Access [Disabled]

      - Execute DisableBit [Enabled]
      - MLC Streamer [Enabled]
      - MLC Spatial Prefetcher [Disabled]
      - DCU Data Prefetcher [Disabled]
      - DCU Instruction Prefetcher [Enabled]

    - Software configuration:

      - Linux operating system: Fedora 20 64-bit
      - Linux kernel version: 3.6.10
    """
}
