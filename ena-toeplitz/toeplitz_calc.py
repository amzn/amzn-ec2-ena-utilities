#!/usr/bin/env python3

import sys
import argparse
import re

prog_name = sys.argv[0]
USAGE_EXAMPLE = f"""
Usage example:
    Calculate the Toeplitz hash of a packet sent from 1.2.3.4 to 1.2.3.5 with source/destination
    port of 7000:

    - on an instance that support changing Toeplitz key (only the instance on RX side matters):
      (note that on such instances the key might be randomized by the driver and needs to be
      queried, On Linux the user can use `ethtool -x [interface] command` to fetch it)

    $ {prog_name} -t 1.2.3.4 -T 7000 -r 1.2.3.5 -R 7000 -k 77:d1:c9:34:a4:c9:bd:87:6e:35:dd:17:b2:e3:23:9e:39:6d:8a:93:2a:95:b4:72:3a:b3:7f:56:8e:de:b6:01:97:af:3b:2f:3a:70:e7:04

    - on an instance that doesn't support changing Toeplitz key (only the instance on RX side matters):
      (note that on such instances the key is hardcoded in HW, and cannot be changed so there is
      no need to specify it)

    $ {prog_name} -t 1.2.3.4 -T 7000 -r 1.2.3.5 -R 7000


    Please note that hash function/key configuration is supported by the 5th generation network
    accelerated instances (c5n, m5n, r5n etc) and on some of the 6th generation instances (c6gn, m6i
    etc). Also Linux kernel 5.9 or newer is required for hash function/key configuration support but
    the major Linux distributions ported the driver support to kernels older than v5.9 (For example
    Amazon Linux 2 supports it since kernel 4.14.209).
    You can also manually install GitHub driver v2.2.11g or newer to get this support if your instance
    doesn't come with it by default. The Github driver can be found in https://github.com/amzn/amzn-drivers

    Also the Linux driver older than version 2.6 had a bug in which the hash before changing the RSS key
    for the first time is the different from the one after the RSS key is set explicitly. The script
    prints both versions.

    Please check the appropriate method of configuring RSS for your driver to check whether it supports
    configuring the RSS key.
"""

# The default key on instances where it cannot be changed
# is a manipulated version of Microsoft's RSS key:
# https://docs.microsoft.com/en-us/windows-hardware/drivers/network/verifying-the-rss-hash-calculation
RSS_DEFAULT_KEY = [
	0xbe, 0xac, 0x01, 0xfa, 0x6a, 0x42, 0xb7, 0x3b,
	0x80, 0x30, 0xf2, 0x0c, 0x77, 0xcb, 0x2d, 0xa3,
	0xae, 0x7b, 0x30, 0xb4, 0xd0, 0xca, 0x2b, 0xcb,
	0x43, 0xa3, 0x8f, 0xb0, 0x41, 0x67, 0x25, 0x3d,
	0x25, 0x5b, 0x0e, 0xc2, 0x6d, 0x5a, 0x56, 0xda
]

TOEPLITZ_KEY_SIZE = 128
BITS_IN_BYTE = 8

def circular_shift_key_one_left(key):
    """The function does a cyclic shift left of the whole key.
    To be able to shift the whole 40 bytes left in a cyclic manner, the function
    shifts the bits between two adjacent bytes each time"""

    l = len(key)
    return [ ((key[i] << 1) & 0xff) | ((key[(i + 1) % l] & 0x80) >> 7) for i in range(0, l) ]

def or_32msb_bits_of_key(key):
    return (key[0] << 24) | (key[1] << 16) | (key[2] << 8) | key[3]

def calculate_hash(rx_ip, rx_port, tx_ip, tx_port, initial_value, key):
    """Calculate the Toeplitz hash based on the given parameters. Note that this
    implementation is relevant for ENA, and doesn't claim to be compatible with
    the standard implementation"""

    hash_result = initial_value
    input_bytes = list()
    input_bytes.extend((*tx_ip, *rx_ip, *tx_port, *rx_port))

    for input_byte in input_bytes:
        for i in range(BITS_IN_BYTE):
            # is the (8 - i -1) bit set
            if (input_byte & (1 << (BITS_IN_BYTE - i - 1))):
                hash_result ^= or_32msb_bits_of_key(key)

            key = circular_shift_key_one_left(key)

    return hash_result

def ipv4_addr_type(str):
    """type function to argparse which transforms an
    ipv4 string into its hexadecimal number"""
    if not re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}$", str):
        raise argparse.ArgumentTypeError(f"IP address needs to have the format 1.2.3.4")

    return [int(octet) for octet in str.split('.')]

def toeplitz_key_type(str):
    """type function to argparse which transforms a
    Toeplits key string into an array of hexadecimal values"""
    if not re.match(r"^([0-9a-zA-Z]{1,2}:){39}[0-9a-zA-Z]{1,2}$", str):
        raise argparse.ArgumentTypeError(f"Toeplitz key hash format is invalid (should be 40 hex values delimeted with columns)")

    return [int(key_elem, 16) for key_elem in str.split(':')]

def main():

    parser = argparse.ArgumentParser(description='ENA Toeplitz hash calculator',
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=USAGE_EXAMPLE)

    parser.add_argument('-r', '--rx-ip', help='Receiving side ipv4', dest='rx_ip', nargs='?',
                        required=True, type=ipv4_addr_type)
    parser.add_argument('-R', '--rx-port', help='Receiving side port', dest='rx_port', nargs='?',
                        required=True, type=int)
    parser.add_argument('-t', '--tx-ip', help='Transmitting side ipv4',
                        dest='tx_ip', nargs='?', required=True, type=ipv4_addr_type)
    parser.add_argument('-T', '--tx-port', help='Transmitting side port', dest='tx_port', nargs='?',
                        required=True, type=int)
    parser.add_argument('-k', '--toeplitz-key',
                        help='The Toeplitz key (only in instances that support changing it)',
                        dest='toeplitz_key', nargs='?', type=toeplitz_key_type)

    args = parser.parse_args()

    rx_ip   = args.rx_ip
    tx_ip   = args.tx_ip
    # "break" port number into two byte representation
    rx_port = [(args.rx_port & 0xff00) >> 8, args.rx_port & 0x00ff]
    tx_port = [(args.tx_port & 0xff00) >> 8, args.tx_port & 0x00ff]

    if not args.toeplitz_key:
        initial_value = 0xffffffff
        key           = RSS_DEFAULT_KEY

        # on such instances ignore the direction of the packets and
        # instead refer to the smaller value as the "source ip/port"
        if int.from_bytes(rx_ip, "big") < int.from_bytes(tx_ip, "big"):
            rx_ip, tx_ip = tx_ip, rx_ip

        if int.from_bytes(rx_port, "big") < int.from_bytes(tx_port, "big"):
            rx_port, tx_port = tx_port, rx_port

    else:
        initial_value = 0
        key = args.toeplitz_key

    # calculate the hash with inital value of 0x0xffffffff
    hash = calculate_hash(rx_ip, rx_port, tx_ip, tx_port, initial_value, key)

    if not args.toeplitz_key:
        # instances with default key only use the lower 16 bits
        hash = ((hash & 0xffff) | (hash << 16)) & 0xffffffff

    rss_table_entry = hash % 128

    tx_ip_str = '.'.join([str(byte) for byte in args.tx_ip])
    rx_ip_str = '.'.join([str(byte) for byte in args.rx_ip])
    print(f"Sending traffic from {tx_ip_str}:{args.tx_port} to {rx_ip_str}:{args.rx_port}")

    if not args.toeplitz_key:
        print("to an instance with a default RSS key that cannot be changed\n")
        print("Should result in the hash for all drivers:".ljust(50), f"\t{hex(hash)} (RSS table entry : {rss_table_entry})")
        return

    # -- instances where Toeplitz key can be modified --

    print("to an instance which supports changing the key\n")
    print("Should result in the following hash for each driver:")

    # DPDK and freeBSD drivers follow the standard implementation
    print("DPDK".ljust(50), f"\t{hex(hash)} (RSS table entry: {rss_table_entry})")
    print("FreeBSD".ljust(50), f"\t{hex(hash)} (RSS table entry: {rss_table_entry})")

    # The HW reveses the provided RSS key, and the rest of the drivers don't make
    # up for it by reversing it beforehand
    key.reverse()
    hash = calculate_hash(rx_ip, rx_port, tx_ip, tx_port, initial_value, key)
    rss_table_entry = hash % 128

    # On Linux driver on an instance where the key can change the initial value
    # is 0 instead of 0xffffffff if using *default* RSS key (the one configured
    # automatically). This is relveant to driver versions <= 2.6. Newer Linux
    # driver versions would always have the value listed as 'after setting the
    # key'.
    print("Linux (before setting the key with ethtool)".ljust(50), f"\t{hex(hash)} (RSS table entry: {rss_table_entry})")

    # calculate the Toeplitz hash with initial value of 0x0
    initial_value = 0xffffffff
    hash = calculate_hash(rx_ip, rx_port, tx_ip, tx_port, initial_value, key)
    rss_table_entry = hash % 128

    print("Linux (after setting the key with ethtool)".ljust(50), f"\t{hex(hash)} (RSS table entry: {rss_table_entry})")
    print("Windows".ljust(50), f"\t{hex(hash)} (RSS table entry: {rss_table_entry})")

if __name__ == '__main__':
    main()
