#this structure will be used to determine which parts of tests should be skipped
"""
Dict used to skip parts of tests if NIC is known not to support them
"""
DRIVER_TEST_LACK_CAPA = {
	'sctp_tx_offload' : ['thunder-nicvf', 'fm10k']
}


