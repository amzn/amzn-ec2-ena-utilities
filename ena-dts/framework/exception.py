"""
 Changes made to the original file:
   * Add FlowDetectionException
   * Add PcapFileException
"""

"""
User-defined exceptions used across the framework.
"""


class TimeoutException(Exception):

    """
    Command execution timeout.
    """

    def __init__(self, command, output):
        self.command = command
        self.output = output

    def __str__(self):
        msg = 'TIMEOUT on %s' % (self.command)
        return msg

    def get_output(self):
        return self.output


class VerifyFailure(Exception):

    """
    To be used within the test cases to verify if a command output
    is as it was expected.
    """

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class SSHConnectionException(Exception):

    """
    SSH connection error.
    """

    def __init__(self, host):
        self.host = host

    def __str__(self):
        return 'Error trying to connect with %s' % self.host


class SSHSessionDeadException(Exception):

    """
    SSH session is not alive.
    It can no longer be used.
    """

    def __init__(self, host):
        self.host = host

    def __str__(self):
        return 'SSH session with %s has been dead' % self.host


class ParameterInvalidException(Exception):
    pass

class StartVMFailedException(Exception):

    """
    Start VM failed.
    """

    def __init__(self, error):
        self.error = error

    def __str__(self):
        return repr(self.error)


class ConfigParseException(Exception):

    """
    Configuration file parse failure exception.
    """

    def __init__(self, conf_file):
        self.config = conf_file

    def __str__(self):
        return "Faile to parse config file [%s]" % (self.config)


class VirtConfigParseException(Exception):
    pass


class PortConfigParseException(Exception):
    pass


class VirtConfigParamException(Exception):

    """
    Virtualizatoin param execution exception.
    """
    def __init__(self, param):
        self.param = param

    def __str__(self):
        return "Faile to execute param [%s]" % (self.param)


class VirtDutConnectException(Exception):
    pass


class VirtConfigParamException(Exception):

    """
    Virtualizatoin param execution exception.
    """
    def __init__(self, param):
        self.param = param

    def __str__(self):
        return "Faile to execute param [%s]" % (self.param)


class VirtDutConnectException(Exception):
    pass


class VirtDutInitException(Exception):
    def __init__(self, vm_dut):
        self.vm_dut = vm_dut

class VirtDeviceCreateException(Exception):
    pass

class VirtVmOperationException(Exception):
    pass

class VirtHostPrepareException(Exception):
    pass

class FlowDetectionException(Exception):
    ZERO_HITS = -1
    MULTIPLE_HITS = -2

    def __init__(self, _state):
        self.state = _state

class PcapFileException(Exception):
    ERR_UNDEF = -1
    ERR_PARAM = -2
    ERR_PATH = -3
    ERR_COPY = -4

    err_tbl = {
            ERR_UNDEF: "Undefined problem with pcap file: {}",
            ERR_PARAM: "Missing --BW_pcap_tester=<PCAP_FILE_PATH>",
            ERR_PATH: "Wrong path: '{}'. Check value of the --BW-pcap-tester parameter",
            ERR_COPY: "Pcap file '{}' was not successfully copied",
        }
    def __init__(self, e=None, _fnm=''):
        if e not in self.err_tbl.keys():
            e = -1
        self.msg = self.err_tbl.get(e).format(_fnm)
    def __str__(self):
        return self.msg

