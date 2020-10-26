"""
 Changes made to the original file:
   * Add support for multiple connections per session
   * Add support for SSH key
   * Set prompt as '# ' when starting SSH session/
   * Start SSH session as su
   * Exit from su mode session before logging out
   * Increase timeout of SCP from 2 to 5 minutes
"""

import time
import pexpect
from pexpect import pxssh
from debugger import ignore_keyintr, aware_keyintr
from exception import TimeoutException, SSHConnectionException, SSHSessionDeadException
from utils import RED, GREEN
import settings

"""
Module handle ssh sessions between tester and DUT.
Implement send_expect function to send command and get output data.
Aslo support transfer files to tester or DUT.
"""


class SSHPexpect(object):
    connections = 0
    def __init__(self, host, username, password, ssh_key=None):
        self.magic_prompt = "MAGIC PROMPT"
        try:
            SSHPexpect.connections += 1
            ssh_options = {}
            path = '{}/ssh_{}_{}.log'.format(
                settings.FOLDERS['Output'], host, SSHPexpect.connections)
            self.logfile = open(path, 'w')
            self.session = pxssh.pxssh(logfile=self.logfile)
            self.host = host
            self.username = username
            self.password = password
            self.ssh_key = ssh_key
            if ':' in host:
                self.ip = host.split(':')[0]
                self.port = int(host.split(':')[1])
                self.session.login(self.ip, self.username,
                                   self.password, original_prompt='[$#>]',
                                   port=self.port, login_timeout=20, ssh_key=ssh_key)
            else:
                self.session.login(self.host, self.username,
                                   self.password, original_prompt='[$#>]', ssh_key=ssh_key)
            self.send_expect("PS1='# '", '# ')
            self.send_expect('stty -echo', '# ', timeout=2)
            self.session.sendline("sudo su")
            self.session.expect('#')
            self.send_expect("PS1='# '", '# ')
        except Exception, e:
            print RED(e)
            if getattr(self, 'port', None):
                suggestion = "\nSuggession: Check if the fireware on [ %s ] " % \
                    self.ip + "is stoped\n"
                print GREEN(suggestion)

            raise SSHConnectionException(host)

    def init_log(self, logger, name):
        self.logger = logger
        self.logger.info("ssh %s@%s" % (self.username, self.host))

    def send_expect_base(self, command, expected, timeout):
        ignore_keyintr()
        self.clean_session()
        self.session.PROMPT = expected
        self.__sendline(command)
        self.__prompt(command, timeout)
        aware_keyintr()

        before = self.get_output_before()
        return before

    def send_expect(self, command, expected, timeout=15, verify=False):
        ret = self.send_expect_base(command, expected, timeout)
        if verify:
            ret_status = self.send_expect_base("echo $?", expected, timeout)
            if not int(ret_status):
                return ret
            else:
                self.logger.error("Command: %s failure!" % command)
                self.logger.error(ret)
                return int(ret_status)
        else:
            return ret

    def send_command(self, command, timeout=1):
        ignore_keyintr()
        self.clean_session()
        self.__sendline(command)
        aware_keyintr()
        return self.get_session_before(timeout)

    def clean_session(self):
        self.get_session_before(timeout=0.01)

    def get_session_before(self, timeout=15):
        """
        Get all output before timeout
        """
        ignore_keyintr()
        try:
            self.session.prompt(timeout)
        except Exception as e:
            pass

        aware_keyintr()
        before = self.get_output_before()
        self.__flush()
        return before

    def __flush(self):
        """
        Clear all session buffer
        """
        self.session.buffer = ""
        self.session.before = ""

    def __prompt(self, command, timeout):
        if not self.session.prompt(timeout):
            raise TimeoutException(command, self.get_output_all())

    def __sendline(self, command):
        if not self.isalive():
            raise SSHSessionDeadException(self.host)
        if len(command) == 2 and command.startswith('^'):
            self.session.sendcontrol(command[1])
        else:
            self.session.sendline(command)

    def get_output_before(self):
        if not self.isalive():
            raise SSHSessionDeadException(self.host)
        self.session.flush()
        before = self.session.before.rsplit('\r\n', 1)
        if before[0] == "[PEXPECT]":
            before[0] = ""

        return before[0]

    def get_output_all(self):
        self.session.flush()
        output = self.session.before
        output.replace("[PEXPECT]", "")
        return output

    def close(self, force=False):
        if force is True:
            self.session.close()
        else:
            if self.isalive():
                self.send_expect('exit', '#')
                self.session.logout()

    def isalive(self):
        return self.session.isalive()

    def copy_file_from(self, src, dst=".", password=''):
        """
        Copies a file from a remote place into local.
        """
        key_string = ""
        if self.ssh_key is not None:
            key_string = "-i {}".format(self.ssh_key)
        if ':' in self.host:
            command = 'scp {0} -v -P {1} -o NoHostAuthenticationForLocalhost=yes {2}@{3}:{4} {5}'.format(
                key_string, str(self.port), self.username, self.ip, src, dst)
        else:
            command = 'scp {0} -v {1}@{2}:{3} {4}'.format(key_string, self.username, self.host, src, dst)
        if password == '':
            self._spawn_scp(command, self.password)
        else:
            self._spawn_scp(command, password)

    def copy_file_to(self, src, dst="~/", password=''):
        """
        Sends a local file to a remote place.
        """
        key_string = ""
        if self.ssh_key is not None:
            key_string = "-i {}".format(self.ssh_key)
        if ':' in self.host:
            command = 'scp {0} -v -P {1} -o NoHostAuthenticationForLocalhost=yes {2} {3}@{4}:{5}'.format(
                key_string, str(self.port), src, self.username, self.ip, dst)
        else:
            command = 'scp {0} -v {1} {2}@{3}:{4}'.format(
                key_string, src, self.username, self.host, dst)
        if password == '':
            self._spawn_scp(command, self.password)
        else:
            self._spawn_scp(command, password)

    def _spawn_scp(self, scp_cmd, password):
        """
        Transfer a file with SCP
        """
        self.logger.info(scp_cmd)
        p = pexpect.spawn(scp_cmd)
        time.sleep(0.5)
        ssh_newkey = 'Are you sure you want to continue connecting'
        i = p.expect([ssh_newkey, '[pP]assword', "# ", pexpect.EOF,
                      pexpect.TIMEOUT], 360)
        if i == 0:  # add once in trust list
            p.sendline('yes')
            i = p.expect([ssh_newkey, '[pP]assword', "# ", pexpect.EOF], 2)

        if i == 1:
            time.sleep(0.5)
            p.sendline(password)
            p.expect("Exit status 0", 60)
        if i == 4:
            self.logger.error("SCP TIMEOUT error %d" % i)

        p.close()
