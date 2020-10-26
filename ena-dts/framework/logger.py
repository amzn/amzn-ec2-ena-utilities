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

import logging
import os
import sys
import inspect
import re

from settings import LOG_NAME_SEP, FOLDERS
from utils import RED

"""
DTS logger module with several log level. DTS framwork and TestSuite log
will saved into different log files.
"""
verbose = False

logging.DTS_DUT_CMD = logging.INFO + 1
logging.DTS_DUT_OUTPUT = logging.DEBUG + 1
logging.DTS_DUT_RESULT = logging.WARNING + 1

logging.DTS_TESTER_CMD = logging.INFO + 2
logging.DTS_TESTER_OUTPUT = logging.DEBUG + 2
logging.DTS_TESTER_RESULT = logging.WARNING + 2

logging.SUITE_DUT_CMD = logging.INFO + 3
logging.SUITE_DUT_OUTPUT = logging.DEBUG + 3

logging.SUITE_TESTER_CMD = logging.INFO + 4
logging.SUITE_TESTER_OUTPUT = logging.DEBUG + 4

logging.DTS_IXIA_CMD = logging.INFO + 5
logging.DTS_IXIA_OUTPUT = logging.DEBUG + 5

logging.DTS_VIRTDUT_CMD = logging.INFO + 6
logging.DTS_VIRTDUT_OUTPUT = logging.DEBUG + 6

logging.addLevelName(logging.DTS_DUT_CMD, 'DTS_DUT_CMD')
logging.addLevelName(logging.DTS_DUT_OUTPUT, 'DTS_DUT_OUTPUT')
logging.addLevelName(logging.DTS_DUT_RESULT, 'DTS_DUT_RESULT')

logging.addLevelName(logging.DTS_TESTER_CMD, 'DTS_TESTER_CMD')
logging.addLevelName(logging.DTS_TESTER_OUTPUT, 'DTS_TESTER_OUTPUT')
logging.addLevelName(logging.DTS_TESTER_RESULT, 'DTS_TESTER_RESULT')

logging.addLevelName(logging.DTS_IXIA_CMD, 'DTS_IXIA_CMD')
logging.addLevelName(logging.DTS_IXIA_OUTPUT, 'DTS_IXIA_OUTPUT')

logging.addLevelName(logging.DTS_VIRTDUT_CMD, 'VIRTDUT_CMD')
logging.addLevelName(logging.DTS_VIRTDUT_OUTPUT, 'VIRTDUT_OUTPUT')

logging.addLevelName(logging.SUITE_DUT_CMD, 'SUITE_DUT_CMD')
logging.addLevelName(logging.SUITE_DUT_OUTPUT, 'SUITE_DUT_OUTPUT')

logging.addLevelName(logging.SUITE_TESTER_CMD, 'SUITE_TESTER_CMD')
logging.addLevelName(logging.SUITE_TESTER_OUTPUT, 'SUITE_TESTER_OUTPUT')

logging.addLevelName(logging.DTS_IXIA_CMD, 'DTS_IXIA_CMD')
logging.addLevelName(logging.DTS_IXIA_OUTPUT, 'DTS_IXIA_OUTPUT')

message_fmt = '%(asctime)s %(levelname)20s: %(message)s'
date_fmt = '%d/%m/%Y %H:%M:%S'
RESET_COLOR = '\033[0m'
stream_fmt = '%(color)s%(levelname)20s: %(message)s' + RESET_COLOR
log_dir = None


def set_verbose():
    global verbose
    verbose = True


def add_salt(salt, msg):
    if not salt:
        return msg
    else:
        return '[%s] ' % salt + str(msg)


class BaseLoggerAdapter(logging.LoggerAdapter):
    """
    Upper layer of original logging module.
    """

    def dts_dut_cmd(self, msg, *args, **kwargs):
        self.log(logging.DTS_DUT_CMD, msg, *args, **kwargs)

    def dts_dut_output(self, msg, *args, **kwargs):
        self.log(logging.DTS_DUT_OUTPUT, msg, *args, **kwargs)

    def dts_dut_result(self, msg, *args, **kwargs):
        self.log(logging.DTS_DUT_RESULT, msg, *args, **kwargs)

    def dts_tester_cmd(self, msg, *args, **kwargs):
        self.log(logging.DTS_TESTER_CMD, msg, *args, **kwargs)

    def dts_tester_output(self, msg, *args, **kwargs):
        self.log(logging.DTS_TESTER_CMD, msg, *args, **kwargs)

    def dts_tester_result(self, msg, *args, **kwargs):
        self.log(logging.DTS_TESTER_RESULT, msg, *args, **kwargs)

    def suite_dut_cmd(self, msg, *args, **kwargs):
        self.log(logging.SUITE_DUT_CMD, msg, *args, **kwargs)

    def suite_dut_output(self, msg, *args, **kwargs):
        self.log(logging.SUITE_DUT_OUTPUT, msg, *args, **kwargs)

    def suite_tester_cmd(self, msg, *args, **kwargs):
        self.log(logging.SUITE_TESTER_CMD, msg, *args, **kwargs)

    def suite_tester_output(self, msg, *args, **kwargs):
        self.log(logging.SUITE_TESTER_OUTPUT, msg, *args, **kwargs)

    def dts_ixia_cmd(self, msg, *args, **kwargs):
        self.log(logging.DTS_IXIA_CMD, msg, *args, **kwargs)

    def dts_ixia_output(self, msg, *args, **kwargs):
        self.log(logging.DTS_IXIA_OUTPUT, msg, *args, **kwargs)

    def dts_virtdut_cmd(self, msg, *args, **kwargs):
        self.log(logging.DTS_VIRTDUT_CMD, msg, *args, **kwargs)

    def dts_virtdut_output(self, msg, *args, **kwargs):
        self.log(logging.DTS_VIRTDUT_OUTPUT, msg, *args, **kwargs)


class ColorHandler(logging.StreamHandler):
    """
    Color of DTS log format.
    """
    LEVEL_COLORS = {
        logging.DEBUG: '',  # SYSTEM
        logging.DTS_DUT_OUTPUT: '\033[00;37m',  # WHITE
        logging.DTS_TESTER_OUTPUT: '\033[00;37m',  # WHITE
        logging.SUITE_DUT_OUTPUT: '\033[00;37m',  # WHITE
        logging.SUITE_TESTER_OUTPUT: '\033[00;37m',  # WHITE
        logging.INFO: '\033[00;36m',  # CYAN
        logging.DTS_DUT_CMD: '',  # SYSTEM
        logging.DTS_TESTER_CMD: '',  # SYSTEM
        logging.SUITE_DUT_CMD: '',  # SYSTEM
        logging.SUITE_TESTER_CMD: '',  # SYSTEM
        logging.DTS_IXIA_CMD: '',  # SYSTEM
        logging.DTS_IXIA_OUTPUT: '',  # SYSTEM
        logging.DTS_VIRTDUT_CMD: '',  # SYSTEM
        logging.DTS_VIRTDUT_OUTPUT: '',  # SYSTEM
        logging.WARN: '\033[01;33m',  # BOLD YELLOW
        logging.DTS_DUT_RESULT: '\033[01;34m',  # BOLD BLUE
        logging.DTS_TESTER_RESULT: '\033[01;34m',  # BOLD BLUE
        logging.ERROR: '\033[01;31m',  # BOLD RED
        logging.CRITICAL: '\033[01;31m',  # BOLD RED
    }

    def format(self, record):
        record.__dict__['color'] = self.LEVEL_COLORS[record.levelno]
        return logging.StreamHandler.format(self, record)


class DTSLOG(BaseLoggerAdapter):
    """
    DTS log class for framework and testsuite.
    """

    def __init__(self, logger, crb="suite"):
        global log_dir
        filename = inspect.stack()[1][1][:-3]
        self.name = filename.split('/')[-1]

        self.error_lvl = logging.ERROR
        self.warn_lvl = logging.WARNING
        self.info_lvl = logging.INFO
        self.debug_lvl = logging.DEBUG

        if log_dir is None:
            self.log_path = os.getcwd() + "/../" + FOLDERS['Output']
        else:
            self.log_path = log_dir    # log dir should contain tag/crb global value and mod in dts
        self.dts_log = "dts.log"

        self.logger = logger
        self.logger.setLevel(logging.DEBUG)

        self.crb = crb
        super(DTSLOG, self).__init__(self.logger, dict(crb=self.crb))

        self.salt = ''

        self.fh = None
        self.ch = None

        # add default log file
        fh = logging.FileHandler(self.log_path + "/" + self.dts_log)
        ch = ColorHandler()
        self.__log_handler(fh, ch)

    def __log_handler(self, fh, ch):
        """
        Config stream handler and file handler.
        """
        fh.setFormatter(logging.Formatter(message_fmt, date_fmt))
        ch.setFormatter(logging.Formatter(stream_fmt, date_fmt))

        fh.setLevel(logging.DEBUG)   # file hander default level
        global verbose
        if verbose is True:
            ch.setLevel(logging.DEBUG)
        else:
            ch.setLevel(logging.INFO)   # console handler default level

        self.logger.addHandler(fh)
        self.logger.addHandler(ch)

        if self.fh is not None:
            self.logger.removeHandler(self.fh)
        if self.ch is not None:
            self.logger.removeHandler(self.ch)

        self.fh = fh
        self.ch = ch

    def warning(self, message):
        """
        DTS warnning level log function.
        """
        message = add_salt(self.salt, message)
        self.logger.log(self.warn_lvl, message)

    def info(self, message):
        """
        DTS information level log function.
        """
        message = add_salt(self.salt, message)
        self.logger.log(self.info_lvl, message)

    def error(self, message):
        """
        DTS error level log function.
        """
        message = add_salt(self.salt, message)
        self.logger.log(self.error_lvl, message)

    def debug(self, message):
        """
        DTS debug level log function.
        """
        message = add_salt(self.salt, message)
        self.logger.log(self.debug_lvl, message)

    def set_logfile_path(self, path):
        """
        Configure the log file path.
        """
        self.log_path = path

    def set_stream_level(self, lvl):
        """
        Configure the stream level, logger level >= stream level will be
        output on the screen.
        """
        self.ch.setLevel(lvl)

    def set_logfile_level(self, lvl):
        """
        Configure the file handler level, logger level >= logfile level will
        be saved into log file.
        """
        self.fh.setLevel(lvl)

    def config_execution(self, crb):
        """
        Reconfigure stream&logfile level and reset info,debug,warn level.
        """
        log_file = self.log_path + '/' + self.dts_log
        fh = logging.FileHandler(log_file)
        ch = ColorHandler()
        self.__log_handler(fh, ch)

        def set_salt(crb, start_flag):
            if LOG_NAME_SEP in crb:
                old = '%s%s' % (start_flag, LOG_NAME_SEP)
                if not self.salt:
                    self.salt = crb.replace(old, '', 1)

        if crb.startswith('dut'):
            self.info_lvl = logging.DTS_DUT_CMD
            self.debug_lvl = logging.DTS_DUT_OUTPUT
            self.warn_lvl = logging.DTS_DUT_RESULT

            set_salt(crb, 'dut')
        elif crb.startswith('tester'):
            self.info_lvl = logging.DTS_TESTER_CMD
            self.debug_lvl = logging.DTS_TESTER_OUTPUT
            self.warn_lvl = logging.DTS_TESTER_RESULT

            set_salt(crb, 'tester')
        elif crb.startswith('ixia'):
            self.info_lvl = logging.DTS_IXIA_CMD
            self.debug_lvl = logging.DTS_IXIA_OUTPUT

            set_salt(crb, 'ixia')
        elif crb.startswith('virtdut'):
            self.info_lvl = logging.DTS_VIRTDUT_CMD
            self.debug_lvl = logging.DTS_VIRTDUT_OUTPUT

            set_salt(crb, 'virtdut')
        else:
            self.error_lvl = logging.ERROR
            self.warn_lvl = logging.WARNING
            self.info_lvl = logging.INFO
            self.debug_lvl = logging.DEBUG

    def config_suite(self, suitename, crb=None):
        """
        Reconfigure stream&logfile level and reset info,debug level.
        """
        log_file = self.log_path + '/' + suitename + '.log'
        fh = logging.FileHandler(log_file)
        ch = ColorHandler()

        # exit first
        self.logger_exit()

        # then add handler
        self.__log_handler(fh, ch)

        if crb == 'dut':
            self.info_lvl = logging.SUITE_DUT_CMD
            self.debug_lvl = logging.SUITE_DUT_OUTPUT
        elif crb == 'tester':
            self.info_lvl = logging.SUITE_TESTER_CMD
            self.debug_lvl = logging.SUITE_TESTER_OUTPUT
        elif crb == 'ixia':
            self.info_lvl = logging.DTS_IXIA_CMD
            self.debug_lvl = logging.DTS_IXIA_OUTPUT
        elif crb == 'virtdut':
            self.info_lvl = logging.DTS_VIRTDUT_CMD
            self.debug_lvl = logging.DTS_VIRTDUT_OUTPUT

    def logger_exit(self):
        """
        Remove stream handler and logfile handler.
        """
        if self.fh is not None:
            self.logger.removeHandler(self.fh)
        if self.ch is not None:
            self.logger.removeHandler(self.ch)


def getLogger(name, crb="suite"):
    """
    Get logger handler and if there's no handler for specified CRB will create one.
    """
    logger = DTSLOG(logging.getLogger(name), crb)
    return logger


_TESTSUITE_NAME_FORMAT_PATTERN = r'TEST SUITE : (.*)'
_TESTSUITE_ENDED_FORMAT_PATTERN = r'TEST SUITE ENDED: (.*)'
_TESTCASE_NAME_FORMAT_PATTERN = r'Test Case (.*) Begin'
_TESTCASE_RESULT_FORMAT_PATTERN = r'Test Case (.*) Result (.*):'


class LogParser(object):
    """
    Module for parsing saved log file, will implement later.
    """

    def __init__(self, log_path):
        self.log_path = log_path

        try:
            self.log_handler = open(self.log_path, 'r')
        except:
            print RED("Failed to logfile %s" % log_path)
            return None

        self.suite_pattern = re.compile(_TESTSUITE_NAME_FORMAT_PATTERN)
        self.end_pattern = re.compile(_TESTSUITE_ENDED_FORMAT_PATTERN)
        self.case_pattern = re.compile(_TESTCASE_NAME_FORMAT_PATTERN)
        self.result_pattern = re.compile(_TESTCASE_RESULT_FORMAT_PATTERN)

        self.loglist = self.parse_logfile()
        self.log_handler.close()

    def locate_suite(self, suite_name=None):
        begin = 0
        end = len(self.loglist)
        for line in self.loglist:
            m = self.suite_pattern.match(line.values()[0])
            if m:
                if suite_name is None:
                    begin = self.loglist.index(line)
                elif suite_name == m.group(1):
                    begin = self.loglist.index(line)

        for line in self.loglist[begin:]:
            m = self.end_pattern.match(line.values()[0])
            if m:
                if suite_name is None:
                    end = self.loglist.index(line)
                elif suite_name == m.group(1):
                    end = self.loglist.index(line)

        return self.loglist[begin:end + 1]

    def locate_case(self, case_name=None):
        begin = 0
        end = len(self.loglist)
        for line in self.loglist:
            # only handle case log
            m = self.case_pattern.match(line.values()[0])
            if m:
                # not determine case will start from begining
                if case_name is None:
                    begin = self.loglist.index(line)
                # start from the determined case
                elif case_name == m.group(1):
                    begin = self.loglist.index(line)

        for line in self.loglist[begin:]:
            m = self.result_pattern.match(line.values()[0])
            if m:
                # not determine case will stop to the end
                if case_name is None:
                    end = self.loglist.index(line)
                # stop to the determined case
                elif case_name == m.group(1):
                    end = self.loglist.index(line)

        return self.loglist[begin:end + 1]

    def __dict_log(self, lvl_name, msg):
        tmp = {}
        if lvl_name is not '':
            tmp[lvl_name] = msg
        return tmp

    def parse_logfile(self):
        loglist = []

        out_type = 'DTS_DUT_OUTPUT'
        for line in self.log_handler:
            tmp = {}
            line = line.replace('\n', '')
            line = line.replace('^M', '')
            m = re.match("(\d{2}/\d{2}/\d{4}) (\d{2}:\d{2}:\d{2}) (.{20}): (.*)", line)
            if m:
                lvl_name = m.group(3).strip()
                tmp = self.__dict_log(lvl_name, m.group(4))
                if "OUTPUT" in lvl_name:
                    out_type = lvl_name
            else:
                tmp[out_type] = line

            loglist.append(tmp)

        return loglist
