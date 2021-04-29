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
   * Pass test cmdline arguments to the TestCase object
   * Add support for multiple testers
   * Increase timeout of get_session_output to 1 second
   * Rework some of the logs
   * Add logs about test case running and current iteration
   * Add result_table_set_precision() method
"""

"""
A base class for creating DTF test cases.
"""
import re
import debugger
import traceback
import signal
import time

from exception import VerifyFailure, TimeoutException
from settings import DRIVERS, NICS, get_nic_name, load_global_setting
from settings import PERF_SETTING, FUNC_SETTING, DEBUG_SETTING, DEBUG_CASE_SETTING, HOST_DRIVER_SETTING
from rst import RstReport
from test_result import ResultTable, Result
from logger import getLogger
from config import SuiteConf

class TestCase(object):

    def __init__(self, duts, testers, target, suitename, test_configs):
        self.suite_name = suitename
        self.dut = duts[0]
        self.duts = duts
        self.testers = testers
        self.tester = testers[0]
        self.target = target
        self.test_configs = test_configs

        # local variable
        self._requested_tests = None

        # check session and reconnect if possible
        for dutobj in self.duts:
            self._check_and_reconnect(crb=dutobj)
        for tester in self.testers:
            self._check_and_reconnect(crb=tester)

        # covert netdevice to codename
        self.nics = []
        for portid in range(len(self.dut.ports_info)):
            nic_type = self.dut.ports_info[portid]['type']
            self.nics.append(get_nic_name(nic_type))
        if len(self.nics):
            self.nic = self.nics[0]
        else:
            self.nic = ''
        self.kdriver = self._get_nic_driver(self.nic)

        # result object for save suite result
        self._suite_result = Result()
        self._suite_result.dut = self.dut.crb['IP']
        self._suite_result.target = target
        self._suite_result.nic = self.nic
        self._suite_result.test_suite = self.suite_name
        if self._suite_result is None:
            raise ValueError("Result object should not None")

        # load running enviornment
        if load_global_setting(PERF_SETTING) == "yes":
            self._enable_perf = True
        else:
            self._enable_perf = False

        if load_global_setting(FUNC_SETTING) == "yes":
            self._enable_func = True
        else:
            self._enable_func = False

        if load_global_setting(DEBUG_SETTING) == "yes":
            self._enable_debug = True
        else:
            self._enable_debug = False

        if load_global_setting(DEBUG_CASE_SETTING) == "yes":
            self._debug_case = True
        else:
            self._debug_case = False

        self.drivername = load_global_setting(HOST_DRIVER_SETTING)

        # create rst format report for this suite
        self._rst_obj = RstReport('rst_report', target, self.nic, self.suite_name, self._enable_perf)

        # load suite configuration
        self._suite_conf = SuiteConf(self.suite_name)
        self._suite_cfg = self._suite_conf.suite_cfg

    def init_log(self):
        # get log handler
        class_name = self.__class__.__name__
        self.logger = getLogger(class_name)
        self.logger.config_suite(class_name)

    def _check_and_reconnect(self, crb=None):
        try:
            result = crb.session.check_available()
        except:
            result = False

        if result is False:
            crb.reconnect_session()
            if 'dut' in str(type(crb)):
                crb.send_expect("cd %s" % crb.base_dir, "#")

        try:
            result = crb.alt_session.check_available()
        except:
            result = False

        if result is False:
            crb.reconnect_session(alt_session=True)

    def set_up_all(self):
        pass

    def set_up(self):
        pass

    def tear_down(self):
        pass

    def tear_down_all(self):
        pass

    def verify(self, passed, description):
        if not passed:
            raise VerifyFailure(description)

    def _get_nic_driver(self, nic_name):
        if nic_name in DRIVERS.keys():
            return DRIVERS[nic_name]

        return "Unknown"

    def set_check_inst(self, check=None):
        self._check_inst = check

    def rst_report(self, *args, **kwargs):
        self._rst_obj.report(*args, **kwargs)

    def result_table_create(self, header):
        self._result_table = ResultTable(header)
        self._result_table.set_rst(self._rst_obj)
        self._result_table.set_logger(self.logger)

    def result_table_add(self, row):
        self._result_table.add_row(row)

    def result_table_print(self):
        self._result_table.table_print()

    def result_table_getrows(self):
        return self._result_table.results_table_rows

    def result_table_set_precision(self, width):
        self._result_table.set_precision(width)

    def _get_functional_cases(self):
        """
        Get all functional test cases.
        """
        return self._get_test_cases(r'test_(?!perf_)')

    def _get_performance_cases(self):
        """
        Get all performance test cases.
        """
        return self._get_test_cases(r'test_perf_')

    def _has_it_been_requested(self, test_case, test_name_regex):
        """
        Check whether test case has been requested for validation.
        """
        name_matches = re.match(test_name_regex, test_case.__name__)

        if self._requested_tests is not None:
            return name_matches and test_case.__name__ in self._requested_tests

        return name_matches

    def set_requested_cases(self, case_list):
        """
        Pass down input cases list for check
        """
        self._requested_tests = case_list

    def _get_test_cases(self, test_name_regex):
        """
        Return case list which name matched regex.
        """
        for test_case_name in dir(self):
            test_case = getattr(self, test_case_name)
            if callable(test_case) and self._has_it_been_requested(test_case, test_name_regex):
                yield test_case

    def execute_setup_all(self):
        """
        Execute suite setup_all function before cases.
        """
        # clear all previous output
        for dutobj in self.duts:
            dutobj.get_session_output(timeout=1)
        for tester in self.testers:
            tester.get_session_output(timeout=1)

        try:
            self.set_up_all()
            return True
        except Exception:
            self.logger.error('set_up_all failed:\n' + traceback.format_exc())
            # record all cases blocked
            if self._enable_func:
                for case_obj in self._get_functional_cases():
                    self._suite_result.test_case = case_obj.__name__
                    self._suite_result.test_case_blocked('set_up_all failed')
            if self._enable_perf:
                for case_obj in self._get_performance_cases():
                    self._suite_result.test_case = case_obj.__name__
                    self._suite_result.test_case_blocked('set_up_all failed')
            return False

    def _execute_test_case(self, case_obj):
        """
        Execute specified test case in specified suite. If any exception occured in
        validation process, save the result and tear down this case.
        """
        case_name = case_obj.__name__
        self._suite_result.test_case = case_obj.__name__

        self._rst_obj.write_title("Test Case: " + case_name)

        # load suite configuration file here for rerun command
        self._suite_conf = SuiteConf(self.suite_name)
        self._suite_cfg = self._suite_conf.suite_cfg
        self._case_cfg = self._suite_conf.load_case_config(case_name)
        del(self._suite_conf)

        case_result = True
        if self._check_inst is not None:
            if self._check_inst.case_skip(case_name[len("test_"):]):
                self.logger.info('Test Case "%s" Result SKIPPED:' % case_name)
                self._rst_obj.write_result("N/A")
                self._suite_result.test_case_skip(self._check_inst.comments)
                return case_result

            if not self._check_inst.case_support(case_name[len("test_"):]):
                self.logger.info('Test Case "%s" Result SKIPPED:' % case_name)
                self._rst_obj.write_result("N/A")
                self._suite_result.test_case_skip(self._check_inst.comments)
                return case_result

        if self._enable_perf:
            self._rst_obj.write_annex_title("Annex: " + case_name)
        try:
            self.logger.info('Test Case "%s" Begin' % case_name)

            self.running_case = case_name
            # clean session
            for dutobj in self.duts:
                dutobj.get_session_output(timeout=1)
            for tester in self.testers:
                tester.get_session_output(timeout=1)
            # run set_up function for each case
            self.set_up()
            # run test case
            case_obj()

            self._suite_result.test_case_passed()

            self._rst_obj.write_result("PASS")
            self.logger.info('Test Case "%s" Result PASSED:' % case_name)

        except VerifyFailure as v:
            case_result = False
            self._suite_result.test_case_failed(str(v))
            self._rst_obj.write_result("FAIL")
            self.logger.error('Test Case "%s" Result FAILED: ' % (case_name) + str(v))
        except KeyboardInterrupt:
            self._suite_result.test_case_blocked("Skipped")
            self.logger.error('Test Case "%s" SKIPPED: ' % (case_name))
            self.tear_down()
            raise KeyboardInterrupt("Stop DTS")
        except TimeoutException as e:
            case_result = False
            self._rst_obj.write_result("FAIL")
            self._suite_result.test_case_failed(str(e))
            self.logger.error('Test Case "%s" Result FAILED: ' % (case_name) + str(e))
            self.logger.error('%s' % (e.get_output()))
        except Exception:
            case_result = False
            trace = traceback.format_exc()
            self._suite_result.test_case_failed(trace)
            self.logger.error('Test Case "%s" Result ERROR: ' % (case_name) + trace)
        finally:
            self.tear_down()
            return case_result

    def execute_test_cases(self):
        """
        Execute all test cases in one suite.
        """
        # prepare debugger rerun case environment
        if self._enable_debug or self._debug_case:
            debugger.AliveSuite = self
            debugger.AliveModule = __import__('TestSuite_' + self.suite_name)

        if load_global_setting(FUNC_SETTING) == 'yes':
            for case_obj in self._get_functional_cases():
                print("Case: " + case_obj)
                for i in range(self.tester.re_run_time + 1):
                    print("Run: " + i)
                    ret = self.execute_test_case(case_obj)

                    if ret is False and self.tester.re_run_time:
                        for dutobj in self.duts:
                            dutobj.get_session_output(timeout = 0.5 * (i + 1))
                        for tester in self.testers:
                            tester.get_session_output(timeout = 0.5 * (i + 1))
                        time.sleep(i + 1)
                        self.logger.info(" Test case %s failed and re-run %d time" % (case_obj.__name__, i + 1))
                    else:
                        break

        if load_global_setting(PERF_SETTING) == 'yes':
            for case_obj in self._get_performance_cases():
                self.execute_test_case(case_obj)

    def execute_test_case(self, case_obj):
        """
        Execute test case or enter into debug mode.
        """
        debugger.AliveCase = case_obj.__name__

        if self._debug_case:
            self.logger.info("Rerun Test Case %s Begin" % debugger.AliveCase)
            debugger.keyboard_handle(signal.SIGINT, None)
        else:
            return self._execute_test_case(case_obj)

    def get_result(self):
        """
        Return suite test result
        """
        return self._suite_result

    def get_case_cfg(self):
        """
        Return case based configuration
        """
        return self._case_cfg

    def get_suite_cfg(self):
        """
        Return suite based configuration
        """
        return self._suite_cfg

    def execute_tear_downall(self):
        """
        execute suite tear_down_all function
        """
        try:
            self.tear_down_all()
        except Exception:
            self.logger.error('tear_down_all failed:\n' + traceback.format_exc())

        for dutobj in self.duts:
            dutobj.kill_all()
        for tester in self.testers:
            tester.kill_all()

        for dutobj in self.duts:
            dutobj.virt_exit()
            # destroy all vfs
            dutobj.destroy_all_sriov_vfs()


    def wirespeed(self, nic, frame_size, num_ports):
        """
        Calculate bit rate. It is depended for NICs
        """
        bitrate = 1000.0  # 1Gb ('.0' forces to operate as float)
        if self.nic == "any" or self.nic == "cfg":
            driver = self._get_nic_driver(self.dut.ports_info[0]['type'])
            nic = get_nic_name(self.dut.ports_info[0]['type'])
        else:
            driver = self._get_nic_driver(self.nic)
            nic = self.nic

        if driver == "ixgbe":
            bitrate *= 10  # 10 Gb NICs
        elif nic == "avoton2c5":
            bitrate *= 2.5  # 2.5 Gb NICs
        elif nic in ["fortville_spirit", "fortville_spirit_single"]:
            bitrate *= 40
        elif nic == 'fortville_eagle':
            bitrate *= 10
        elif nic == 'fortpark_TLV':
            bitrate *= 10
        elif nic == 'redrockcanyou':
            bitrate *= 40
        elif driver == 'thunder-nicvf':
            bitrate *= 10
        elif nic == 'fortville_25g':
            bitrate *=25

        return bitrate * num_ports / 8 / (frame_size + 20)
