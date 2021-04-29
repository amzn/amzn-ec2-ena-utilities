"""
 Changes made to the original file:
    * Change some error logs to be
    * Improve some comments
    * Remove 'main' section from the code - it should be used only externally
"""

import xlrd
import collections
import json

from settings import get_nic_name
from utils import RED

filter_json_file = './conf/test_case_checklist.json'
support_json_file = './conf/test_case_supportlist.json'


class CheckCase(object):
    """
    Class for check test case running criteria. All information will be loaded
    from conf/test_case_*list.json. Current two files are maintained. One is
    for check whether test case should skip, another one is for check whether
    current environment support test case execution.
    """

    def __init__(self):
        self.dut = None
        self.comments = ''

        self.check_function_dict = {}
        self.support_function_dict = {}
        try:
            self.check_function_dict = json.load(open(filter_json_file), object_pairs_hook=collections.OrderedDict)
        except:
            print RED("Can't load check list for test cases, all test cases will be considered supported")

        try:
            self.support_function_dict = json.load(open(support_json_file), object_pairs_hook=collections.OrderedDict)
        except:
            print RED("Can't load support list for test cases, all test cases will be considered supported")

    def change_dut(self, dut):
        """
        Change DUT instance for environment check
        """
        self.dut = dut

    def _check_os(self, os_type):
        if 'all' == os_type[0].lower():
            return True
        dut_os_type = self.dut.get_os_type()
        if dut_os_type in os_type:
            return True
        else:
            return False

    def _check_nic(self, nic_type):
        if 'all' == nic_type[0].lower():
            return True
        dut_nic_type = get_nic_name(self.dut.ports_info[0]['type'])
        if dut_nic_type in nic_type:
            return True
        else:
            return False

    def _check_target(self, target):
        if 'all' == target[0].lower():
            return True
        if self.dut.target in target:
            return True
        else:
            return False

    def case_skip(self, case_name):
        """
        Check whether test case and DUT match skip criteria
        Return True if it is possible to skip the case
        """
        skip_flag = False
        self.comments = ""

        if self.dut is None:
            print RED("No Dut assigned before case skip check")
            return skip_flag

        if case_name in self.check_function_dict.keys():
            case_checks = self.check_function_dict[case_name]
            # each case may have several checks
            for case_check in case_checks:
                # init result for each check
                skip_flag = False
                for key in case_check.keys():
                    # some items like "Bug ID" and "Comments" do not need check
                    try:
                        if 'Comments' == key:
                            continue
                        if 'Bug ID' == key:
                            continue
                        check_function = getattr(self, '_check_%s' % key.lower())
                    except:
                        print RED("case_skip: can't check %s type in case name %s" % (key, case_name))

                    # skip this check if any item not matched
                    if check_function(case_check[key]):
                        skip_flag = True
                    else:
                        skip_flag = False
                        break

                # if all items matched, this case should skip
                if skip_flag:
                    if 'Comments' in case_check.keys():
                        self.comments = case_check['Comments']
                    return skip_flag

        return skip_flag

    def case_support(self, case_name):
        """
        Check whether test case and DUT match support criteria
        Return False if test case not supported
        """
        support_flag = True
        self.comments = ""

        if self.dut is None:
            print RED("No Dut assigned before case support check")
            return support_flag

        if case_name in self.support_function_dict.keys():
            # each case may have several supports
            case_supports = self.support_function_dict[case_name]
            for case_support in case_supports:
                # init result for each check
                support_flag = True
                for key in case_support.keys():
                    # some items like "Bug ID" and "Comments" do not need check
                    try:
                        if 'Comments' == key:
                            continue
                        if 'Bug ID' == key:
                            continue
                        check_function = getattr(self, '_check_%s' % key.lower())
                    except:
                        print RED("case_skip: can't check %s type in case name %s" % (key, case_name))

                    # skip this case if any item not matched
                    if check_function(case_support[key]):
                        support_flag = True
                    else:
                        support_flag = False
                        break

            if support_flag is False:
                if 'Comments' in case_support.keys():
                    self.comments = case_support['Comments']
                return support_flag

        return support_flag


class simple_dut(object):

    def __init__(self, os='', target='', nic=''):
        self.ports_info = [{}]
        self.os = os
        self.target = target
        self.ports_info[0]['type'] = nic

    def get_os_type(self):
        return self.os
