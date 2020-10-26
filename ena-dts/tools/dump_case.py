#!/usr/bin/python
import sys
import os
import re
import inspect
import json

exec_file = os.path.realpath(__file__)
DTS_PATH = exec_file.replace('/tools/dump_case.py', '')

DTS_SUITES = DTS_PATH + '/tests'
DTS_FRAMEWORK = DTS_PATH + '/framework'

sys.path.append(DTS_SUITES)
sys.path.append(DTS_FRAMEWORK)

import dts
from test_case import TestCase
from utils import pprint


def get_subclasses(module, clazz):
    """
    Get module attribute name and attribute.
    """
    for subclazz_name, subclazz in inspect.getmembers(module):
        if hasattr(subclazz, '__bases__') and clazz in subclazz.__bases__:
            yield (subclazz_name, subclazz)


def scan_suites():
    global suites
    suite_reg = r'TestSuite_(.*).py$'

    suites = []
    files = os.listdir(DTS_SUITES)
    for file_name in files:
        m = re.match(suite_reg, file_name)
        if m:
            suites.append(m.group(1))

    suites = sorted(suites)


def get_cases(test_suite, test_name_regex):
    """
    Return case list which name matched regex.
    """
    cases = []
    for test_case_name in dir(test_suite):
        test_case = getattr(test_suite, test_case_name)
        if callable(test_case) and re.match(test_name_regex, test_case_name):
            cases.append(test_case_name)

    return cases


def get_functional_test_cases(test_suite):
    """
    Get all functional test cases.
    """
    return get_cases(test_suite, r'test_(?!perf_)')


def get_performance_test_cases(test_suite):
    """
    Get all performance test cases.
    """
    return get_cases(test_suite, r'test_perf_')


class simple_dut(object):

    def __init__(self):
        self.ports_info = []


def load_cases():
    dut = simple_dut()
    suite_func_list = {}
    suite_perf_list = {}
    for suite in suites:
        test_module = __import__('TestSuite_' + suite)
        for classname, test_class in get_subclasses(test_module, TestCase):
            test_suite = test_class(dut, None, None, suite)
            func_cases = get_functional_test_cases(test_suite)
            perf_cases = get_performance_test_cases(test_suite)
        suite_func_list[suite] = func_cases
        suite_perf_list[suite] = perf_cases 

    print pprint(suite_func_list)
    print pprint(suite_perf_list)


if __name__ == '__main__':
    scan_suites()
    load_cases()
