# BSD LICENSE
#
# Copyright(c) 2017 Linaro. All rights reserved.
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

import json

class JSONReporter(object):

    def __init__(self, filename):
        self.filename = filename

    def __scan_cases(self, result, dut, target, suite):
        case_results = {}
        for case in result.all_test_cases(dut, target, suite):
             test_result = result.result_for(dut, target, suite, case)
             case_name = '{}/{}'.format(suite,case)
             case_results[case_name] = test_result
             if 'PASSED' in test_result:
                 case_results[case_name] = 'passed'
             elif 'N/A' in test_result:
                 case_results[case_name] = 'n/a'
             elif 'FAILED' in test_result:
                 case_results[case_name] = 'failed'
             elif 'BLOCKED' in test_result:
                 case_results[case_name] = 'blocked'
        return case_results

    def __scan_target(self, result, dut, target):
        if result.is_target_failed(dut, target):
            return 'fail'
        case_results = {}
        for suite in result.all_test_suites(dut, target):
            case_results.update(self.__scan_cases(result, dut, target, suite))
        return case_results

    def __scan_dut(self, result, dut):
        if result.is_dut_failed(dut):
            return 'fail'
        target_map = {}
        for target in result.all_targets(dut):
            target_map[target] = self.__scan_target(result, dut, target)
        return target_map

    def save(self, result):
        result_map = {}
        for dut in result.all_duts():
            result_map[dut] = self.__scan_dut(result, dut)
        with open(self.filename, 'w') as outfile:
            json.dump(result_map, outfile, indent=4, separators=(',', ': '), encoding="utf-8", sort_keys=True)
