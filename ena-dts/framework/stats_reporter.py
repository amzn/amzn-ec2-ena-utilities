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
Simple text file statistics generator
"""


class StatsReporter(object):

    """
    Generates a small statistics file containing the number of passing,
    failing and blocked tests. It makes use of a Result instance as input.
    """

    def __init__(self, filename):
        self.filename = filename

    def __add_stat(self, test_result):
        if test_result is not None:
            if test_result[0] == 'PASSED':
                self.passed += 1
            if test_result[0] == 'FAILED':
                self.failed += 1
            if test_result[0] == 'BLOCKED':
                self.blocked += 1
            self.total += 1

    def __count_stats(self):
        for dut in self.result.all_duts():
            for target in self.result.all_targets(dut):
                for suite in self.result.all_test_suites(dut, target):
                    for case in self.result.all_test_cases(dut, target, suite):
                        test_result = self.result.result_for(
                            dut, target, suite, case)
                        if len(test_result):
                            self.__add_stat(test_result)

    def __write_stats(self):
        self.__count_stats()
        self.stats_file.write("Passed     = %d\n" % self.passed)
        self.stats_file.write("Failed     = %d\n" % self.failed)
        self.stats_file.write("Blocked    = %d\n" % self.blocked)
        rate = 0
        if self.total > 0:
            rate = self.passed * 100.0 / self.total
        self.stats_file.write("Pass rate  = %.1f\n" % rate)

    def save(self, result):
        self.passed = 0
        self.failed = 0
        self.blocked = 0
        self.total = 0
        self.stats_file = open(self.filename, "w+")
        self.result = result
        self.__write_stats()
        self.stats_file.close()
