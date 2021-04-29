# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from exception import TimeoutException

from utils import GREEN, RED, BLUE


class GDB(object):
    PROMPT = "(gdb)"

    def __init__(self, host, app, app_prompt):
        self.host = host
        self.app = app
        self.app_prompt = app_prompt

    def start(self, p=""):
        self.send("gdb --args {} {}".format(self.app, p))
        self.send("set confirm off")
        self.send("set pagination off")

    def send_twice(self, command, prompt):
        out = ""
        try:
            out = self.host.send_expect(command, prompt)
        except TimeoutException as te:
            out += self.send_app("")
        return out

    def send(self, command):
        return self.send_twice(command, GDB.PROMPT)

    def send_app(self, command):
        return self.send_twice(command, self.app_prompt)

    def test_path(self, f_in, action, f_ret, ret_value, call_number):
        o = self.add_tbreak(f_in)
        if o != 0:
            self.exit_gdb()
            return -1
        if action is None:
            self.send("run")
        else:
            self.interact(action)
        for i in range(call_number):
            o = self.add_tbreak(f_ret)
            if o != 0:
                self.exit_gdb()
                return -1
            self.send("continue")
        self.send("backtrace")
        self.send("return {}".format(ret_value))
        return 0

    def continue_app(self):
        return self.send_app("continue")

    def continue_gdb(self):
        return self.send("continue")

    def interact(self, action):
        pass

    def exit_gdb(self):
        self.host.send_expect("quit", self.host.prompt)

    def add_tbreak(self, func_name):
        out = self.send("tbreak {}".format(func_name))
        if "not defined" in out:
            print(RED("Cannot find {}".format(func_name)))
            return -1
        return 0


class TestpmdGDB(GDB):
    TESTPMD_PROMPT = "testpmd>"
    APP = "./x86_64-native-linuxapp-gcc/app/testpmd -c 0x3 -n 2  -- " \
          "--portmask=0x1 --forward-mode=icmpecho -i -a"

    def __init__(self, host):
        super(TestpmdGDB, self).__init__(host, self.APP, self.TESTPMD_PROMPT)

    def exit(self):
        out = self.send("quit")  # Press enter to exit testpmd non interactive mode
        self.exit_gdb()
        return out

    def interact(self, action):
        self.send_twice("run", self.TESTPMD_PROMPT)
        for a in action[:-1]:
            self.send_twice(a, self.TESTPMD_PROMPT)
        self.send(action[-1])
