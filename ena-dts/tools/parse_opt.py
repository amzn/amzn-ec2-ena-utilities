#!/usr/bin/python
import sys
import os.path
import re


def RED(text):
    return "\x1B[" + "31;1m" + str(text) + "\x1B[" + "0m"


def GREEN(text):
    return "\x1B[" + "32;1m" + str(text) + "\x1B[" + "0m"


OPTION_TYPES = ['string', 'ip', 'int', 'bool', 'choice', 'multichoice']


class Option(object):

    def __init__(self, **args):
        self.args = args

        if 'prompt' in args.keys():
            self.prompt = args['prompt'] + ': '
        else:
            self.prompt = "Please input value: "
        if 'type' in args.keys():
            opt_type = args['type']
            if opt_type not in OPTION_TYPES:
                print RED('Invalid option type!!!')
                raise ValueError
            else:
                self.opt_type = opt_type
        else:
            self.opt_type = 'string'
        if self.opt_type == 'bool':
            self.prompt += '[Yes/No]'

        if 'help' in args.keys():
            self.help_msg = args['help']
        else:
            self.help_msg = ''
        if 'options' in args.keys():
            self.opts = args['options']

        if 'default' in args.keys():
            self.default_value = args['default']
            self.prompt += ' Default is [%s]' % self.default_value
        else:
            self.default_value = ''

        if self.check_args() is False:
            raise ValueError

        self.prompt += '->'

    def check_args(self):
        if self.opt_type == 'choice':
            if 'options' not in self.args.keys():
                print RED("Choice option request options list!!!")
                return False

            if type(self.opts) != list:
                return False

        return True

    def __print_options(self):
        index = 0
        for opt in self.opts:
            print GREEN("%2d: %s" % (index, str(opt)))
            index += 1

    def parse_input(self):
        parse_done = False

        print GREEN(self.help_msg)

        while not parse_done:
            try:
                if self.opt_type == 'choice' or self.opt_type == 'multichoice':
                    self.__print_options()

                input_val = raw_input(self.prompt)
                if input_val == '':
                    input_val = self.default_value
                    print GREEN("Chose default [%s]" % input_val)

                if self.opt_type == 'int':
                    self.value = int(input_val)
                elif self.opt_type == 'bool':
                    opt = input_val.upper()
                    if opt not in ['YES', 'NO']:
                        raise ValueError
                    if opt == 'YES':
                        self.value = True
                    elif opt == 'NO':
                        self.value = False
                elif self.opt_type == 'string':
                    self.value = input_val
                elif self.opt_type == 'choice':
                    try:
                        index = int(input_val)
                    except:
                        print RED("Invalid option index!!!")
                        raise ValueError

                    if index >= len(self.opts):
                        print RED("Choice index should be 0-%d!!!"
                                  % len(self.opts))
                        raise ValueError
                    self.value = self.opts[index]
                    self.choice = index
                elif self.opt_type == 'multichoice':
                    if input_val == 'all':
                        self.value = self.opts
                        break
                    try:
                        sel_indexs = []
                        sel_options = []
                        input_val.strip()
                        input_arrs = input_val.split(',')
                        for sel_index in input_arrs:
                            if '-' in sel_index:
                                indexs = sel_index.split('-')
                                start = int(indexs[0])
                                end = int(indexs[1])
                                if end <= start:
                                    print RED("Choice end number must be "
                                              "larger than start number!!!")
                                    raise ValueError

                                for index in range(start, end + 1):
                                    sel_indexs.append(index)
                            else:
                                index = int(sel_index)

                                sel_indexs.append(index)
                        # sorted list
                        sel_indexs = list(set(sorted(sel_indexs)))
                        for index in sel_indexs:
                            if index >= len(self.opts):
                                print RED("Choice index should be 0-%d!!!"
                                          % len(self.opts))
                            sel_options.append(self.opts[index])
                        self.value = sel_options
                    except:
                        print RED("Invalid option!!!")
                        raise ValueError

                elif self.opt_type == 'ip':
                    ip_reg = r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}'
                    m = re.match(ip_reg, input_val)
                    if m:
                        self.value = input_val
                    else:
                        raise ValueError

            except Exception as e:
                if type(e) is ValueError:
                    print "Options parse failure"
                    continue

            parse_done = True

        print ('')

        return self.value


if __name__ == "__main__":
    option = {'prompt': 'first option',
              'type': 'string', 'help': 'help message',
              'default': 'DEFAULT'}
    string_opt = Option(**option)
    print string_opt.parse_input()
    option = {'prompt': 'bool option', 'type': 'bool',
              'help': 'bool option [Yes/No] only',
              'default': 'No'}
    bool_opt = Option(**option)
    print bool_opt.parse_input()
    option = {'prompt': 'choice option', 'type': 'choice',
              'help': 'choice option in [1, 2 ,3]',
              'options': ['option1', 'option2', 'option3'],
              'default': '0'}
    choice_opt = Option(**option)
    print choice_opt.parse_input()
    option = {'prompt': 'multichoice option', 'type': 'multichoice',
              'help': 'mutli choice option in [1, 2 ,3]',
              'options': ['option1', 'option2', 'option3'],
              'default': '0'}
    multichoice_opt = Option(**option)
    print multichoice_opt.parse_input()
