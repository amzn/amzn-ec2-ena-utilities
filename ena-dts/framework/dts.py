# BSD LICENSE
#
# Copyright(c) 2010-2016 Intel Corporation. All rights reserved.
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
    * Add possibility to use 2 separate testers
    * Allow to use different DPDK/pktgen on DUT and Tester
    * Remove support of running multiple suites at once
    * Detect if the configuration was already performed and skip it (unless
      forced to do otherwise)
    * Remove and rework some logs
    * Add logs about pcap files being reused or created
    * Add functions:
      - parse_repo
      - raise_error
      - patches_from_subdir
      - apply_patches
      - prepare_repos
      - execute
    * Call restore_modules for tester for dts_run_target
"""

import re           # regular expressions module
import ConfigParser  # config parse module
import os           # operation system module
import texttable    # text format
import traceback    # exception traceback
import inspect      # load attribute
import atexit       # register callback when exit
import json         # json format
import signal       # signal module for debug mode
import time         # time module for unique output folder
import copy         # copy module for duplicate variable

import rst          # rst file support
import sys          # system module
import settings     # dts settings
from tester import Tester
from dut import Dut
from serializer import Serializer
from test_case import TestCase
from test_result import Result
from stats_reporter import StatsReporter
from excel_reporter import ExcelReporter
from json_reporter import JSONReporter
from exception import TimeoutException, ConfigParseException, VerifyFailure
from logger import getLogger
import logger
import debugger
from config import CrbsConf
from checkCase import CheckCase
from utils import get_subclasses, copy_instance_attr, RED
import sys
import shutil
reload(sys)
sys.setdefaultencoding('UTF8')


requested_tests = None
result = None
excel_report = None
json_report = None
stats_report = None
log_handler = None


def dts_parse_param(config, section):
    """
    Parse execution file parameters.
    """
    # default value
    performance = False
    functional = False
    # Set parameters
    parameters = config.get(section, 'parameters').split(':')
    drivername = config.get(section, 'drivername').split('=')[-1]

    driver = drivername.split(':')
    if len(driver) == 2:
        drivername = driver[0]
        drivermode = driver[1]
        settings.save_global_setting(settings.HOST_DRIVER_MODE_SETTING, drivermode)
    else:
        drivername = driver[0]

    settings.save_global_setting(settings.HOST_DRIVER_SETTING, drivername)

    paramDict = dict()
    for param in parameters:
        (key, _, value) = param.partition('=')
        paramDict[key] = value

    if 'perf' in paramDict and paramDict['perf'] == 'true':
        performance = True
    if 'func' in paramDict and paramDict['func'] == 'true':
        functional = True

    if 'nic_type' not in paramDict:
        paramDict['nic_type'] = 'any'

    settings.save_global_setting(settings.HOST_NIC_SETTING, paramDict['nic_type'])

    # save perf/funtion setting in enviornment
    if performance:
        settings.save_global_setting(settings.PERF_SETTING, 'yes')
    else:
        settings.save_global_setting(settings.PERF_SETTING, 'no')

    if functional:
        settings.save_global_setting(settings.FUNC_SETTING, 'yes')
    else:
        settings.save_global_setting(settings.FUNC_SETTING, 'no')


def dts_parse_config(config, section):
    """
    Parse execution file configuration.
    """
    duts = [dut_.strip() for dut_ in config.get(section,
                                                'crbs').split(',')]
    targets = [target.strip()
               for target in config.get(section, 'targets').split(',')]
    test_suites = [suite.strip()
                   for suite in config.get(section, 'test_suites').split(',')]
    try:
        rx_mode = config.get(section, 'rx_mode').strip()
    except:
        rx_mode = 'default'

    settings.save_global_setting(settings.DPDK_RXMODE_SETTING, rx_mode)

    for suite in test_suites:
        if suite == '':
            test_suites.remove(suite)

    return duts, targets, test_suites


def dts_parse_commands(commands):
    """
    Parse command information from dts arguments
    """
    dts_commands = []

    if commands is None:
        return dts_commands

    args_format = {"shell": 0,
                   "crb": 1,
                   "stage": 2,
                   "check": 3,
                   "max_num": 4}
    cmd_fmt = r"\[(.*)\]"

    for command in commands:
        args = command.split(':')
        if len(args) != args_format['max_num']:
            log_handler.error("Command [%s] is lack of arguments" % command)
            raise VerifyFailure("commands input is not corrected")
            continue
        dts_command = {}

        m = re.match(cmd_fmt, args[0])
        if m:
            cmds = m.group(1).split(',')
            shell_cmd = ""
            for cmd in cmds:
                shell_cmd += cmd
                shell_cmd += ' '
            dts_command['command'] = shell_cmd[:-1]
        else:
            dts_command['command'] = args[0]
        if args[1] == "tester":
            dts_command['host'] = "tester"
        else:
            dts_command['host'] = "dut"
        if args[2] == "post-init":
            dts_command['stage'] = "post-init"
        else:
            dts_command['stage'] = "pre-init"
        if args[3] == "ignore":
            dts_command["verify"] = False
        else:
            dts_command["verify"] = True

        dts_commands.append(dts_command)

    return dts_commands


def dts_run_commands(crb, dts_commands):
    """
    Run dts input commands
    """
    for dts_command in dts_commands:
        command = dts_command['command']
        if dts_command['host'] in crb.NAME:
            if crb.stage == dts_command['stage']:
                ret = crb.send_expect(command, expected="# ", verify=True)
                if type(ret) is int:
                    log_handler.error("[%s] return failure" % command)
                    if dts_command['verify'] is True:
                        raise VerifyFailure("Command execution failed")


def get_project_obj(project_name, super_class, crbInst, serializer, test_configs):
    """
    Load project module and return crb instance.
    """
    project_obj = None
    PROJECT_MODULE_PREFIX = 'project_'
    try:
        project_module = __import__(PROJECT_MODULE_PREFIX + project_name)

        for project_subclassname, project_subclass in get_subclasses(project_module, super_class):
            project_obj = project_subclass(crbInst, serializer)
        if project_obj is None:
            project_obj = super_class(crbInst, serializer)
    except Exception as e:
        log_handler.info("LOAD PROJECT MODULE INFO: " + str(e))
        project_obj = super_class(crbInst, serializer)

    project_obj.test_configs = test_configs
    return project_obj


def dts_log_testsuite(duts, testers, suite_obj, log_handler, test_classname):
    """
    Change to SUITE self logger handler.
    """
    log_handler.config_suite(test_classname, 'dts')
    for tester in testers:
        tester.logger.config_suite(test_classname, 'tester')

    for dutobj in duts:
        dutobj.logger.config_suite(test_classname, 'dut')
        dutobj.test_classname = test_classname

    try:
        for tester in testers:
            if tester.it_uses_external_generator():
                getattr(tester, 'ixia_packet_gen')
                tester.ixia_packet_gen.logger.config_suite(test_classname, 'ixia')
    except Exception as ex:
        pass


def dts_log_execution(duts, testers, log_handler):
    """
    Change to DTS default logger handler.
    """
    log_handler.config_execution('dts')
    for tester in testers:
        tester.logger.config_execution('tester' + settings.LOG_NAME_SEP +
                                       '%s' % tester.crb['My IP'])

    for dutobj in duts:
        dutobj.logger.config_execution('dut' + settings.LOG_NAME_SEP + '%s' % dutobj.crb['My IP'])

    try:
        for tester in testers:
            if tester.it_uses_external_generator():
                getattr(tester, 'ixia_packet_gen')
                tester.ixia_packet_gen.logger.config_execution('ixia')
    except Exception as ex:
        pass


def dts_crbs_init(crbInsts, read_cache, project, base_dir,
                  serializer, virttype, test_configs):
    """
    Create dts dut/tester instance and initialize them.
    """
    duts = []
    test_configs["two_way_mono"] = False

    serializer.set_serialized_filename(settings.FOLDERS['Output'] +
                                       '/.%s.cache' % crbInsts[0]['IP'])
    serializer.load_from_file()

    testInst = copy.copy(crbInsts[0])
    testInst['My IP'] = crbInsts[0]['tester IP']
    testers = [get_project_obj(project, Tester, testInst, serializer, test_configs)]

    if 'tester2 IP' in testInst.keys():
        test2Inst = copy.copy(testInst)
        test2Inst['My IP'] = test2Inst['tester2 IP']
        test2Inst['tester IP'] = test2Inst['tester2 IP']
        test2Inst['tester_user'] = test2Inst['tester2_user']
        test2Inst['tester_ssh_key'] = test2Inst['tester2_ssh_key']
        testers.append(get_project_obj(project, Tester, test2Inst, serializer, test_configs))

    for crbInst in crbInsts:
        dutInst = copy.copy(crbInst)
        dutInst['My IP'] = crbInst['IP']
        dutobj = get_project_obj(project, Dut, dutInst, serializer, test_configs)
        duts.append(dutobj)

    dts_log_execution(duts, testers, log_handler)

    for tester in testers:
        tester.duts = duts
        tester.init_ext_gen()

    nic = settings.load_global_setting(settings.HOST_NIC_SETTING)
    for dutobj in duts:
        dutobj.tester = testers[0]
        dutobj.set_virttype(virttype)
        dutobj.set_directory(base_dir)
        # save execution nic setting
        dutobj.set_nic_type(nic)

    return duts, testers


def dts_crbs_exit(duts, testers):
    """
    Call dut and tester exit function after execution finished
    """
    for dutobj in duts:
        dutobj.crb_exit()

    for tester in testers:
        tester.crb_exit()


def dts_run_prerequisties(duts, testers, pkgName, patch, dts_commands,
        serializer, pktgen, test_configs):
    """
    Run dts prerequisties function.
    """
    try:
        for tester in testers:
            dts_run_commands(tester, dts_commands)
            tester.prerequisites(test_configs)
            dts_run_commands(tester, dts_commands)
    except Exception as ex:
        log_handler.error(" PREREQ EXCEPTION " + traceback.format_exc())
        log_handler.info('CACHE: Discarding cache.')
        serializer.discard_cache()
        settings.report_error("TESTER_SETUP_ERR")
        return False

    try:
        for dutobj in duts:
            dts_run_commands(dutobj, dts_commands)
            dutobj.set_package(pkgName, patch, pktgen)
            dutobj.prerequisites(test_configs)
            dts_run_commands(dutobj, dts_commands)

        serializer.save_to_file()
    except Exception as ex:
        log_handler.error(" PREREQ EXCEPTION " + traceback.format_exc())
        result.add_failed_dut(duts[0], str(ex))
        log_handler.info('CACHE: Discarding cache.')
        serializer.discard_cache()
        settings.report_error("DUT_SETUP_ERR")
        return False


def dts_run_target(duts, testers, targets, test_suites, test_configs):
    """
    Run each target in execution targets.
    """
    for target in targets:
        log_handler.info("TARGET " + target)
        result.target = target

        try:
            drivername = settings.load_global_setting(settings.HOST_DRIVER_SETTING)
            if drivername == "":
                for dutobj in duts:
                    dutobj.set_target(target, bind_dev=False)
            else:
                for dutobj in duts:
                    dutobj.set_target(target, test_configs)
            for tester in testers:
                tester.set_target(target, test_configs)
        except AssertionError as ex:
            log_handler.error(" TARGET ERROR: " + str(ex))
            settings.report_error("DPDK_BUILD_ERR")
            result.add_failed_target(result.dut, target, str(ex))
            continue
        except Exception as ex:
            settings.report_error("GENERIC_ERR")
            log_handler.error(" !!! DEBUG IT: " + traceback.format_exc())
            result.add_failed_target(result.dut, target, str(ex))
            continue

        dts_run_suite(duts, testers, test_suites, target, test_configs)

    for tester in testers:
        tester.restore_interfaces(test_configs["skip_target_env_setup"])
        tester.restore_modules(test_configs["skip_target_env_setup"])

    for dutobj in duts:
        dutobj.stop_ports()
        dutobj.restore_interfaces(test_configs["skip_target_env_setup"])
        dutobj.restore_modules(test_configs["skip_target_env_setup"])


def dts_run_suite(duts, testers, test_suites, target, test_configs):
    """
    Run each suite in test suite list.
    """
    for suite_name in test_suites:
        try:
            result.test_suite = suite_name
            suite_module = __import__('TestSuite_' + suite_name)

            test_classname = 'Test{}'.format(suite_name)
            test_class = getattr(suite_module, test_classname)
            suite_obj = test_class(duts, testers, target, suite_name, test_configs)
            suite_obj.init_log()
            suite_obj.set_requested_cases(requested_tests)
            suite_obj.set_check_inst(check=check_case_inst)
            result.nic = suite_obj.nic

            dts_log_testsuite(duts, testers, suite_obj, log_handler, test_classname)
            log_handler.info("Test suite: " + test_classname)

            if suite_obj.execute_setup_all():
                suite_obj.execute_test_cases()
                suite_obj.execute_tear_downall()

            # save suite cases result
            result.copy_suite(suite_obj.get_result())
            save_all_results()

            log_handler.info("Test suite ended: " + test_classname)
            dts_log_execution(duts, testers, log_handler)
        except VerifyFailure:
            settings.report_error("SUITE_EXECUTE_ERR")
            log_handler.error(" !!! DEBUG IT: " + traceback.format_exc())
        except KeyboardInterrupt:
            # stop/save result/skip execution
            log_handler.error(" !!! STOPPING DTS")
            suite_obj.execute_tear_downall()
            save_all_results()
            break
        except Exception as e:
            settings.report_error("GENERIC_ERR")
            log_handler.error(str(e))
        finally:
            suite_obj.execute_tear_downall()
            save_all_results()


def run_all(config_file, pkgName, patch, force_setup,
            read_cache, project, suite_dir, test_cases,
            base_dir, output_dir, verbose, virttype, debug,
            debugcase, re_run, commands, pktgen, test_configs):
    """
    Main process of DTS, it will run all test suites in the config file.
    """

    global requested_tests
    global result
    global excel_report
    global json_report
    global stats_report
    global log_handler
    global check_case_inst

    # save global variable
    serializer = Serializer()

    # load check/support case lists
    check_case_inst = CheckCase()

    # prepare the output folder
    if output_dir == '':
        output_dir = settings.FOLDERS['Output']

    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    # add python module search path
    sys.path.append(suite_dir)

    # enable debug mode
    if debug is True:
        settings.save_global_setting(settings.DEBUG_SETTING, 'yes')
    if debugcase is True:
        settings.save_global_setting(settings.DEBUG_CASE_SETTING, 'yes')

    # init log_handler handler
    if verbose is True:
        logger.set_verbose()

    if re_run < 0:
        re_run = 0

    logger.log_dir = output_dir
    log_handler = getLogger('dts')
    log_handler.config_execution('dts')

    # run designated test case
    requested_tests = test_cases

    # Read config file
    dts_cfg_folder = settings.load_global_setting(settings.DTS_CFG_FOLDER)
    if dts_cfg_folder != '':
        config_file = dts_cfg_folder + os.sep +  config_file

    config = ConfigParser.SafeConfigParser()
    load_cfg = config.read(config_file)
    if len(load_cfg) == 0:
        raise ConfigParseException(config_file)

    # parse commands
    dts_commands = dts_parse_commands(commands)

    os.environ["TERM"] = "dumb"

    # change rst output folder
    rst.path2Result = output_dir

    # report objects
    excel_report = ExcelReporter(output_dir + '/test_results.xls')
    json_report = JSONReporter(output_dir + '/test_results.json')
    stats_report = StatsReporter(output_dir + '/statistics.txt')
    result = Result()

    crbInsts = []
    crbs_conf = CrbsConf()
    crbs = crbs_conf.load_crbs_config()

    # for all Exectuion sections
    for section in config.sections():
        # Skip configuration sections
        if section in ['DPDK', 'Pktgen', 'Tester_DPDK', 'Tester_Pktgen',\
                'latency', 'reset']:
            continue
        dts_parse_param(config, section)

        # verify if the delimiter is good if the lists are vertical
        duts, targets, test_suites = dts_parse_config(config, section)

        # look up in crbs - to find the matching IP
        for dut in duts:
            for crb in crbs:
                if crb['section'] == dut:
                    crbInsts.append(crb)
                    break

        # only run on the dut in known crbs
        if len(crbInsts) == 0:
            log_handler.error(" SKIP UNKNOWN CRB")
            continue

        result.dut = duts[0]

        # init dut, tester crb
        duts, testers = dts_crbs_init(crbInsts, read_cache, project,
                                     base_dir, serializer, virttype,
                                     test_configs)
        for tester in testers:
            tester.set_re_run(re_run)
        # register exit action
        atexit.register(quit_execution, duts, testers)

        check_case_inst.change_dut(duts[0])

        test_configs["force_setup"] = force_setup
        # Check if set-up is installed on all CRBs:
        if force_setup is False:
            setup_ready = True
            dut_dpdk_repo = parse_repo(dict(config.items("DPDK")))
            dut_pktgen_repo = parse_repo(dict(config.items("Pktgen")))
            for dut in duts:
                setup_ready = setup_ready and dut.check_setup(
                    dut_dpdk_repo, dut_pktgen_repo,
                    test_configs["skip_target_env_setup"])
            tester_dpdk_repo = parse_repo(dict(config.items("Tester_DPDK")))\
                if "Tester_DPDK" in config.sections() else dut_dpdk_repo
            tester_pktgen_repo = parse_repo(dict(config.items("Tester_Pktgen")))\
                if "Tester_Pktgen" in config.sections() else dut_pktgen_repo
            for tester in testers:
                setup_ready = setup_ready and tester.check_setup(
                    tester_dpdk_repo, tester_pktgen_repo,
                    test_configs["skip_target_env_setup"])
        else:
            setup_ready = False

        show_speedup_options_messages(read_cache, setup_ready,
                test_configs["try_reuse_pcaps"], test_cases)
        for tester in testers:
            tester.set_speedup_options(read_cache, setup_ready)
        for dut in duts:
            dut.set_speedup_options(read_cache, setup_ready)

        # Clone DPDK and Pktgen repos and apply patches
        if not setup_ready:
            prepare_repos(config, pkgName, pktgen)

        # Run DUT prerequisites
        if dts_run_prerequisties(duts, testers, pkgName, patch, dts_commands,
                serializer, pktgen, test_configs) is False:
            dts_crbs_exit(duts, testers)
            continue

        dts_run_target(duts, testers, targets, test_suites, test_configs)

        dts_crbs_exit(duts, testers)

    save_all_results()


def show_speedup_options_messages(read_cache, skip_setup, reuse_pcaps,
        test_cases):
    if read_cache:
        log_handler.info('CACHE: All configuration will be read from cache.')
    else:
        log_handler.info('CACHE: Cache will not be read.')

    if skip_setup:
        log_handler.info('SKIP: Skipping DPDK setup.')
    else:
        log_handler.info('SKIP: The DPDK setup steps will be executed.')

    if reuse_pcaps:
        log_handler.info('It will be attempted to use existing pcap files (if any)')
    elif "test_perf_bw" in test_cases:
        log_handler.info('New pcap files will be generated')


def parse_repo(repo):
    assert "git" in repo, "Repository address not configured"
    remote = repo["git"]
    branch = repo["branch"] if "branch" in repo else None
    return remote, branch


def save_all_results():
    """
    Save all result to files.
    """
    excel_report.save(result)
    json_report.save(result)
    stats_report.save(result)


def quit_execution(duts, testers):
    """
    Close session to DUT and tester before quit.
    Return exit status when failure occurred.
    """
    # close all nics
    for dutobj in duts:
        if getattr(dutobj, 'ports_info', None) and dutobj.ports_info:
            for port_info in dutobj.ports_info:
                netdev = port_info['port']
                netdev.close()
        # close all session
        dutobj.close()
    for tester in testers:
        if tester is not None:
            tester.close()
    log_handler.info("DTS ended")

    # return value
    settings.exit_error()

def raise_error(error):
    raise error

def patches_from_subdir(pd):
    _dir_nm = '{patch_prefix}/{patch_dir}'.format(**pd)
    (_, _, f_lst) = os.walk(_dir_nm, onerror=raise_error).next()
    f_lst.sort()
    return f_lst

# Patches are taken from <patches_dir> and have to be applicable from within
# 'dep/<app_dir>'
def apply_patches(pd, isRevert=None):
    pd['revert'] = '' if isRevert is None else '-R'
    _apply_cmd = 'patch -d {app_prefix}/{app_dir} -p1 {revert} ' \
            '--ignore-whitespace < ' \
            'dep/patches/{patch_dir}/{{}}'.format(**pd)
    patch_lst = patches_from_subdir(pd)
    for p in patch_lst:
        execute(_apply_cmd.format(p))

def prepare_repos(config, dpdk, pktgen):
    print("Clone repos and apply patches")
    dep = settings.FOLDERS['Depends']
    dpdk = dpdk.split('/')[-1]
    pktgen = pktgen.split('/')[-1]
    for component in [('DPDK', 'dpdk', dpdk), ('Pktgen', 'pktgen', pktgen),
                      ('Tester_DPDK', 'dpdk', settings.tester_prefix + dpdk),
                      ('Tester_Pktgen', 'pktgen', settings.tester_prefix + pktgen)]:
        if os.path.exists('{}/{}'.format(dep, component[1])):
            shutil.rmtree('{}/{}'.format(dep, component[1]))
        if component[0] in config.sections():
            repo = dict(config.items(component[0]))
            if 'git' in repo:
                print(repo['git'])
                clone = "git clone {} {}/{}".format(
                    repo['git'], dep, component[1])
                execute(clone)
            if 'branch' in repo:
                branch = "cd {}/{}; git checkout {}".format(
                    dep, component[1], repo['branch'])
                execute(branch)
            # Apply all patches residing in indicated directory
            if 'patches_dir' in repo:
                apply_patches({
                    'app_prefix': dep,
                    'app_dir': component[1],
                    'patch_prefix': dep + '/' + settings.FOLDERS['Patches'],
                    'patch_dir': repo['patches_dir']
                    })
            archive = "cd {}; tar -cvzf {} {} > /dev/null".format(
                dep, component[2], component[1])
            execute(archive)
        elif settings.tester_prefix in component[0]:
            # if Testers setup not defined use the same as for dut
            execute("cd {}; cp {} {}".format(dep, component[2].replace(
                settings.tester_prefix, ""), component[2]))
    for app in [settings.latency_app, settings.reset_app]:
        if os.path.exists("{}/{}".format(dep, app)):
            # Patching auxiliary programs
            _patched = False
            if app in config.sections():
                _apply_input = {
                    'app_prefix': dep,
                    'app_dir': app,
                    'patch_prefix': dep + '/' + settings.FOLDERS['Patches'],
                    'patch_dir': dict(config.items(app))['patches_dir']
                    }
                apply_patches(_apply_input)
                _patched = True

            a = "cd {}; tar -cvzf {}.tar.gz {} > /dev/null".format(dep, app, app)
            execute(a)
            # Components that are not cloned need a revert locally so that the
            # test suite runs correctly next time
            if _patched:
                apply_patches(_apply_input, isRevert=True)

    # Download the amzn-drivers for the patched vfio-pci module
    if os.path.exists('{}/amzn-drivers'.format(dep)):
        shutil.rmtree('{}/amzn-drivers'.format(dep))

    amzn_repo = "https://github.com/amzn/amzn-drivers"
    clone = "git clone {} {}/amzn-drivers".format(amzn_repo, dep)
    execute(clone)
    vfio_path = "amzn-drivers/userspace/dpdk"
    archive = "cd {}; tar -C {} -czf enav2-vfio-patch.tar.gz enav2-vfio-patch > /dev/null".format(
        dep, vfio_path)
    execute(archive)

    # Download dpdk-kmods for standalone igb_uio module
    if os.path.exists('{}/dpdk-kmods'.format(dep)):
        shutil.rmtree('{}/dpdk-kmods'.format(dep))

    dpdk_kmods_repo = "git://dpdk.org/dpdk-kmods"
    clone = "git clone {} {}/dpdk-kmods".format(dpdk_kmods_repo, dep)
    execute(clone)
    archive = "cd {}; tar -czf dpdk-kmods.tar.gz dpdk-kmods > /dev/null".format(dep)
    execute(archive)

def execute(cmd):
    print(cmd)
    ret = os.system(cmd)
    if ret is not 0:
        raise EnvironmentError
