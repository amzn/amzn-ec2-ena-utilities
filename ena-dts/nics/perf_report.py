# BSD LICENSE
#
# Copyright(c) 2010-2017 Intel Corporation. All rights reserved.
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

import os
import time
import re

import jinja2
import smtplib

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import OrderedDict
#install GitPython
from git import Repo
from system_info import SystemInfo
import utils

def get_dpdk_git_info(repo_dir="/root/dpdk"):

    if not os.path.exists(repo_dir):
        return None

    commit = OrderedDict()

    git_repo = Repo(repo_dir)
    assert not git_repo.bare

    latest_commit = git_repo.active_branch.commit
    commit['branch'] = str(git_repo.active_branch)
    commit['commit'] = str(latest_commit)
    commit['author'] = latest_commit.author
    commit['date'] = time.ctime(latest_commit.authored_date)
    commit['summary'] = latest_commit.summary
    return commit

def generate_html_report(file_tpl, perf_data, git_info, nic_info, system_info):
   
    if not os.path.exists(file_tpl):
        return None

    templateLoader = jinja2.FileSystemLoader(searchpath = "/")
    templateEnv = jinja2.Environment(loader=templateLoader)
    template = templateEnv.get_template(file_tpl)
 
    templateVars = { "title" : "Daily Performance Test Report", \
                     "test_results" : perf_data, \
                     "system_infos" : system_info, \
                     "nic_infos" : nic_info, \
                     "git_info" : git_info \
                   }

    output = template.render(templateVars)
    return output

#sender = 'zzz@intel.com'
#mailto = ['xxx@intel.com', 'yyy@intel.com']
def html_message(sender, mailto, subject, html_msg):

    msg = MIMEMultipart('alternative')
    msg['From'] = sender
    msg['to'] = ";".join(mailto)
    msg['Subject'] = subject

    msg.attach(MIMEText(html_msg, 'html'))

    return msg

#smtp = smtplib.SMTP('smtp.intel.com')
def send_email(sender, mailto, message, smtp_server):

    try:
        smtp = smtplib.SMTP(smtp_server)
        smtp.sendmail(sender, mailto, message.as_string())
        smtp.quit()
        print utils.GREEN("Email sent successfully.")
    except Exception, e:
        print utils.RED("Failed to send email " + str(e))

def send_html_report(sender, mailto, subject, html_msg, smtp_server):
    
    message = html_message(sender, mailto, subject, html_msg)
    send_email(sender, mailto, message, smtp_server)
