import pytest
import os
import subprocess

@pytest.fixture(arg_1, arg_2, [('phone_test1.txt', 'phone_out1.txt'),
                               ('phone_test2.txt', 'phone_out2.txt')])
def do_things_phone(arg_1, arg_2):
    cmd = 'do_things.py -u {} {}'.format(arg_1, arg_2)
    out = subprocess.Popen(cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    stdout,stderr = out.communicate()
    assert stdout is not None

@pytest.fixture(arg_1, arg_2, [('comp_test1.txt', 'test2.txt'),
                               ('test3.txt', 'test4.txt')])
def do_things_comp(arg_1, arg_2):
    cmd = 'do_things.py -p {} {}'.format(arg_1, arg_2)
    out = subprocess.Popen(cmd,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
    stdout,stderr = out.communicate()
    assert stdout is not None
