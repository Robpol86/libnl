import os
import subprocess
import sys

import pytest


def test_list_network_interfaces(ifacesi):
    path = os.path.join(os.path.dirname(__file__), '..', 'example_list_network_interfaces.py')
    stdout = subprocess.check_output([sys.executable, path, 'print'])
    if hasattr(stdout, 'decode'):
        stdout = stdout.decode('ascii')
    stdout_split = stdout.splitlines()
    assert 'Sent 20 bytes to the kernel.' == stdout_split.pop(0)
    for index, name in ifacesi:
        assert 'Found network interface {0}: {1}'.format(index, name) == stdout_split.pop(0)
    assert not stdout_split


@pytest.mark.skipif('not os.path.exists("/sys/class/net/wlan0")')
def test_show_wifi_interface_all():
    path = os.path.join(os.path.dirname(__file__), '..', 'example_show_wifi_interface.py')
    stdout = subprocess.check_output([sys.executable, path, 'print'])
    if hasattr(stdout, 'decode'):
        stdout = stdout.decode('ascii')
    assert 'NL80211_ATTR_MAC' in stdout


@pytest.mark.skipif('not os.path.exists("/sys/class/net/wlan0")')
def test_show_wifi_interface_wlan0():
    path = os.path.join(os.path.dirname(__file__), '..', 'example_show_wifi_interface.py')
    stdout = subprocess.check_output([sys.executable, path, 'print', 'wlan0'])
    if hasattr(stdout, 'decode'):
        stdout = stdout.decode('ascii')
    assert 'NL80211_ATTR_MAC' in stdout
