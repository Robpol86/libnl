import os
import subprocess
import sys


def test_list_network_interfaces(ifacesi):
    path = os.path.join(os.path.dirname(__file__), '..', '..', 'example_list_network_interfaces.py')
    stdout = subprocess.check_output([sys.executable, path, 'print']).decode('ascii').splitlines()
    assert 'Sent 20 bytes to the kernel.' == stdout.pop(0)
    for index, name in ifacesi:
        assert 'Found network interface {0}: {1}'.format(index, name) == stdout.pop(0)
    assert not stdout
