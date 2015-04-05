import fcntl
import imp
import logging
import os
import socket
import struct
import threading
import time

try:
    import socketserver
except ImportError:
    import SocketServer as socketserver

import pytest


@pytest.fixture(scope='function')
def tcp_server(request):
    """Starts up a TCP server in a thread."""
    data = list()

    class Getter(object):
        def __init__(self, t, s, d):
            self.thread = t
            self.server = s
            self._data = d

        @property
        def data(self):
            for i in range(50):
                if self._data:
                    break
                time.sleep(0.1)
            return self._data

    class TCPHandler(socketserver.BaseRequestHandler):
        def handle(self):
            data.append(self.request.recv(25))

    server = socketserver.TCPServer(('', 0), TCPHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    def fin():
        server.socket.close()
        server.shutdown()
        for _ in range(5):
            if not thread.is_alive():
                break
            time.sleep(0.2)
        assert not thread.is_alive()
    request.addfinalizer(fin)

    return Getter(thread, server, data)


@pytest.fixture(scope='session', autouse=True)
def log():
    """Stores libnl log statements in a list."""
    log_statements = list()

    class ListHandler(logging.StreamHandler):
        def emit(self, record):
            log_statements.append(self.format(record))
    handler = ListHandler()
    handler.setFormatter(logging.Formatter('%(funcName)s: %(message)s'))
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    return log_statements


@pytest.fixture(scope='function')
def nlcb_debug(request):
    """Sets the NLCB environment variable to 'debug' and reloads libnl.handlers to take effect."""
    os.environ['NLCB'] = 'debug'
    __import__('libnl').socket_.init_default_cb()
    imp.reload(__import__('libnl').handlers)

    def fin():
        os.environ['NLCB'] = 'default'
        __import__('libnl').socket_.init_default_cb()
        imp.reload(__import__('libnl').handlers)
    request.addfinalizer(fin)


@pytest.fixture(scope='function')
def nlcb_verbose(request):
    """Sets the NLCB environment variable to 'verbose' and reloads libnl.handlers to take effect."""
    os.environ['NLCB'] = 'verbose'
    __import__('libnl').socket_.init_default_cb()
    imp.reload(__import__('libnl').handlers)

    def fin():
        os.environ['NLCB'] = 'default'
        __import__('libnl').socket_.init_default_cb()
        imp.reload(__import__('libnl').handlers)
    request.addfinalizer(fin)


def all_indexes():
    """Returns dictionary of network interface names (values) and their indexes (keys)."""
    mapping = dict()
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for if_name in os.listdir('/sys/class/net'):
        # From: http://pydrcom.googlecode.com/svn-history/r2/trunk/pydrcom.py
        info = struct.unpack('16sI', fcntl.ioctl(sk.fileno(), 0x8933, struct.pack('16sI', if_name.encode('ascii'), 0)))
        mapping[int(info[1])] = if_name
    sk.close()
    return mapping


@pytest.fixture(scope='session')
def ifaces():
    """Returns tuple of network interfaces (by name)."""
    return tuple(i[1] for i in sorted(all_indexes().items()))


@pytest.fixture(scope='session')
def ifacesi():
    """Returns tuple of tuples of network interfaces (by name) (second item) and their indexes (first item)."""
    return tuple(sorted(all_indexes().items()))


@pytest.fixture(scope='session')
def wlan0_info():
    """Returns a dict of data about the wlan0 interface, or an empty dict."""
    if not os.path.exists('/sys/class/net/wlan0'):
        return dict()
    data = dict()
    # Get MAC address, http://stackoverflow.com/a/4789267/1198943
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(sk.fileno(), 0x8927, struct.pack('256s', b'wlan0'))
    sk.close()
    data['mac'] = ':'.join(format(x if hasattr(x, 'real') else ord(x), '02x') for x in info[18:24])
    # Get ifindex.
    data['ifindex'] = [k for k, v in all_indexes().items() if v == 'wlan0'][0]
    return data
