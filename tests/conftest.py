import fcntl
import importlib
import logging
import os
import socket
import socketserver
import struct
import threading
import time

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
    logging.basicConfig(format='%(funcName)s: %(message)s', level=logging.DEBUG, handlers=[ListHandler()])
    return log_statements


@pytest.fixture(scope='session')
def ifaces():
    """Returns tuple of network interfaces (by name)."""
    return tuple(i[1] for i in socket.if_nameindex())


@pytest.fixture(scope='session')
def ifacesi():
    """Returns tuple of tuples of network interfaces (by name) (second item) and their indexes (first item)."""
    return tuple(socket.if_nameindex())


@pytest.fixture(scope='function')
def nlcb_debug(request):
    """Sets the NLCB environment variable to 'debug' and reloads libnl.handlers to take effect."""
    os.environ['NLCB'] = 'debug'
    __import__('libnl').socket_.init_default_cb()
    importlib.reload(__import__('libnl').handlers)

    def fin():
        os.environ['NLCB'] = 'default'
        __import__('libnl').socket_.init_default_cb()
        importlib.reload(__import__('libnl').handlers)
    request.addfinalizer(fin)


@pytest.fixture(scope='function')
def nlcb_verbose(request):
    """Sets the NLCB environment variable to 'verbose' and reloads libnl.handlers to take effect."""
    os.environ['NLCB'] = 'verbose'
    __import__('libnl').socket_.init_default_cb()
    importlib.reload(__import__('libnl').handlers)

    def fin():
        os.environ['NLCB'] = 'default'
        __import__('libnl').socket_.init_default_cb()
        importlib.reload(__import__('libnl').handlers)
    request.addfinalizer(fin)


@pytest.fixture(scope='session')
def wlan0_info():
    """Returns a dict of data about the wlan0 interface, or an empty dict."""
    if not os.path.exists('/sys/class/net/wlan0'):
        return dict()
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data = dict()
    # Get MAC address, http://stackoverflow.com/a/4789267/1198943
    info = fcntl.ioctl(sk.fileno(), 0x8927,  struct.pack('256s', b'wlan0'))
    data['mac'] = ':'.join(format(x, '02x') for x in info[18:24])
    # Get ifindex, http://pydrcom.googlecode.com/svn-history/r2/trunk/pydrcom.py
    info = struct.unpack('16sI', fcntl.ioctl(sk.fileno(), 0x8933,  struct.pack('16sI', b'wlan0', 0)))
    data['ifindex'] = int(info[1])
    sk.close()
    return data
