import logging
import os
import socketserver
import threading
import time

import pytest

os.environ.setdefault('NLCB', 'debug')


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
