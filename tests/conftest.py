import json
import os
import socketserver
import threading
import time

import pytest


@pytest.fixture(scope='session')
def correct_answers():
    json_file_path = os.path.join(os.path.dirname(__file__), 'correct_answers.json')
    if not os.path.exists(json_file_path):
        raise RuntimeError('Missing correct_answers.json! Compile and run correct_answers.c, redirect stdout.')
    with open(json_file_path) as f:
        contents = f.read(10000)
    parsed = json.loads(contents)
    return parsed


@pytest.fixture(scope='function')
def tcp_server(request):
    """Starts up a TCP server in a thread."""
    data = list()

    class Getter(object):
        def __init__(self, t, s, d):
            self.thread = t
            self.server =s
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
