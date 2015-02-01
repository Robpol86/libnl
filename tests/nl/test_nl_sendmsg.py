import base64
import re
from socket import AF_INET, AF_PACKET, NETLINK_ROUTE, SOCK_STREAM, socket
import socketserver
import threading

import pytest

from libnl.linux_private.netlink import NLM_F_REQUEST, NLM_F_DUMP
from libnl.linux_private.rtnetlink import rtgenmsg, RTM_GETLINK
from libnl.nl import nl_connect, nl_send_simple
from libnl.socket_ import nl_socket_alloc, nl_socket_free


class TCPHandler(socketserver.BaseRequestHandler):
    DATA = ''

    def handle(self):
        data = self.request.recv(25)
        self.DATA = base64.b64encode(data)


@pytest.mark.skipif('True')
def test_sendmsg(request):
    """// gcc $(pkg-config --cflags --libs libnl-genl-3.0) a.c
    // for i in {1..10}; do (nc -l 2000 &); sleep 0.1; ./a.out; done
    #include <netlink/msg.h>
    struct nl_sock {
        struct sockaddr_nl s_local; struct sockaddr_nl s_peer; int s_fd; int s_proto; unsigned int s_seq_next;
        unsigned int s_seq_expect; int s_flags; struct nl_cb *s_cb; size_t s_bufsize;
    };
    int main() {
        struct sockaddr_in sin = { .sin_port = htons(2000), .sin_family = AF_INET, };
        sin.sin_addr.s_addr = inet_addr("127.0.0.1");
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        connect(fd, (struct sockaddr *) &sin, sizeof(sin));
        struct nl_sock *sk = nl_socket_alloc();
        nl_connect(sk, NETLINK_ROUTE);  // Create file descriptor and bind socket.
        sk->s_fd = fd;
        sk->s_local.nl_pid = 0;
        struct msghdr hdr = {
            .msg_name = (void *) &sk->s_peer, .msg_namelen = sizeof(struct sockaddr_nl), .msg_iov = iov,
            .msg_iovlen = iovlen,
        };
        int ret = nl_sendmsg(sk, msg, &hdr);
        printf("Bytes: %d\n", ret);  // 20
        return 0;
    }
    // Expected bash for loop output (should regex match FAAAABIABQO\wSs1UAAAAABEAAAA):
    // FAAAABIABQOqSs1UAAAAABEAAAA=
    // FAAAABIABQOrSs1UAAAAABEAAAA=
    // FAAAABIABQOrSs1UAAAAABEAAAA=
    // FAAAABIABQOrSs1UAAAAABEAAAA=
    // FAAAABIABQOrSs1UAAAAABEAAAA=
    // FAAAABIABQOrSs1UAAAAABEAAAA=
    // FAAAABIABQOrSs1UAAAAABEAAAA=
    // FAAAABIABQOsSs1UAAAAABEAAAA=
    // FAAAABIABQOsSs1UAAAAABEAAAA=
    // FAAAABIABQOsSs1UAAAAABEAAAA=
    """
    server = socketserver.TCPServer(('', 0), TCPHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    sk = nl_socket_alloc()
    nl_connect(sk, NETLINK_ROUTE)
    sk.socket_instance.close()
    sk.socket_instance = socket(AF_INET, SOCK_STREAM)
    sk.socket_instance.connect(server.server_address)
    sk.s_local.nl_pid = 0

    def fin():
        server.socket.close()
        nl_socket_free(sk)
    request.addfinalizer(fin)

    rt_hdr = rtgenmsg(rtgen_family=AF_PACKET)
    assert 20 == nl_send_simple(sk, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, rt_hdr)
    assert re.match(r'^FAAAABIABQO\wSs1UAAAAABEAAAA$', TCPHandler.DATA)


@pytest.mark.skipif('True')
def test_error_nle_bad_sock():
    pass


@pytest.mark.skipif('True')
def test_error_cb_not_nl_ok():
    pass


@pytest.mark.skipif('True')
def test_error_nlerr():
    pass


@pytest.mark.skipif('True')
def test_nl_cb_msg_out():
    pass
