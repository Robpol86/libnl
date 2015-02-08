import base64
import socket

import pytest

from libnl.linux_private.netlink import NLM_F_REQUEST, NLM_F_DUMP, NETLINK_ROUTE
from libnl.linux_private.rtnetlink import rtgenmsg, RTM_GETLINK
from libnl.nl import nl_connect, nl_send_simple
from libnl.socket_ import nl_socket_alloc, nl_socket_free


@pytest.mark.skipif('True')
def test(tcp_server):
    """// gcc $(pkg-config --cflags --libs libnl-genl-3.0) a.c
    // (nc -l 2000 |base64 &); sleep 0.1; ./a.out
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
        sk->s_seq_next = 1;
        struct rtgenmsg rt_hdr = { .rtgen_family = AF_PACKET, };

        int ret = nl_send_simple(sk, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, &rt_hdr, sizeof(rt_hdr));
        // printf("Bytes: %d\n", ret);  // 20
        return 0;
    }
    // Expected bash output:
    // FAAAABIABQMBAAAAAAAAABEAAAA=
    """
    sk = nl_socket_alloc()
    nl_connect(sk, NETLINK_ROUTE)
    sk.socket_instance.close()
    sk.socket_instance = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.socket_instance.connect(tcp_server.server.server_address)
    sk.s_local.nl_pid = 0
    sk.s_seq_next = 1
    rt_hdr = rtgenmsg(rtgen_family=socket.AF_PACKET)

    assert 20 == nl_send_simple(sk, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, rt_hdr)
    assert 1 == len(tcp_server.data)
    assert b'FAAAABIABQMBAAAAAAAAABEAAAA=' == base64.b64encode(tcp_server.data[0])
    nl_socket_free(sk)
