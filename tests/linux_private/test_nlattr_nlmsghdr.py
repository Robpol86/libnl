import base64
import socket

import pytest

from libnl.attr import nla_put_u32, nla_get_u32, nla_type
from libnl.linux_private.netlink import NETLINK_ROUTE
from libnl.misc import msghdr
from libnl.msg import nlmsg_alloc, nlmsg_hdr, nlmsg_find_attr
from libnl.nl import nl_sendmsg, nl_connect, nl_complete_msg
from libnl.socket_ import nl_socket_alloc, nl_socket_free


def test_nlattr_u32(tcp_server):
    """// gcc $(pkg-config --cflags --libs libnl-genl-3.0) a.c && (nc -l 2000 |base64 &) && sleep 0.1 && ./a.out
    #include <netlink/msg.h>
    struct nl_sock {
        struct sockaddr_nl s_local; struct sockaddr_nl s_peer; int s_fd; int s_proto; unsigned int s_seq_next;
        unsigned int s_seq_expect; int s_flags; struct nl_cb *s_cb; size_t s_bufsize;
    };
    int main() {
        struct nl_msg *msg = nlmsg_alloc();
        printf("%d == nla_put_u32()\n", nla_put_u32(msg, 4, 8));
        struct nlmsghdr *nlh = nlmsg_hdr(msg);
        struct nlattr *attr = nlmsg_find_attr(nlh, 0, 4);
        printf("%d == nla_type(attr)\n", nla_type(attr));
        printf("%d == nla_get_u32(attr)\n", nla_get_u32(attr));
        printf("%d == attr->nla_len\n", attr->nla_len);

        struct sockaddr_in sin = { .sin_port = htons(2000), .sin_family = AF_INET, };
        sin.sin_addr.s_addr = inet_addr("127.0.0.1");
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        connect(fd, (struct sockaddr *) &sin, sizeof(sin));

        struct nl_sock *sk = nl_socket_alloc();
        nl_connect(sk, NETLINK_ROUTE);
        sk->s_fd = fd;
        sk->s_local.nl_pid = 0;
        nl_complete_msg(sk, msg);

        struct iovec iov = { .iov_base = attr, .iov_len = attr->nla_len };
        struct msghdr hdr = { .msg_iov = &iov, .msg_iovlen = 1, };

        int ret = nl_sendmsg(sk, msg, &hdr);
        printf("Bytes: %d\n", ret);  // 14
        return 0;
    }
    // Expected bash output:
    // 0 == nla_put_u32()
    // 4 == nla_type(attr)
    // 8 == nla_get_u32(attr)
    // 8 == attr->nla_len
    // Bytes: 8
    // CAAEAAgAAAA=
    """
    msg = nlmsg_alloc()
    assert 0 == nla_put_u32(msg, 4, 8)
    nlh = nlmsg_hdr(msg)
    attr = nlmsg_find_attr(nlh, 4)
    assert 4 == nla_type(attr)
    assert 8 == nla_get_u32(attr)

    sk = nl_socket_alloc()
    nl_connect(sk, NETLINK_ROUTE)
    sk.socket_instance.close()
    sk.socket_instance = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.socket_instance.connect(tcp_server.server.server_address)
    sk.s_local.nl_pid = 0
    nl_complete_msg(sk, msg)

    iov = bytes(attr)[:attr.nla_len]
    hdr = msghdr(msg_iov=iov)

    assert 8 == nl_sendmsg(sk, msg, hdr)
    assert 1 == len(tcp_server.data)
    assert b'CAAEAAgAAAA=' == base64.b64encode(tcp_server.data[0])
    nl_socket_free(sk)


@pytest.mark.skipif('True')
def test_nlattr_all_types():
    pass
