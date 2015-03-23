import base64
import socket

import libnl.socket_
from libnl.linux_private.netlink import NETLINK_ROUTE, NLM_F_DUMP, NLM_F_REQUEST, NLMSG_ALIGNTO
from libnl.linux_private.rtnetlink import rtgenmsg, RTM_GETLINK
from libnl.msg import nlmsg_alloc_simple, nlmsg_append, nlmsg_hdr
from libnl.nl import nl_complete_msg, nl_connect, nl_send_simple
from libnl.socket_ import nl_socket_alloc, nl_socket_free


def test_bare(tcp_server, monkeypatch):
    """// gcc a.c $(pkg-config --cflags --libs libnl-genl-3.0) && (nc -l 2000 |base64 &) && sleep 0.1 && ./a.out
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
        nl_connect(sk, NETLINK_ROUTE);
        sk->s_fd = fd;
        sk->s_local.nl_pid = 0;
        sk->s_seq_next = 0;

        int ret = nl_send_simple(sk, RTM_GETLINK, 0, NULL, 0);

        printf("Bytes: %d\n", ret);
        return 0;
    }
    // Expected bash output:
    // Bytes: 16
    // EAAAABIABQAAAAAAAAAAAA==
    """
    monkeypatch.setattr(libnl.socket_, 'generate_local_port', lambda: 0)

    sk = nl_socket_alloc()
    nl_connect(sk, NETLINK_ROUTE)
    sk.socket_instance.close()
    sk.socket_instance = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.socket_instance.connect(tcp_server.server.server_address)
    sk.s_local.nl_pid = 0
    sk.s_seq_next = 0

    assert 16 == nl_send_simple(sk, RTM_GETLINK, 0, None)
    assert 1 == len(tcp_server.data)
    assert b'EAAAABIABQAAAAAAAAAAAA==' == base64.b64encode(tcp_server.data[0])
    nl_socket_free(sk)


def test_dissect(monkeypatch):
    """
    --- test_bare.c	2015-02-08 12:43:15.543135855 -0800
    +++ test_dissect.c	2015-02-08 13:25:31.375715668 -0800
    @@ -16,8 +16,22 @@
             sk->s_local.nl_pid = 0;
             sk->s_seq_next = 0;

    -        int ret = nl_send_simple(sk, RTM_GETLINK, 0, NULL, 0);
    +        struct rtgenmsg rt_hdr = { .rtgen_family = AF_PACKET, };
    +        struct nl_msg *msg = nlmsg_alloc_simple(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP);
    +        nlmsg_append(msg, &rt_hdr, sizeof(rt_hdr), NLMSG_ALIGNTO);
    +        nl_complete_msg(sk, msg);
    +        struct nlmsghdr *nlh = nlmsg_hdr(msg);

    +        printf("%d == nlh->nlmsg_len\n", nlh->nlmsg_len);
    +        printf("%d == nlh->nlmsg_type\n", nlh->nlmsg_type);
    +        printf("%d == nlh->nlmsg_flags\n", nlh->nlmsg_flags);
    +        printf("%d == nlh->nlmsg_seq\n", nlh->nlmsg_seq);
    +        printf("%d == nlh->nlmsg_pid\n", nlh->nlmsg_pid);
    +
    +        struct iovec iov = { .iov_base = nlh, .iov_len = nlh->nlmsg_len };
    +        struct msghdr hdr = { .msg_iov = &iov, .msg_iovlen = 1, };
    +
    +        int ret = nl_sendmsg(sk, msg, &hdr);
             printf("Bytes: %d\n", ret);
             return 0;
         }
    """
    monkeypatch.setattr(libnl.socket_, 'generate_local_port', lambda: 0)

    sk = nl_socket_alloc()
    nl_connect(sk, NETLINK_ROUTE)
    sk.socket_instance.close()
    sk.s_local.nl_pid = 0
    sk.s_seq_next = 0

    rt_hdr = rtgenmsg(rtgen_family=socket.AF_PACKET)
    msg = nlmsg_alloc_simple(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP)
    nlmsg_append(msg, rt_hdr, rt_hdr.SIZEOF, NLMSG_ALIGNTO)
    nl_complete_msg(sk, msg)
    nlh = nlmsg_hdr(msg)

    assert 20 == nlh.nlmsg_len
    assert 18 == nlh.nlmsg_type
    assert 773 == nlh.nlmsg_flags
    assert 0 == nlh.nlmsg_seq
    assert 0 == nlh.nlmsg_pid

    assert b'FAAAABIABQMAAAAAAAAAABEAAAA=' == base64.b64encode(nlh.bytearray[:nlh.nlmsg_len])
    nl_socket_free(sk)


def test_full(tcp_server, monkeypatch):
    """
    --- test_bare.c	2015-02-08 12:43:15.543135855 -0800
    +++ test_full.c	2015-02-08 12:43:08.533183752 -0800
    @@ -13,10 +13,11 @@
             struct nl_sock *sk = nl_socket_alloc();
             nl_connect(sk, NETLINK_ROUTE);
             sk->s_fd = fd;
    -        sk->s_local.nl_pid = 0;
    -        sk->s_seq_next = 0;
    +        sk->s_local.nl_pid = 1234;
    +        sk->s_seq_next = 10;

    -        int ret = nl_send_simple(sk, RTM_GETLINK, 0, NULL, 0);
    +        struct rtgenmsg rt_hdr = { .rtgen_family = AF_PACKET, };
    +        int ret = nl_send_simple(sk, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, &rt_hdr, sizeof(rt_hdr));

             printf("Bytes: %d\n", ret);
             return 0;
    """
    monkeypatch.setattr(libnl.socket_, 'generate_local_port', lambda: 1234)

    sk = nl_socket_alloc()
    nl_connect(sk, NETLINK_ROUTE)
    sk.socket_instance.close()
    sk.socket_instance = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.socket_instance.connect(tcp_server.server.server_address)
    sk.s_local.nl_pid = 1234
    sk.s_seq_next = 10
    rt_hdr = rtgenmsg(rtgen_family=socket.AF_PACKET)

    assert 20 == nl_send_simple(sk, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, rt_hdr, rt_hdr.SIZEOF)
    assert 1 == len(tcp_server.data)
    assert b'FAAAABIABQMKAAAA0gQAABEAAAA=' == base64.b64encode(tcp_server.data[0])
    nl_socket_free(sk)
