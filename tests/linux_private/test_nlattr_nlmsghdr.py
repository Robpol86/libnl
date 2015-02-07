import base64
from ctypes import c_float
import socket
import string

import pytest

from libnl.attr import (nla_put_u32, nla_get_u32, nla_type, nla_put_u8, nla_put_u16, nla_put_u64, nla_get_u8,
                        nla_get_u16, nla_get_u64, nla_get_flag, nla_put_flag, nla_put_string, nla_get_string,
                        nla_put_msecs, nla_get_msecs)
from libnl.linux_private.netlink import NETLINK_ROUTE
from libnl.misc import msghdr
from libnl.msg import nlmsg_alloc, nlmsg_hdr, nlmsg_find_attr
from libnl.nl import nl_sendmsg, nl_connect, nl_complete_msg
from libnl.socket_ import nl_socket_alloc, nl_socket_free


def test_nlattr_socket(tcp_server):
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
    assert 8 == attr.nla_len

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
    assert b'CAAEAAgAAAA=' == base64.b64encode(iov)
    assert b'CAAEAAgAAAA=' == base64.b64encode(tcp_server.data[0])
    nl_socket_free(sk)


def test_nlattr_ints():
    msg = nlmsg_alloc()
    assert 0 == nla_put_u8(msg, 2, 10)
    assert 0 == nla_put_u16(msg, 3, 11)
    assert 0 == nla_put_u32(msg, 4, 12)
    assert 0 == nla_put_u64(msg, 5, 13195)

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 2)
    assert 2 == nla_type(attr)
    assert 10 == nla_get_u8(attr)
    assert 5 == attr.nla_len
    assert b'BQACAAo=' == base64.b64encode(bytes(attr)[:attr.nla_len])

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 3)
    assert 3 == nla_type(attr)
    assert 11 == nla_get_u16(attr)
    assert 6 == attr.nla_len
    assert b'BgADAAsA' == base64.b64encode(bytes(attr)[:attr.nla_len])

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 4)
    assert 4 == nla_type(attr)
    assert 12 == nla_get_u32(attr)
    assert 8 == attr.nla_len
    assert b'CAAEAAwAAAA=' == base64.b64encode(bytes(attr)[:attr.nla_len])

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 5)
    assert 5 == nla_type(attr)
    assert 13195 == nla_get_u64(attr)  # printf("%llu\n", nla_get_u64(attr));
    assert 12 == attr.nla_len
    assert b'DAAFAIszAAAAAAAA' == base64.b64encode(bytes(attr)[:attr.nla_len])


def test_nlattr_flag():
    msg = nlmsg_alloc()
    assert 0 == nla_put_flag(msg, 7)

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 7)
    assert 7 == nla_type(attr)
    assert nla_get_flag(attr) is True  # printf("%s\n", nla_get_flag(attr) ? "True" : "False");
    assert 4 == attr.nla_len
    assert b'BAAHAA==' == base64.b64encode(bytes(attr)[:attr.nla_len])


def test_nlattr_msecs():
    msg = nlmsg_alloc()
    assert 0 == nla_put_msecs(msg, 12, 99)

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 12)
    assert 12 == nla_type(attr)
    assert 99 == nla_get_msecs(attr)
    assert 12 == attr.nla_len
    assert b'DAAMAGMAAAAAAAAA' == base64.b64encode(bytes(attr)[:attr.nla_len])


@pytest.mark.skipif('True')
def test_nlattr_string_short():
    payload = bytes('test'.encode('ascii'))
    msg = nlmsg_alloc()
    assert 0 == nla_put_string(msg, 6, payload)

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 6)
    assert 6 == nla_type(attr)
    assert payload == nla_get_string(attr)
    assert 9 == attr.nla_len
    assert b'CQAMAHRlc3QA' == base64.b64encode(bytes(attr)[:attr.nla_len])


@pytest.mark.skipif('True')
def test_nlattr_string_medium():
    payload = bytes('The quick br()wn f0x jumps over the l@zy dog!'.encode('ascii'))
    msg = nlmsg_alloc()
    assert 0 == nla_put_string(msg, 6, payload)

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 6)
    assert 6 == nla_type(attr)
    assert payload == nla_get_string(attr)
    assert 50 == attr.nla_len
    expected = b'MgAMAFRoZSBxdWljayBicigpd24gZjB4IGp1bXBzIG92ZXIgdGhlIGxAenkgZG9nIQA='
    assert expected == base64.b64encode(bytes(attr)[:attr.nla_len])


@pytest.mark.skipif('True')
def test_nlattr_string_long():
    payload = bytes(string.printable[:-2].encode('ascii'))
    msg = nlmsg_alloc()
    assert 0 == nla_put_string(msg, 6, payload)

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 6)
    assert 6 == nla_type(attr)
    assert payload == nla_get_string(attr)
    assert 103 == attr.nla_len
    expected = b'ZwAMADAxMjM0NTY3ODlhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ekFCQ0RFRkdISUpLTE1OT1BRQFtcXV5fYHt8fX4gCQoNAA=='
    assert expected == base64.b64encode(bytes(attr)[:attr.nla_len])


@pytest.mark.skipif('True')
def test_nlattr_addr():
    msg = nlmsg_alloc()
    assert 0 == nla_put_addr(msg, 1, '127.0.0.1')

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 1)
    assert 1 == nla_type(attr)
    assert '127.0.0.1' == nla_get_addr(attr)
    assert 4 == attr.nla_len
    assert b'' == base64.b64encode(bytes(attr)[:attr.nla_len])


@pytest.mark.skipif('True')
def test_nlattr_data():
    msg = nlmsg_alloc()
    assert 0 == nla_put_data(msg, 0, c_float(3.14))

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 0)
    assert 0 == nla_type(attr)
    assert c_float(3.14).value == nla_get_data(attr)
    assert 4 == attr.nla_len
    assert b'' == base64.b64encode(bytes(attr)[:attr.nla_len])


@pytest.mark.skipif('True')
def test_nlattr_nested():
    msg = nlmsg_alloc()
    assert 0 == nla_put_u8(msg, 2, 10)
    msg2 = nlmsg_alloc()
    assert 0 == nla_put_u32(msg2, 0, 18)
    assert 0 == nla_put_u32(msg2, 1, 19)
    assert 0 == nla_put_nested(msg, 9, msg2)


@pytest.mark.skipif('True')
def test_nlattr_same_attrtype():
    pass


@pytest.mark.skipif('True')
def test_nla_get_wrong_type():
    pass
