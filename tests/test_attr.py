import base64
import ctypes
import socket
import string

import pytest

from libnl.attr import (nla_put_u32, nla_get_u32, nla_type, nla_put_u8, nla_put_u16, nla_put_u64, nla_get_u8,
                        nla_get_u16, nla_get_u64, nla_get_flag, nla_put_flag, nla_put_string, nla_get_string,
                        nla_put_msecs, nla_get_msecs, nla_put_nested, nla_for_each_nested)
from libnl.linux_private.netlink import NETLINK_ROUTE
from libnl.misc import msghdr
from libnl.msg import nlmsg_alloc, nlmsg_hdr, nlmsg_find_attr, nlmsg_for_each_attr
from libnl.nl import nl_sendmsg, nl_connect, nl_complete_msg
from libnl.socket_ import nl_socket_alloc, nl_socket_free


def test_nla_put_get_u32():
    """// gcc $(pkg-config --cflags --libs libnl-genl-3.0) a.c && ./a.out
    #include <netlink/msg.h>
    int main() {
        int rem, i, range[] = { 0, 1, 2, 19, 20, 50 };
        struct nl_msg *msg = nlmsg_alloc();
        struct nlmsghdr *nlh = nlmsg_hdr(msg);
        struct nlattr *nla;
        for (i = 0; i < (sizeof(range) / sizeof(int)); i++) nla_put_u32(msg, i, range[i]);
        nlmsg_for_each_attr(nla, nlh, 0, rem) printf("type: %d; nla_get_u32: %d\n", nla_type(nla), nla_get_u32(nla));
        nlmsg_free(msg);
        return 0;
    }
    // Expected output:
    // type: 0; nla_get_u32: 0
    // type: 1; nla_get_u32: 1
    // type: 2; nla_get_u32: 2
    // type: 3; nla_get_u32: 19
    // type: 4; nla_get_u32: 20
    // type: 5; nla_get_u32: 50
    """
    range_ = (0, 1, 2, 19, 20, 50)
    msg = nlmsg_alloc()
    for i in range(len(range_)):
        nla_put_u32(msg, i, range_[i])
    nlh = nlmsg_hdr(msg)
    i = 0
    for nla in nlmsg_for_each_attr(nlh):
        assert i == nla_type(nla)
        assert range_[i] == nla_get_u32(nla)
        i += 1


def test_socket(tcp_server):
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
    attr = nlmsg_find_attr(nlh, 0, 4)
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


def test_ints():
    msg = nlmsg_alloc()
    assert 0 == nla_put_u8(msg, 2, 10)
    assert 0 == nla_put_u16(msg, 3, 11)
    assert 0 == nla_put_u32(msg, 4, 12)
    assert 0 == nla_put_u64(msg, 5, 13195)

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 0, 2)
    assert 2 == nla_type(attr)
    assert 10 == nla_get_u8(attr)
    assert 5 == attr.nla_len
    assert b'BQACAAo=' == base64.b64encode(bytes(attr)[:attr.nla_len])

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 0, 3)
    assert 3 == nla_type(attr)
    assert 11 == nla_get_u16(attr)
    assert 6 == attr.nla_len
    assert b'BgADAAsA' == base64.b64encode(bytes(attr)[:attr.nla_len])

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 0, 4)
    assert 4 == nla_type(attr)
    assert 12 == nla_get_u32(attr)
    assert 8 == attr.nla_len
    assert b'CAAEAAwAAAA=' == base64.b64encode(bytes(attr)[:attr.nla_len])

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 0, 5)
    assert 5 == nla_type(attr)
    assert 13195 == nla_get_u64(attr)  # printf("%llu\n", nla_get_u64(attr));
    assert 12 == attr.nla_len
    assert b'DAAFAIszAAAAAAAA' == base64.b64encode(bytes(attr)[:attr.nla_len])


def test_flag():
    msg = nlmsg_alloc()
    assert 0 == nla_put_flag(msg, 7)

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 0, 7)
    assert 7 == nla_type(attr)
    assert nla_get_flag(attr) is True  # printf("%s\n", nla_get_flag(attr) ? "True" : "False");
    assert 4 == attr.nla_len
    assert b'BAAHAA==' == base64.b64encode(bytes(attr)[:attr.nla_len])


def test_msecs():
    msg = nlmsg_alloc()
    assert 0 == nla_put_msecs(msg, 12, 99)

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 0, 12)
    assert 12 == nla_type(attr)
    assert 99 == nla_get_msecs(attr)
    assert 12 == attr.nla_len
    assert b'DAAMAGMAAAAAAAAA' == base64.b64encode(bytes(attr)[:attr.nla_len])


def test_string_short():
    payload = bytes('test'.encode('ascii'))
    msg = nlmsg_alloc()
    assert 0 == nla_put_string(msg, 6, payload)

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 0, 6)
    assert 6 == nla_type(attr)
    assert payload == nla_get_string(attr)
    assert 9 == attr.nla_len
    assert b'CQAGAHRlc3QA' == base64.b64encode(bytes(attr)[:attr.nla_len])


def test_string_medium():
    payload = bytes('The quick br()wn f0x jumps over the l@zy dog!'.encode('ascii'))
    msg = nlmsg_alloc()
    assert 0 == nla_put_string(msg, 6, payload)

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 0, 6)
    assert 6 == nla_type(attr)
    assert payload == nla_get_string(attr)
    assert 50 == attr.nla_len
    expected = b'MgAGAFRoZSBxdWljayBicigpd24gZjB4IGp1bXBzIG92ZXIgdGhlIGxAenkgZG9nIQA='
    assert expected == base64.b64encode(bytes(attr)[:attr.nla_len])


def test_string_long():
    payload = bytes(string.printable[:-2].encode('ascii'))
    msg = nlmsg_alloc()
    assert 0 == nla_put_string(msg, 6, payload)

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 0, 6)
    assert 6 == nla_type(attr)
    assert payload == nla_get_string(attr)
    assert 103 == attr.nla_len
    expected = (b'ZwAGADAxMjM0NTY3ODlhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ekFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaISIjJCUmJygp'
                b'KissLS4vOjs8PT4/QFtcXV5fYHt8fX4gCQoNAA==')
    assert expected == base64.b64encode(bytes(attr)[:attr.nla_len])


@pytest.mark.skipif('True')
def test_addr():
    msg = nlmsg_alloc()
    assert 0 == nla_put_addr(msg, 1, '127.0.0.1')

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 0, 1)
    assert 1 == nla_type(attr)
    assert '127.0.0.1' == nla_get_addr(attr)
    assert 4 == attr.nla_len
    assert b'' == base64.b64encode(bytes(attr)[:attr.nla_len])


@pytest.mark.skipif('True')
def test_data():
    msg = nlmsg_alloc()
    assert 0 == nla_put_data(msg, 0, ctypes.c_float(3.14))

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 0, 0)
    assert 0 == nla_type(attr)
    assert c_float(3.14).value == nla_get_data(attr)
    assert 4 == attr.nla_len
    assert b'' == base64.b64encode(bytes(attr)[:attr.nla_len])


def test_nested():
    """// gcc $(pkg-config --cflags --libs libnl-genl-3.0) a.c && ./a.out
    #include <netlink/msg.h>
    int main() {
        struct nl_msg *msg = nlmsg_alloc();
        struct nl_msg *sub = nlmsg_alloc();
        nla_put_string(sub, 2, "sub level A");
        nla_put_string(sub, 3, "sub level B");
        nla_put_string(sub, 6, "sub level C");
        nla_put_nested(msg, 9, sub);
        nlmsg_free(sub);

        struct nlattr *nla, *nla_outer;
        struct nlmsghdr *nlh = nlmsg_hdr(msg);
        int rem;
        nlmsg_for_each_attr(nla_outer, nlh, 0, rem) {
            printf("Outer type: %d\n", nla_type(nla_outer));
            nla_for_each_nested(nla, nla_outer, rem) {
                printf("type: %d; nla_get_string: %s\n", nla_type(nla), nla_get_string(nla));
            }
        }

        nlmsg_free(msg);
        return 0;
    }
    // Expected output:
    // Outer type: 9
    // type: 2; nla_get_string: sub level A
    // type: 3; nla_get_string: sub level B
    // type: 6; nla_get_string: sub level C
    """
    msg = nlmsg_alloc()
    sub = nlmsg_alloc()
    nla_put_string(sub, 2, b'sub level A')
    nla_put_string(sub, 3, b'sub level B')
    nla_put_string(sub, 6, b'sub level C')
    nla_put_nested(msg, 9, sub)

    actual = dict()
    nlh = nlmsg_hdr(msg)
    for nla_outer in nlmsg_for_each_attr(nlh):
        actual[nla_type(nla_outer)] = b'Outer'
        for nla in nla_for_each_nested(nla_outer):
            actual[nla_type(nla)] = nla_get_string(nla)
    expected = {
        9: b'Outer',
        2: b'sub level A',
        3: b'sub level B',
        6: b'sub level C',
    }
    assert expected == actual


@pytest.mark.skipif('True')
def test_same_attrtype():
    pass


@pytest.mark.skipif('True')
def test_nla_get_wrong_type():
    pass
