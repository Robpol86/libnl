import base64
import ctypes
import socket

from libnl.attr import nla_put_u32, nla_put_u64
from libnl.linux_private.netlink import NETLINK_ROUTE, nlmsghdr
from libnl.misc import msghdr
from libnl.msg import nlmsg_alloc, nlmsg_hdr
from libnl.nl import nl_connect, nl_complete_msg, nl_sendmsg
from libnl.socket_ import nl_socket_alloc, nl_socket_free


def test_socket(tcp_server):
    """// gcc $(pkg-config --cflags --libs libnl-genl-3.0) a.c && (nc -l 2000 |base64 &) && sleep 0.1 && ./a.out
    #include <netlink/msg.h>
    struct nl_sock {
        struct sockaddr_nl s_local; struct sockaddr_nl s_peer; int s_fd; int s_proto; unsigned int s_seq_next;
        unsigned int s_seq_expect; int s_flags; struct nl_cb *s_cb; size_t s_bufsize;
    };
    int main() {
        struct nl_msg *msg = nlmsg_alloc();
        struct nlmsghdr *nlh = nlmsg_hdr(msg);
        printf("%d == nlh->nlmsg_len\n", nlh->nlmsg_len);
        printf("%d == nlh->nlmsg_type\n", nlh->nlmsg_type);
        printf("%d == nlh->nlmsg_flags\n", nlh->nlmsg_flags);
        printf("%d == nlh->nlmsg_seq\n", nlh->nlmsg_seq);
        printf("%d == nlh->nlmsg_pid\n", nlh->nlmsg_pid);

        struct sockaddr_in sin = { .sin_port = htons(2000), .sin_family = AF_INET, };
        sin.sin_addr.s_addr = inet_addr("127.0.0.1");
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        connect(fd, (struct sockaddr *) &sin, sizeof(sin));

        struct nl_sock *sk = nl_socket_alloc();
        nl_connect(sk, NETLINK_ROUTE);
        sk->s_fd = fd;
        sk->s_local.nl_pid = 0;
        sk->s_seq_next = 0;
        nl_complete_msg(sk, msg);
        printf("%d == nlh->nlmsg_seq\n", nlh->nlmsg_seq);

        struct iovec iov = { .iov_base = nlh, .iov_len = nlh->nlmsg_len };
        struct msghdr hdr = { .msg_iov = &iov, .msg_iovlen = 1, };

        int ret = nl_sendmsg(sk, msg, &hdr);
        printf("Bytes: %d\n", ret);
        return 0;
    }
    // Expected bash output:
    // 16 == nlh->nlmsg_len
    // 0 == nlh->nlmsg_type
    // 0 == nlh->nlmsg_flags
    // 0 == nlh->nlmsg_seq
    // 0 == nlh->nlmsg_pid
    // 0 == nlh->nlmsg_seq
    // Bytes: 16
    // EAAAAAAABQAAAAAAAAAAAA==
    """
    msg = nlmsg_alloc()
    nlh = nlmsg_hdr(msg)
    assert 16 == nlh.nlmsg_len
    assert 0 == nlh.nlmsg_type
    assert 0 == nlh.nlmsg_flags
    assert 0 == nlh.nlmsg_seq
    assert 0 == nlh.nlmsg_pid

    sk = nl_socket_alloc()
    nl_connect(sk, NETLINK_ROUTE)
    sk.socket_instance.close()
    sk.socket_instance = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.socket_instance.connect(tcp_server.server.server_address)
    sk.s_local.nl_pid = 0
    sk.s_seq_next = 0
    nl_complete_msg(sk, msg)
    assert 0 == nlh.nlmsg_seq
    nlh.nlmsg_pid = 0  # sk.s_local.nl_pid is read-only in Python.

    iov = bytes(nlh)[:nlh.nlmsg_len]
    hdr = msghdr(msg_iov=iov)

    assert 16 == nl_sendmsg(sk, msg, hdr)
    assert 1 == len(tcp_server.data)
    assert b'EAAAAAAABQAAAAAAAAAAAA==' == base64.b64encode(iov)
    assert b'EAAAAAAABQAAAAAAAAAAAA==' == base64.b64encode(tcp_server.data[0])
    nl_socket_free(sk)


def test_seq():
    msg = nlmsg_alloc()
    nlh = nlmsg_hdr(msg)
    assert 16 == nlh.nlmsg_len
    assert 0 == nlh.nlmsg_type
    assert 0 == nlh.nlmsg_flags
    assert 0 == nlh.nlmsg_seq
    assert 0 == nlh.nlmsg_pid

    sk = nl_socket_alloc()
    nl_connect(sk, NETLINK_ROUTE)
    sk.socket_instance.close()
    sk.s_local.nl_pid = 0
    nl_complete_msg(sk, msg)
    assert 1423351063 <= nlh.nlmsg_seq
    nlh.nlmsg_seq = 1423350947
    assert 1423350947 == nlh.nlmsg_seq
    nlh.nlmsg_pid = 0  # sk.s_local.nl_pid is read-only in Python.

    assert b'EAAAAAAABQCjnNZUAAAAAA==' == base64.b64encode(bytes(nlh)[:nlh.nlmsg_len])


def test_two_attrs():
    msg = nlmsg_alloc()
    assert 0 == nla_put_u32(msg, 4, 8)
    nlh = nlmsg_hdr(msg)
    assert 24 == nlh.nlmsg_len
    assert 0 == nlh.nlmsg_type
    assert 0 == nlh.nlmsg_flags
    assert 0 == nlh.nlmsg_seq
    assert 0 == nlh.nlmsg_pid
    assert 0 == nla_put_u64(msg, 5, 17)
    assert 36 == nlh.nlmsg_len

    sk = nl_socket_alloc()
    nl_connect(sk, NETLINK_ROUTE)
    sk.socket_instance.close()
    sk.s_local.nl_pid = 0
    sk.s_seq_next = 0
    nl_complete_msg(sk, msg)
    assert 0 == nlh.nlmsg_seq
    nlh.nlmsg_pid = 0  # sk.s_local.nl_pid is read-only in Python.

    assert b'JAAAAAAABQAAAAAAAAAAAAgABAAIAAAADAAFABEAAAAAAAAA' == base64.b64encode(bytes(nlh)[:nlh.nlmsg_len])


def test_from_buffer_no_attrs():
    nlh = nlmsghdr()
    nlh.nlmsg_type = 1
    nlh.nlmsg_flags = 20
    nlh.nlmsg_seq = 300
    nlh.nlmsg_pid = 4000

    assert 16 == nlh.nlmsg_len
    assert bytes(ctypes.c_uint16(1)) == bytes(getattr(nlh, '_nlmsg_type'))
    assert bytes(ctypes.c_uint16(20)) == bytes(getattr(nlh, '_nlmsg_flags'))
    assert bytes(ctypes.c_uint32(300)) == bytes(getattr(nlh, '_nlmsg_seq'))
    assert bytes(ctypes.c_uint32(4000)) == bytes(getattr(nlh, '_nlmsg_pid'))
    assert list() == nlh.payload

    buf = bytearray(bytes(nlh))
    nlh2 = nlmsghdr.from_buffer(buf)
    assert 16 == nlh2.nlmsg_len
    assert bytes(ctypes.c_uint16(1)) == bytes(getattr(nlh2, '_nlmsg_type'))
    assert bytes(ctypes.c_uint16(20)) == bytes(getattr(nlh2, '_nlmsg_flags'))
    assert bytes(ctypes.c_uint32(300)) == bytes(getattr(nlh2, '_nlmsg_seq'))
    assert bytes(ctypes.c_uint32(4000)) == bytes(getattr(nlh2, '_nlmsg_pid'))
    assert list() == nlh2.payload
