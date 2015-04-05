import socket

from libnl.linux_private.netlink import NETLINK_ROUTE
from libnl.misc import msghdr
from libnl.msg import nlmsg_alloc_simple
from libnl.nl import nl_complete_msg, nl_connect, nl_sendmsg
from libnl.socket_ import nl_socket_alloc, nl_socket_free


def test_default(tcp_server):
    """C code to test against.

    // gcc a.c $(pkg-config --cflags --libs libnl-genl-3.0)
    // (nc -l 2000 &); sleep 0.1; ./a.out
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
        struct nl_msg *msg = nlmsg_alloc_simple(0, 0);
        nl_connect(sk, NETLINK_ROUTE);
        sk->s_fd = fd;
        sk->s_local.nl_pid = 0;
        nl_complete_msg(sk, msg);

        char message[] = "Hello World!\n";
        struct iovec iov = { .iov_base = message, .iov_len = sizeof(message), };
        struct msghdr hdr = { .msg_iov = &iov, .msg_iovlen = 1, };

        int ret = nl_sendmsg(sk, msg, &hdr);
        printf("Bytes: %d\n", ret);  // 14
        return 0;
    }
    // Expected bash output:
    // Hello World!
    // Bytes: 14
    """
    sk = nl_socket_alloc()
    msg = nlmsg_alloc_simple(0, 0)
    nl_connect(sk, NETLINK_ROUTE)
    sk.socket_instance.close()
    sk.socket_instance = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.socket_instance.connect(tcp_server.server.server_address)
    sk.s_local.nl_pid = 0
    nl_complete_msg(sk, msg)

    message = 'Hello World!\n\0'
    iov = bytes(message.encode('ascii'))
    hdr = msghdr(msg_iov=iov)

    assert 14 == nl_sendmsg(sk, msg, hdr)
    assert [iov] == tcp_server.data
    nl_socket_free(sk)


def test_error_nle_bad_sock():
    sk = nl_socket_alloc()
    msg = nlmsg_alloc_simple(0, 0)
    nl_connect(sk, NETLINK_ROUTE)
    sk.socket_instance.close()
    nl_complete_msg(sk, msg)

    message = 'Hello World!\n'
    iov = bytes(message.encode('ascii'))
    hdr = msghdr(msg_iov=iov)

    assert -3 == nl_sendmsg(sk, msg, hdr)
