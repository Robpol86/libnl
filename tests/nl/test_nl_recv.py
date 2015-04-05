import binascii
import re
import sys

from libnl.linux_private.netlink import NETLINK_ROUTE, NLM_F_REQUEST, sockaddr_nl
from libnl.nl import nl_connect, nl_recv, nl_send_simple
from libnl.socket_ import nl_socket_alloc, nl_socket_free


if sys.version_info[:2] >= (2, 7):
    buffer = bytearray


def test_nl_recv():
    """C code to test against.

    // gcc a.c $(pkg-config --cflags --libs libnl-genl-3.0) && ./a.out
    #include <netlink/msg.h>
    struct nl_sock {
        struct sockaddr_nl s_local; struct sockaddr_nl s_peer; int s_fd; int s_proto; unsigned int s_seq_next;
        unsigned int s_seq_expect; int s_flags; struct nl_cb *s_cb; size_t s_bufsize;
    };
    int main() {
        // Send data to the kernel.
        struct nl_sock *sk = nl_socket_alloc();
        sk->s_seq_next = 0;
        nl_connect(sk, NETLINK_ROUTE);
        int ret = nl_send_simple(sk, 0, NLM_F_REQUEST, NULL, 0);
        printf("Bytes Sent: %d\n", ret);

        // Retrieve kernel's response.
        // nl_recvmsgs_default(sk);
        // return 0;
        unsigned char *buf = NULL;
        struct sockaddr_nl nla = {0};
        printf("%d == nla.nl_family\n", nla.nl_family);
        int n = nl_recv(sk, &nla, &buf, NULL);
        printf("Bytes Recv: %d\n", n);

        int i = 0; for (i = 0; i<n; i++) printf("%02x", buf[i]); printf("\n");
        printf("%d == nla.nl_family\n", nla.nl_family);
        return 0;
    }
    // Expected output:
    // Bytes Sent: 16
    // 0 == nla.nl_family
    // Bytes Recv: 36
    // 240000000200000000000000844c000000000000100000000000050000000000844c0000
    // 16 == nla.nl_family
    // Output delta:
    // 240000000200000000000000ac4e000000000000100000000000050000000000ac4e0000
    """
    sk = nl_socket_alloc()
    sk.s_seq_next = 0
    nl_connect(sk, NETLINK_ROUTE)
    assert 16 == nl_send_simple(sk, 0, NLM_F_REQUEST, None)

    buf = bytearray()
    nla = sockaddr_nl()
    assert 0 == nla.nl_family
    assert 36 == nl_recv(sk, nla, buf, None)
    nl_socket_free(sk)

    buf_hex = binascii.hexlify(buffer(buf)).decode('ascii')
    assert re.match(r'240000000200000000000000....000000000000100000000000050000000000....0000', buf_hex)
    assert 16 == nla.nl_family
