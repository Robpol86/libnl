import pytest

from libnl.linux_private.netlink import NLM_F_REQUEST, NETLINK_ROUTE
from libnl.nl import nl_connect, nl_send_simple, nl_recvmsgs_default
from libnl.socket_ import nl_socket_alloc, nl_socket_free


@pytest.mark.skipif('True')
def test_nl_recvmsgs_default():
    """// gcc $(pkg-config --cflags --libs libnl-genl-3.0) a.c && ./a.out
    #include <netlink/msg.h>
    struct nl_sock {
        struct sockaddr_nl s_local; struct sockaddr_nl s_peer; int s_fd; int s_proto; unsigned int s_seq_next;
        unsigned int s_seq_expect; int s_flags; struct nl_cb *s_cb; size_t s_bufsize;
    };
    int main() {
        // Send data to the kernel.
        struct nl_sock *sk = nl_socket_alloc();
        nl_connect(sk, NETLINK_ROUTE);
        int ret = nl_send_simple(sk, 0, NLM_F_REQUEST, NULL, 0);
        printf("Bytes Sent: %d\n", ret);

        // Retrieve kernel's response.
        printf("%d == nl_recvmsgs_default(sk)\n", nl_recvmsgs_default(sk));

        return 0;
    }
    // Expected output:
    // Bytes Sent: 16
    // 0 == nl_recvmsgs_default(sk)
    """
    sk = nl_socket_alloc()
    nl_connect(sk, NETLINK_ROUTE)
    assert 16 == nl_send_simple(sk, 0, NLM_F_REQUEST, None)
    assert 0 == nl_recvmsgs_default(sk)
    nl_socket_free(sk)


@pytest.mark.skipif('True')
def test_nl_recvmsgs_default_error():
    """// gcc $(pkg-config --cflags --libs libnl-genl-3.0) a.c && ./a.out
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
        printf("%d == nl_recvmsgs_default(sk)\n", nl_recvmsgs_default(sk));

        return 0;
    }
    // Expected output:
    // Bytes Sent: 16
    // -16 == nl_recvmsgs_default(sk)
    """
    sk = nl_socket_alloc()
    sk.s_seq_next = 0
    nl_connect(sk, NETLINK_ROUTE)
    assert 16 == nl_send_simple(sk, 0, NLM_F_REQUEST, None)
    assert 0 == nl_recvmsgs_default(sk)
    nl_socket_free(sk)
