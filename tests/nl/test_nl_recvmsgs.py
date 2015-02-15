import pytest

from libnl.linux_private.netlink import NLM_F_REQUEST, NETLINK_ROUTE
from libnl.nl import nl_connect, nl_send_simple, nl_recvmsgs_default
from libnl.socket_ import nl_socket_alloc, nl_socket_free


@pytest.mark.skipif('True')
def test_nl_recvmsgs_default(log):
    """// gcc $(pkg-config --cflags --libs libnl-genl-3.0) a.c && NLDBG=4 NLCB=debug ./a.out
    #include <netlink/msg.h>
    struct nl_sock {
        struct sockaddr_nl s_local; struct sockaddr_nl s_peer; int s_fd; int s_proto; unsigned int s_seq_next;
        unsigned int s_seq_expect; int s_flags; struct nl_cb *s_cb; size_t s_bufsize;
    };
    int main() {
        // Send data to the kernel.
        printf("Begin main()\n");
        struct nl_sock *sk = nl_socket_alloc();
        printf("Allocated socket.\n");
        printf("%d == nl_connect(sk, NETLINK_ROUTE)\n", nl_connect(sk, NETLINK_ROUTE));
        int ret = nl_send_simple(sk, 0, NLM_F_REQUEST, NULL, 0);
        printf("Bytes Sent: %d\n", ret);

        // Retrieve kernel's response.
        printf("%d == nl_recvmsgs_default(sk)\n", nl_recvmsgs_default(sk));

        return 0;
    }
    // Expected output (trimmed):
    // Registered cache operations genl/family
    // Begin main()
    // Allocated socket.
    // 0 == nl_connect(sk, NETLINK_ROUTE)
    // msg 0x10ae0b8: Allocated new message, maxlen=4096
    // msg 0x10ae0b8: Allocated new simple message
    // -- Debug: Sent Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 16
    //     .type = 0 <0x0>
    //     .flags = 5 <REQUEST,ACK>
    //     .seq = 1423967746
    //     .port = 29930
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // sent 16 bytes
    // Returned message reference 0x10ae0b8, 0 remaining
    // msg 0x10ae0b8: Freed
    // Bytes Sent: 16
    // Attempting to read from 0x10ae080
    // recvmsgs(0x10ae080): Read 36 bytes
    // recvmsgs(0x10ae080): Processing valid message...
    // msg 0x10b20c0: Allocated new message, maxlen=36
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 36
    //     .type = 2 <ERROR>
    //     .flags = 0 <>
    //     .seq = 1423967746
    //     .port = 29930
    //   [ERRORMSG] 20 octets
    //     .error = 0 "Success"
    //   [ORIGINAL MESSAGE] 16 octets
    // msg 0x10b2128: Allocated new message, maxlen=4096
    //     .nlmsg_len = 16
    //     .type = 0 <0x0>
    //     .flags = 5 <REQUEST,ACK>
    //     .seq = 1423967746
    //     .port = 29930
    // Returned message reference 0x10b2128, 0 remaining
    // msg 0x10b2128: Freed
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // recvmsgs(0x10ae080): Increased expected sequence number to 1423971272
    // -- Debug: ACK: type=ERROR length=36 flags=<> sequence-nr=1423967746 pid=29930
    // Returned message reference 0x10b20c0, 0 remaining
    // msg 0x10b20c0: Freed
    // 0 == nl_recvmsgs_default(sk)
    // Unregistered cache operations genl/family
    """
    log.clear()
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
