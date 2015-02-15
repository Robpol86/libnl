import re

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

        nl_socket_free(sk);
        return 0;
    }
    // Expected output (trimmed):
    // nl_cache_mngt_register: Registered cache operations genl/family
    // Begin main()
    // Allocated socket.
    // 0 == nl_connect(sk, NETLINK_ROUTE)
    // __nlmsg_alloc: msg 0x3df0b8: Allocated new message, maxlen=4096
    // nlmsg_alloc_simple: msg 0x3df0b8: Allocated new simple message
    // -- Debug: Sent Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 16
    //     .type = 0 <0x0>
    //     .flags = 5 <REQUEST,ACK>
    //     .seq = 1423967746
    //     .port = 29930
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // nl_sendmsg: sent 16 bytes
    // nlmsg_free: Returned message reference 0x3df0b8, 0 remaining
    // nlmsg_free: msg 0x3df0b8: Freed
    // Bytes Sent: 16
    // recvmsgs: Attempting to read from 0x3df080
    // recvmsgs: recvmsgs(0x3df080): Read 36 bytes
    // recvmsgs: recvmsgs(0x3df080): Processing valid message...
    // __nlmsg_alloc: msg 0x3e30c0: Allocated new message, maxlen=36
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
    // __nlmsg_alloc: msg 0x3e3128: Allocated new message, maxlen=4096
    //     .nlmsg_len = 16
    //     .type = 0 <0x0>
    //     .flags = 5 <REQUEST,ACK>
    //     .seq = 1423967746
    //     .port = 29930
    // nlmsg_free: Returned message reference 0x3e3128, 0 remaining
    // nlmsg_free: msg 0x3e3128: Freed
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // recvmsgs: recvmsgs(0x3df080): Increased expected sequence number to 1423967746
    // -- Debug: ACK: type=ERROR length=36 flags=<> sequence-nr=1423967746 pid=29930
    // nlmsg_free: Returned message reference 0x3e30c0, 0 remaining
    // nlmsg_free: msg 0x3e30c0: Freed
    // 0 == nl_recvmsgs_default(sk)
    // nl_cache_mngt_unregister: Unregistered cache operations genl/family
    """
    log.clear()
    sk = nl_socket_alloc()
    nl_connect(sk, NETLINK_ROUTE)
    assert 16 == nl_send_simple(sk, 0, NLM_F_REQUEST, None)

    assert re.match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message', log.pop(0))
    assert re.match('nlmsg_alloc_simple: msg 0x[a-f0-9]+: Allocated new simple message', log.pop(0))
    assert 'nl_msg_out_handler_debug: -- Debug: Sent Message:' == log.pop(0)
    assert 'nl_msg_dump: --------------------------   BEGIN NETLINK MESSAGE ---------------------------' == log.pop(0)
    assert 'nl_msg_dump:   [NETLINK HEADER] 16 octets' == log.pop(0)
    assert 'print_hdr:     .nlmsg_len = 16' == log.pop(0)
    assert 'print_hdr:     .type = 0 <0x0>' == log.pop(0)
    assert 'print_hdr:     .flags = 5 <REQUEST,ACK>' == log.pop(0)
    assert re.match('print_hdr:     .seq = \d+', log.pop(0))
    assert re.match('print_hdr:     .port = \d+', log.pop(0))
    assert 'nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------' == log.pop(0)
    assert 'nl_sendmsg: sent 16 bytes' == log.pop(0)
    assert not log

    assert 0 == nl_recvmsgs_default(sk)
    assert re.match('recvmsgs: Attempting to read from 0x[a-f0-9]+', log.pop(0))
    assert re.match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Read 36 bytes', log.pop(0))
    assert re.match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Processing valid message...', log.pop(0))
    assert re.match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message', log.pop(0))
    assert 'nl_msg_in_handler_debug: -- Debug: Received Message:' == log.pop(0)
    assert 'nl_msg_dump: --------------------------   BEGIN NETLINK MESSAGE ---------------------------' == log.pop(0)
    assert 'nl_msg_dump:   [NETLINK HEADER] 16 octets' == log.pop(0)
    assert 'print_hdr:     .nlmsg_len = 36' == log.pop(0)
    assert 'print_hdr:     .type = 2 <ERROR>' == log.pop(0)
    assert 'print_hdr:     .flags = 0 <>' == log.pop(0)
    assert re.match('print_hdr:     .seq = \d+', log.pop(0))
    assert re.match('print_hdr:     .port = \d+', log.pop(0))
    assert 'dump_error_msg:   [ERRORMSG] 20 octets' == log.pop(0)
    assert 'dump_error_msg:     .error = 0 "Success"' == log.pop(0)
    assert 'dump_error_msg:   [ORIGINAL MESSAGE] 16 octets' == log.pop(0)
    assert re.match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message', log.pop(0))
    assert 'print_hdr:     .nlmsg_len = 16' == log.pop(0)
    assert 'print_hdr:     .type = 0 <0x0>' == log.pop(0)
    assert 'print_hdr:     .flags = 5 <REQUEST,ACK>' == log.pop(0)
    assert re.match('print_hdr:     .seq = \d+', log.pop(0))
    assert re.match('print_hdr:     .port = \d+', log.pop(0))
    assert 'nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------' == log.pop(0)
    assert re.match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Increased expected sequence number to \d+', log.pop(0))
    assert re.match('-- Debug: ACK: type=ERROR length=36 flags=<> sequence-nr=\d+ pid=\d+', log.pop(0))
    nl_socket_free(sk)
    assert not log
