import re
import socket

import pytest

from libnl.linux_private.netlink import NLM_F_REQUEST, NETLINK_ROUTE, NLM_F_DUMP
from libnl.linux_private.rtnetlink import RTM_GETLINK, rtgenmsg
from libnl.nl import nl_connect, nl_send_simple, nl_recvmsgs_default
from libnl.socket_ import nl_socket_alloc, nl_socket_free


def match(expected, log, is_regex=False):
    log_statement = log.pop(0)
    if is_regex:
        assert re.match(expected, log_statement)
    else:
        assert expected == log_statement
    return True


@pytest.mark.usefixtures('nlcb_debug')
def test_error(log):
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

    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message', log, True)
    assert match('nlmsg_alloc_simple: msg 0x[a-f0-9]+: Allocated new simple message', log, True)
    assert match('nl_msg_out_handler_debug: -- Debug: Sent Message:', log)
    assert match('nl_msg_dump: --------------------------   BEGIN NETLINK MESSAGE ---------------------------', log)
    assert match('nl_msg_dump:   [NETLINK HEADER] 16 octets', log)
    assert match('print_hdr:     .nlmsg_len = 16', log)
    assert match('print_hdr:     .type = 0 <0x0>', log)
    assert match('print_hdr:     .flags = 5 <REQUEST,ACK>', log)
    assert match('print_hdr:     .seq = \d{10}', log, True)
    assert match('print_hdr:     .port = \d{4,}', log, True)
    assert match('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------', log)
    assert match('nl_sendmsg: sent 16 bytes', log)
    assert not log

    assert 0 == nl_recvmsgs_default(sk)
    assert match('recvmsgs: Attempting to read from 0x[a-f0-9]+', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Read 36 bytes', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Processing valid message...', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message', log, True)
    assert match('nl_msg_in_handler_debug: -- Debug: Received Message:', log)
    assert match('nl_msg_dump: --------------------------   BEGIN NETLINK MESSAGE ---------------------------', log)
    assert match('nl_msg_dump:   [NETLINK HEADER] 16 octets', log)
    assert match('print_hdr:     .nlmsg_len = 36', log)
    assert match('print_hdr:     .type = 2 <ERROR>', log)
    assert match('print_hdr:     .flags = 0 <>', log)
    assert match('print_hdr:     .seq = \d{10}', log, True)
    assert match('print_hdr:     .port = \d{4,}', log, True)
    assert match('dump_error_msg:   [ERRORMSG] 20 octets', log)
    assert match('dump_error_msg:     .error = 0 "Success"', log)
    assert match('dump_error_msg:   [ORIGINAL MESSAGE] 16 octets', log)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message', log, True)
    assert match('print_hdr:     .nlmsg_len = 16', log)
    assert match('print_hdr:     .type = 0 <0x0>', log)
    assert match('print_hdr:     .flags = 5 <REQUEST,ACK>', log)
    assert match('print_hdr:     .seq = \d{10}', log, True)
    assert match('print_hdr:     .port = \d{4,}', log, True)
    assert match('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------', log)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Increased expected sequence number to \d{4,}', log, True)
    assert match('nl_ack_handler_debug: -- Debug: ACK: type=ERROR length=36 flags=<> sequence-nr=\d{10,} pid=\d{4,}',
                 log, True)
    nl_socket_free(sk)
    assert not log


def multipart_eth0(log):
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Processing valid message...', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message', log, True)
    assert match('nl_msg_in_handler_debug: -- Debug: Received Message:', log)
    assert match('nl_msg_dump: --------------------------   BEGIN NETLINK MESSAGE ---------------------------', log)
    assert match('nl_msg_dump:   [NETLINK HEADER] 16 octets', log)
    assert match('print_hdr:     .nlmsg_len = \d{3,}', log, True)
    assert match('print_hdr:     .type = 16 <0x10>', log)
    assert match('print_hdr:     .flags = 2 <MULTI>', log)
    assert match('print_hdr:     .seq = \d{10}', log, True)
    assert match('print_hdr:     .port = \d{4,}', log, True)
    assert match('print_msg:   \[PAYLOAD\] \d{3,} octets', log, True)
    assert match('dump_hex:     00 00 01 00 02 00 00 00 .. 10 .. 00 00 00 00 00 ................', log, True)
    assert match('dump_hex:     09 00 03 00 65 74 68 30 00 00 00 00 08 00 0d 00 ....eth0........', log)
    assert match('dump_hex:     e8 03 00 00 05 00 10 00 .. 00 00 00 05 00 11 00 ................', log, True)
    assert match('dump_hex:     00 00 00 00 .. 00 .. 00 dc 05 00 00 .. 00 .. 00 ................', log, True)

    rem = log.index('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------')
    assert 20 < rem  # At least check that there were a lot of log statements skipped.
    log2 = log[rem:]
    log.clear()
    log.extend(log2)

    assert match('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------', log)
    assert match('nl_valid_handler_debug: -- Debug: Unhandled Valid message: type=0x10 length=\d{3,} flags=<MULTI> '
                 'sequence-nr=\d{10,} pid=\d{4,}', log, True)
    return True


def multipart_wlan0(log):
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Processing valid message...', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message', log, True)
    assert match('nl_msg_in_handler_debug: -- Debug: Received Message:', log)
    assert match('nl_msg_dump: --------------------------   BEGIN NETLINK MESSAGE ---------------------------', log)
    assert match('nl_msg_dump:   [NETLINK HEADER] 16 octets', log)
    assert match('print_hdr:     .nlmsg_len = \d{3,}', log, True)
    assert match('print_hdr:     .type = 16 <0x10>', log)
    assert match('print_hdr:     .flags = 2 <MULTI>', log)
    assert match('print_hdr:     .seq = \d{10}', log, True)
    assert match('print_hdr:     .port = \d{4,}', log, True)
    assert match('print_msg:   \[PAYLOAD\] \d{3,} octets', log, True)
    assert match('dump_hex:     00 00 01 00 .. 00 00 00 .. 10 .. 00 00 00 00 00 ................', log, True)
    assert match('dump_hex:     0a 00 03 00 77 6c 61 6e 30 00 00 00 08 00 0d 00 ....wlan0.......', log)
    assert match('dump_hex:     e8 03 00 00 05 00 10 00 .. 00 00 00 05 00 11 00 ................', log, True)
    assert match('dump_hex:     .. 00 00 00 08 00 04 00 dc 05 00 00 .. 00 .. 00 ................', log, True)

    rem = log.index('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------')
    assert 20 < rem  # At least check that there were a lot of log statements skipped.
    log2 = log[rem:]
    log.clear()
    log.extend(log2)

    assert match('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------', log)
    assert match('nl_valid_handler_debug: -- Debug: Unhandled Valid message: type=0x10 length=\d{3,} flags=<MULTI> '
                 'sequence-nr=\d{10,} pid=\d{4,}', log, True)
    return True


@pytest.mark.usefixtures('nlcb_debug')
def test_multipart(log, ifaces):
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
        struct rtgenmsg rt_hdr = { .rtgen_family = AF_PACKET, };
        int ret = nl_send_simple(sk, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, &rt_hdr, sizeof(rt_hdr));
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
    // __nlmsg_alloc: msg 0x1bbe0b8: Allocated new message, maxlen=4096
    // nlmsg_alloc_simple: msg 0x1bbe0b8: Allocated new simple message
    // nlmsg_reserve: msg 0x1bbe0b8: Reserved 4 (1) bytes, pad=4, nlmsg_len=20
    // nlmsg_append: msg 0x1bbe0b8: Appended 1 bytes with padding 4
    // -- Debug: Sent Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 20
    //     .type = 18 <0x12>
    //     .flags = 773 <REQUEST,ACK,ROOT,MATCH>
    //     .seq = 1424053819
    //     .port = 18409
    //   [PAYLOAD] 4 octets
    //     11 00 00 00                                     ....
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // nl_sendmsg: sent 20 bytes
    // nlmsg_free: Returned message reference 0x1bbe0b8, 0 remaining
    // nlmsg_free: msg 0x1bbe0b8: Freed
    // Bytes Sent: 20
    // recvmsgs: Attempting to read from 0x1bbe080
    // recvmsgs: recvmsgs(0x1bbe080): Read 3364 bytes
    // recvmsgs: recvmsgs(0x1bbe080): Processing valid message...
    // __nlmsg_alloc: msg 0x1bc20c0: Allocated new message, maxlen=1116
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 1116
    //     .type = 16 <0x10>
    //     .flags = 2 <MULTI>
    //     .seq = 1424053819
    //     .port = 18409
    //   [PAYLOAD] 1100 octets
    //     00 00 04 03 01 00 00 00 49 00 01 00 00 00 00 00 ........I.......
    //     <trimmed>
    //     00 00 00 00 00 00 00 00 00 00 00 00             ............
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // -- Debug: Unhandled Valid message: type=0x10 length=1116 flags=<MULTI> sequence-nr=1424053819 pid=18409
    // recvmsgs: recvmsgs(0x1bbe080): Processing valid message...
    // nlmsg_free: Returned message reference 0x1bc20c0, 0 remaining
    // nlmsg_free: msg 0x1bc20c0: Freed
    // __nlmsg_alloc: msg 0x1bc20c0: Allocated new message, maxlen=1124
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 1124
    //     .type = 16 <0x10>
    //     .flags = 2 <MULTI>
    //     .seq = 1424053819
    //     .port = 18409
    //   [PAYLOAD] 1108 octets
    //     00 00 01 00 02 00 00 00 43 10 01 00 00 00 00 00 ........C.......
    //     <trimmed>
    //     00 00 00 00                                     ....
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // -- Debug: Unhandled Valid message: type=0x10 length=1124 flags=<MULTI> sequence-nr=1424053819 pid=18409
    // recvmsgs: recvmsgs(0x1bbe080): Processing valid message...
    // nlmsg_free: Returned message reference 0x1bc20c0, 0 remaining
    // nlmsg_free: msg 0x1bc20c0: Freed
    // __nlmsg_alloc: msg 0x1bc20c0: Allocated new message, maxlen=1124
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 1124
    //     .type = 16 <0x10>
    //     .flags = 2 <MULTI>
    //     .seq = 1424053819
    //     .port = 18409
    //   [PAYLOAD] 1108 octets
    //     00 00 01 00 03 00 00 00 03 10 00 00 00 00 00 00 ................
    //     <trimmed>
    //     00 00 00 00                                     ....
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // -- Debug: Unhandled Valid message: type=0x10 length=1124 flags=<MULTI> sequence-nr=1424053819 pid=18409
    // nlmsg_free: Returned message reference 0x1bc20c0, 0 remaining
    // nlmsg_free: msg 0x1bc20c0: Freed
    // recvmsgs: Attempting to read from 0x1bbe080
    // recvmsgs: recvmsgs(0x1bbe080): Read 20 bytes
    // recvmsgs: recvmsgs(0x1bbe080): Processing valid message...
    // __nlmsg_alloc: msg 0x1bc20c0: Allocated new message, maxlen=20
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 20
    //     .type = 3 <DONE>
    //     .flags = 2 <MULTI>
    //     .seq = 1424053819
    //     .port = 18409
    //   [PAYLOAD] 4 octets
    //     00 00 00 00                                     ....
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // recvmsgs: recvmsgs(0x1bbe080): Increased expected sequence number to 1424053820
    // -- Debug: End of multipart message block: type=DONE length=20 flags=<MULTI> sequence-nr=1424053819 pid=18409
    // nlmsg_free: Returned message reference 0x1bc20c0, 0 remaining
    // nlmsg_free: msg 0x1bc20c0: Freed
    // 0 == nl_recvmsgs_default(sk)
    // nl_cache_mngt_unregister: Unregistered cache operations genl/family
    """
    log.clear()
    sk = nl_socket_alloc()
    nl_connect(sk, NETLINK_ROUTE)
    rt_hdr = rtgenmsg(rtgen_family=socket.AF_PACKET)
    assert 20 == nl_send_simple(sk, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, rt_hdr)

    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message', log, True)
    assert match('nlmsg_alloc_simple: msg 0x[a-f0-9]+: Allocated new simple message', log, True)
    assert match('nlmsg_append: msg 0x[a-f0-9]+: Appended \w+', log, True)
    assert match('nl_msg_out_handler_debug: -- Debug: Sent Message:', log)
    assert match('nl_msg_dump: --------------------------   BEGIN NETLINK MESSAGE ---------------------------', log)
    assert match('nl_msg_dump:   [NETLINK HEADER] 16 octets', log)
    assert match('print_hdr:     .nlmsg_len = 20', log)
    assert match('print_hdr:     .type = 18 <0x12>', log)
    assert match('print_hdr:     .flags = 773 <REQUEST,ACK,ROOT,MATCH>', log)
    assert match('print_hdr:     .seq = \d{10}', log, True)
    assert match('print_hdr:     .port = \d{4,}', log, True)
    assert match('print_msg:   [PAYLOAD] 4 octets', log)
    assert match('dump_hex:     11 00 00 00                                     ....', log)
    assert match('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------', log)
    assert match('nl_sendmsg: sent 20 bytes', log)
    assert not log

    assert 0 == nl_recvmsgs_default(sk)
    assert match('recvmsgs: Attempting to read from 0x[a-f0-9]+', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Read \d{4,} bytes', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Processing valid message...', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message', log, True)
    assert match('nl_msg_in_handler_debug: -- Debug: Received Message:', log)
    assert match('nl_msg_dump: --------------------------   BEGIN NETLINK MESSAGE ---------------------------', log)
    assert match('nl_msg_dump:   [NETLINK HEADER] 16 octets', log)
    assert match('print_hdr:     .nlmsg_len = \d{3,}', log, True)
    assert match('print_hdr:     .type = 16 <0x10>', log)
    assert match('print_hdr:     .flags = 2 <MULTI>', log)
    assert match('print_hdr:     .seq = \d{10}', log, True)
    assert match('print_hdr:     .port = \d{4,}', log, True)
    assert match('print_msg:   \[PAYLOAD\] \d{3,} octets', log, True)
    assert match('dump_hex:     00 00 04 03 01 00 00 00 49 00 01 00 00 00 00 00 ........I.......', log)
    assert match('dump_hex:     07 00 03 00 6c 6f 00 00 08 00 0d 00 00 00 00 00 ....lo..........', log)
    assert match('dump_hex:     05 00 10 00 00 00 00 00 05 00 11 00 00 00 00 00 ................', log)

    # Done testing this payload. Differs too much between Travis and Raspbian, and probably others.
    rem = log.index('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------')
    assert 20 < rem  # At least check that there were a lot of log statements skipped.
    log = log[rem:]

    assert match('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------', log)
    assert match('nl_valid_handler_debug: -- Debug: Unhandled Valid message: type=0x10 length=\d{3,} flags=<MULTI> '
                 'sequence-nr=\d{10,} pid=\d{4,}', log, True)

    if 'eth0' in ifaces:
        assert multipart_eth0(log)
    if 'wlan0' in ifaces:
        assert multipart_wlan0(log)
    if set(ifaces) - {'lo0', 'eth0', 'wlan0'}:
        # Unsupported interface found. Nuking everything except last lines from log.
        search_str = 'nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------'
        while log.count(search_str) > 1:
            rem = log.index(search_str) + 2
            log = log[rem:]

    assert match('recvmsgs: Attempting to read from 0x[a-f0-9]+', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Read 20 bytes', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Processing valid message...', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message', log, True)
    assert match('nl_msg_in_handler_debug: -- Debug: Received Message:', log)
    assert match('nl_msg_dump: --------------------------   BEGIN NETLINK MESSAGE ---------------------------', log)
    assert match('nl_msg_dump:   [NETLINK HEADER] 16 octets', log)
    assert match('print_hdr:     .nlmsg_len = 20', log)
    assert match('print_hdr:     .type = 3 <DONE>', log)
    assert match('print_hdr:     .flags = 2 <MULTI>', log)
    assert match('print_hdr:     .seq = \d{10}', log, True)
    assert match('print_hdr:     .port = \d{4,}', log, True)
    assert match('print_msg:   [PAYLOAD] 4 octets', log)
    assert match('dump_hex:     00 00 00 00                                     ....', log)
    assert match('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------', log)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Increased expected sequence number to \d{4,}', log, True)
    assert match('nl_finish_handler_debug: -- Debug: End of multipart message block: type=DONE length=20 flags=<MULTI> '
                 'sequence-nr=\d{10,} pid=\d{4,}', log, True)

    nl_socket_free(sk)
    assert not log


@pytest.mark.usefixtures('nlcb_verbose')
def test_multipart_verbose(log, ifaces):
    """Expected output (trimmed):
    // nl_cache_mngt_register: Registered cache operations genl/family
    // Begin main()
    // Allocated socket.
    // 0 == nl_connect(sk, NETLINK_ROUTE)
    // __nlmsg_alloc: msg 0xa180b8: Allocated new message, maxlen=4096
    // nlmsg_alloc_simple: msg 0xa180b8: Allocated new simple message
    // nlmsg_reserve: msg 0xa180b8: Reserved 4 (1) bytes, pad=4, nlmsg_len=20
    // nlmsg_append: msg 0xa180b8: Appended 1 bytes with padding 4
    // nl_sendmsg: sent 20 bytes
    // nlmsg_free: Returned message reference 0xa180b8, 0 remaining
    // nlmsg_free: msg 0xa180b8: Freed
    // Bytes Sent: 20
    // recvmsgs: Attempting to read from 0xa18080
    // recvmsgs: recvmsgs(0xa18080): Read 3364 bytes
    // recvmsgs: recvmsgs(0xa18080): Processing valid message...
    // __nlmsg_alloc: msg 0xa1c0c0: Allocated new message, maxlen=1116
    // -- Warning: unhandled valid message: type=0x10 length=1116 flags=<MULTI> sequence-nr=1424132449 pid=5810
    // recvmsgs: recvmsgs(0xa18080): Processing valid message...
    // nlmsg_free: Returned message reference 0xa1c0c0, 0 remaining
    // nlmsg_free: msg 0xa1c0c0: Freed
    // __nlmsg_alloc: msg 0xa1c0c0: Allocated new message, maxlen=1124
    // -- Warning: unhandled valid message: type=0x10 length=1124 flags=<MULTI> sequence-nr=1424132449 pid=5810
    // recvmsgs: recvmsgs(0xa18080): Processing valid message...
    // nlmsg_free: Returned message reference 0xa1c0c0, 0 remaining
    // nlmsg_free: msg 0xa1c0c0: Freed
    // __nlmsg_alloc: msg 0xa1c0c0: Allocated new message, maxlen=1124
    // -- Warning: unhandled valid message: type=0x10 length=1124 flags=<MULTI> sequence-nr=1424132449 pid=5810
    // nlmsg_free: Returned message reference 0xa1c0c0, 0 remaining
    // nlmsg_free: msg 0xa1c0c0: Freed
    // recvmsgs: Attempting to read from 0xa18080
    // recvmsgs: recvmsgs(0xa18080): Read 20 bytes
    // recvmsgs: recvmsgs(0xa18080): Processing valid message...
    // __nlmsg_alloc: msg 0xa1c0c0: Allocated new message, maxlen=20
    // recvmsgs: recvmsgs(0xa18080): Increased expected sequence number to 1424132450
    // nlmsg_free: Returned message reference 0xa1c0c0, 0 remaining
    // nlmsg_free: msg 0xa1c0c0: Freed
    // 0 == nl_recvmsgs_default(sk)
    // nl_cache_mngt_unregister: Unregistered cache operations genl/family
    """
    log.clear()
    sk = nl_socket_alloc()
    nl_connect(sk, NETLINK_ROUTE)
    rt_hdr = rtgenmsg(rtgen_family=socket.AF_PACKET)
    assert 20 == nl_send_simple(sk, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, rt_hdr)

    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message', log, True)
    assert match('nlmsg_alloc_simple: msg 0x[a-f0-9]+: Allocated new simple message', log, True)
    assert match('nlmsg_append: msg 0x[a-f0-9]+: Appended \w+', log, True)
    assert match('nl_sendmsg: sent 20 bytes', log)
    assert not log

    assert 0 == nl_recvmsgs_default(sk)
    assert match('recvmsgs: Attempting to read from 0x[a-f0-9]+', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Read \d{4,} bytes', log, True)

    for _ in ifaces:
        assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Processing valid message...', log, True)
        assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message', log, True)
        assert match('nl_valid_handler_verbose: -- Warning: unhandled valid message: type=0x10 length=\d{3,} '
                     'flags=<MULTI> sequence-nr=\d{10,} pid=\d{4,}', log, True)

    assert match('recvmsgs: Attempting to read from 0x[a-f0-9]+', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Read 20 bytes', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Processing valid message...', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Increased expected sequence number to \d{4,}', log, True)

    nl_socket_free(sk)
    assert not log
