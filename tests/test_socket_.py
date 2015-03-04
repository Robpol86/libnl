import re
import socket

import pytest

from libnl.handlers import nl_cb_alloc, NL_CB_VERBOSE, NL_CB_VALID, NL_CB_CUSTOM, NL_OK, NL_STOP
from libnl.linux_private.netlink import NETLINK_ROUTE, NLM_F_REQUEST, NLM_F_DUMP
from libnl.linux_private.rtnetlink import rtgenmsg, RTM_GETLINK
from libnl.msg import nl_msg_dump
from libnl.nl import nl_connect, nl_send_simple, nl_recvmsgs_default
from libnl.socket_ import nl_socket_alloc, nl_socket_free, nl_socket_modify_cb, nl_socket_modify_err_cb


def match(expected, log, is_regex=False):
    log_statement = log.pop(0)
    if is_regex:
        assert re.match(expected + '$', log_statement)
    else:
        assert expected == log_statement
    return True


def test_nl_socket_alloc():
    """// gcc $(pkg-config --cflags --libs libnl-genl-3.0) a.c && ./a.out
    #include <netlink/msg.h>
    struct nl_cb {
        nl_recvmsg_msg_cb_t cb_set[NL_CB_TYPE_MAX+1]; void * cb_args[NL_CB_TYPE_MAX+1]; nl_recvmsg_err_cb_t cb_err;
        void * cb_err_arg; int (*cb_recvmsgs_ow)(struct nl_sock *, struct nl_cb *);
        int (*cb_recv_ow)(struct nl_sock *, struct sockaddr_nl *, unsigned char **, struct ucred **);
        int (*cb_send_ow)(struct nl_sock *, struct nl_msg *); int cb_refcnt; enum nl_cb_type cb_active;
    };
    struct nl_sock {
        struct sockaddr_nl s_local; struct sockaddr_nl s_peer; int s_fd; int s_proto; unsigned int s_seq_next;
        unsigned int s_seq_expect; int s_flags; struct nl_cb *s_cb; size_t s_bufsize;
    };
    void print(struct nl_sock *sk) {
        printf("sk.s_local.nl_family = %d\n", sk->s_local.nl_family);
        printf("sk.s_local.nl_pid = %d  # changes every process, remains same throughout proc.\n", sk->s_local.nl_pid);
        printf("sk.s_local.nl_groups = %d\n", sk->s_local.nl_groups);
        printf("sk.s_peer.nl_family = %d\n", sk->s_peer.nl_family);
        printf("sk.s_peer.nl_pid = %d\n", sk->s_peer.nl_pid);
        printf("sk.s_peer.nl_groups = %d\n", sk->s_peer.nl_groups);
        printf("sk.s_fd = %d\n", sk->s_fd);
        printf("sk.s_proto = %d\n", sk->s_proto);
        printf("sk.s_flags = %d\n", sk->s_flags);
        printf("sk.s_cb.cb_active = %d\n", sk->s_cb->cb_active);
        printf("addr: sk.s_cb.cb_err = %p\n", sk->s_cb->cb_err);
    }
    int main() {
        struct nl_sock *sk = nl_socket_alloc();
        print(sk);
        nl_socket_free(sk);
        printf("\n");
        struct nl_cb *cb = nl_cb_alloc(NL_CB_VERBOSE);
        sk = nl_socket_alloc_cb(cb);
        nl_cb_put(cb);
        print(sk);
        nl_socket_free(sk);
        return 0;
    }
    // Expected output:
    // sk.s_local.nl_family = 16
    // sk.s_local.nl_pid = 12309  # changes every process, remains same throughout proc.
    // sk.s_local.nl_groups = 0
    // sk.s_peer.nl_family = 16
    // sk.s_peer.nl_pid = 0
    // sk.s_peer.nl_groups = 0
    // sk.s_fd = -1
    // sk.s_proto = 0
    // sk.s_flags = 0
    // sk.s_cb.cb_active = 11
    // addr: sk.s_cb.cb_err = (nil)
    //
    // sk.s_local.nl_family = 16
    // sk.s_local.nl_pid = 12309  # changes every process, remains same throughout proc.
    // sk.s_local.nl_groups = 0
    // sk.s_peer.nl_family = 16
    // sk.s_peer.nl_pid = 0
    // sk.s_peer.nl_groups = 0
    // sk.s_fd = -1
    // sk.s_proto = 0
    // sk.s_flags = 0
    // sk.s_cb.cb_active = 11
    // addr: sk.s_cb.cb_err = 0xb6f6eb40
    """
    sk = nl_socket_alloc()
    assert 16 == sk.s_local.nl_family
    assert 0 < sk.s_local.nl_pid
    assert 0 == sk.s_local.nl_groups
    assert 16 == sk.s_peer.nl_family
    assert 0 == sk.s_peer.nl_pid
    assert 0 == sk.s_peer.nl_groups
    assert -1 == sk.s_fd
    assert 0 == sk.s_proto
    assert 0 == sk.s_flags
    assert 11 == sk.s_cb.cb_active
    assert sk.s_cb.cb_err is None
    nl_socket_free(sk)

    first_pid = int(sk.s_local.nl_pid)
    sk = nl_socket_alloc(nl_cb_alloc(NL_CB_VERBOSE))
    assert 16 == sk.s_local.nl_family
    assert first_pid == sk.s_local.nl_pid
    assert 0 == sk.s_local.nl_groups
    assert 16 == sk.s_peer.nl_family
    assert 0 == sk.s_peer.nl_pid
    assert 0 == sk.s_peer.nl_groups
    assert -1 == sk.s_fd
    assert 0 == sk.s_proto
    assert 0 == sk.s_flags
    assert 11 == sk.s_cb.cb_active
    assert sk.s_cb.cb_err is not None
    nl_socket_free(sk)


def test_nl_socket_modify_cb(log, ifaces):
    """// gcc $(pkg-config --cflags --libs libnl-genl-3.0) a.c && NLDBG=4 ./a.out
    #include <netlink/msg.h>
    static int callback(struct nl_msg *msg, void *arg) {
        printf("Got something.\n");
        nl_msg_dump(msg, stdout);
        return NL_OK;
    }
    int main() {
        // Send data to the kernel.
        struct nl_sock *sk = nl_socket_alloc();
        printf("%d == nl_connect(sk, NETLINK_ROUTE)\n", nl_connect(sk, NETLINK_ROUTE));
        struct rtgenmsg rt_hdr = { .rtgen_family = AF_PACKET, };
        int ret = nl_send_simple(sk, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, &rt_hdr, sizeof(rt_hdr));
        printf("Bytes Sent: %d\n", ret);

        // Retrieve kernel's response.
        nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, callback, NULL);
        printf("%d == nl_recvmsgs_default(sk)\n", nl_recvmsgs_default(sk));

        nl_socket_free(sk);
        return 0;
    }
    // Expected output (trimmed):
    // nl_cache_mngt_register: Registered cache operations genl/family
    // 0 == nl_connect(sk, NETLINK_ROUTE)
    // __nlmsg_alloc: msg 0x1b840b8: Allocated new message, maxlen=4096
    // nlmsg_alloc_simple: msg 0x1b840b8: Allocated new simple message
    // nlmsg_reserve: msg 0x1b840b8: Reserved 4 (1) bytes, pad=4, nlmsg_len=20
    // nlmsg_append: msg 0x1b840b8: Appended 1 bytes with padding 4
    // nl_sendmsg: sent 20 bytes
    // nlmsg_free: Returned message reference 0x1b840b8, 0 remaining
    // nlmsg_free: msg 0x1b840b8: Freed
    // Bytes Sent: 20
    // recvmsgs: Attempting to read from 0x1b84080
    // recvmsgs: recvmsgs(0x1b84080): Read 3364 bytes
    // recvmsgs: recvmsgs(0x1b84080): Processing valid message...
    // __nlmsg_alloc: msg 0x1b880c0: Allocated new message, maxlen=1116
    // Got something.
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 1116
    //     .type = 16 <0x10>
    //     .flags = 2 <MULTI>
    //     .seq = 1424133909
    //     .port = 6192
    //   [PAYLOAD] 1100 octets
    //     00 00 04 03 01 00 00 00 49 00 01 00 00 00 00 00 ........I.......
    //     07 00 03 00 6c 6f 00 00 08 00 0d 00 00 00 00 00 ....lo..........
    //     <trimmed>
    //     00 00 00 00 00 00 00 00 00 00 00 00             ............
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // recvmsgs: recvmsgs(0x1b84080): Processing valid message...
    // nlmsg_free: Returned message reference 0x1b880c0, 0 remaining
    // nlmsg_free: msg 0x1b880c0: Freed
    // __nlmsg_alloc: msg 0x1b880c0: Allocated new message, maxlen=1124
    // Got something.
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 1124
    //     .type = 16 <0x10>
    //     .flags = 2 <MULTI>
    //     .seq = 1424133909
    //     .port = 6192
    //   [PAYLOAD] 1108 octets
    //     00 00 01 00 02 00 00 00 43 10 01 00 00 00 00 00 ........C.......
    //     09 00 03 00 65 74 68 30 00 00 00 00 08 00 0d 00 ....eth0........
    //     <trimmed>
    //     00 00 00 00                                     ....
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // recvmsgs: recvmsgs(0x1b84080): Processing valid message...
    // nlmsg_free: Returned message reference 0x1b880c0, 0 remaining
    // nlmsg_free: msg 0x1b880c0: Freed
    // __nlmsg_alloc: msg 0x1b880c0: Allocated new message, maxlen=1124
    // Got something.
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 1124
    //     .type = 16 <0x10>
    //     .flags = 2 <MULTI>
    //     .seq = 1424133909
    //     .port = 6192
    //   [PAYLOAD] 1108 octets
    //     00 00 01 00 04 00 00 00 03 10 00 00 00 00 00 00 ................
    //     0a 00 03 00 77 6c 61 6e 30 00 00 00 08 00 0d 00 ....wlan0.......
    //     <trimmed>
    //     00 00 00 00                                     ....
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // nlmsg_free: Returned message reference 0x1b880c0, 0 remaining
    // nlmsg_free: msg 0x1b880c0: Freed
    // recvmsgs: Attempting to read from 0x1b84080
    // recvmsgs: recvmsgs(0x1b84080): Read 20 bytes
    // recvmsgs: recvmsgs(0x1b84080): Processing valid message...
    // __nlmsg_alloc: msg 0x1b880c0: Allocated new message, maxlen=20
    // recvmsgs: recvmsgs(0x1b84080): Increased expected sequence number to 1424133910
    // nlmsg_free: Returned message reference 0x1b880c0, 0 remaining
    // nlmsg_free: msg 0x1b880c0: Freed
    // 0 == nl_recvmsgs_default(sk)
    // nl_cache_mngt_unregister: Unregistered cache operations genl/family
    """
    got_something = list()

    def callback(msg, arg):
        got_something.append(arg)
        nl_msg_dump(msg)
        return NL_OK

    log.clear()
    sk = nl_socket_alloc()
    nl_connect(sk, NETLINK_ROUTE)
    rt_hdr = rtgenmsg(rtgen_family=socket.AF_PACKET)
    assert 20 == nl_send_simple(sk, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, rt_hdr, rt_hdr.SIZEOF)

    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message, maxlen=4096', log, True)
    assert match('nlmsg_alloc_simple: msg 0x[a-f0-9]+: Allocated new simple message', log, True)
    assert match('nlmsg_reserve: msg 0x[a-f0-9]+: Reserved 4 \(1\) bytes, pad=4, nlmsg_len=20', log, True)
    assert match('nlmsg_append: msg 0x[a-f0-9]+: Appended 1 bytes with padding 4', log, True)
    assert match('nl_sendmsg: sent 20 bytes', log)
    assert not log

    assert 0 == nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, callback, 95)
    assert 0 == nl_recvmsgs_default(sk)
    assert [95] * len(ifaces) == got_something

    assert match('recvmsgs: Attempting to read from 0x[a-f0-9]+', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Read \d{4,} bytes', log, True)

    for _ in ifaces:
        assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Processing valid message...', log, True)
        assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message, maxlen=\d{3,}', log, True)
        assert match('nl_msg_dump: --------------------------   BEGIN NETLINK MESSAGE ---------------------------', log)
        assert match('nl_msg_dump:   [NETLINK HEADER] 16 octets', log)
        assert match('print_hdr:     .nlmsg_len = \d{3,}', log, True)
        assert match('print_hdr:     .type = 16 <0x10>', log)
        assert match('print_hdr:     .flags = 2 <MULTI>', log)
        assert match('print_hdr:     .seq = \d{10}', log, True)
        assert match('print_hdr:     .port = \d{3,}', log, True)
        assert match('print_msg:   \[PAYLOAD\] \d{3,} octets', log, True)

        rem = log.index('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------')
        assert 20 < rem  # At least check that there were a lot of log statements skipped.
        log = log[rem:]
        assert match('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------', log)

    assert match('recvmsgs: Attempting to read from 0x[a-f0-9]+', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Read 20 bytes', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Processing valid message...', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message, maxlen=20', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Increased expected sequence number to \d{4,}', log, True)

    nl_socket_free(sk)
    assert not log


@pytest.mark.usefixtures('nlcb_verbose')
def test_nl_socket_modify_cb_error_verbose(log):
    """// gcc $(pkg-config --cflags --libs libnl-genl-3.0) a.c && NLDBG=4 NLCB=verbose ./a.out
    #include <netlink/msg.h>
    static int callback(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg) {
        int *ret = arg;
        *ret = err->error;
        printf("Got something.\n");
        return NL_STOP;
    }
    int main() {
        // Send data to the kernel.
        struct nl_sock *sk = nl_socket_alloc();
        printf("%d == nl_connect(sk, NETLINK_ROUTE)\n", nl_connect(sk, NETLINK_ROUTE));
        struct rtgenmsg rt_hdr = { .rtgen_family = AF_PACKET, };
        int ret = nl_send_simple(sk, RTM_GETLINK, 0, &rt_hdr, sizeof(rt_hdr));
        printf("Bytes Sent: %d\n", ret);

        // Retrieve kernel's response.
        int err = 0;
        nl_socket_modify_err_cb(sk, NL_CB_CUSTOM, callback, &err);
        printf("%d == err\n", err);
        printf("%d == nl_recvmsgs_default(sk)\n", nl_recvmsgs_default(sk));
        printf("%d == err\n", err);

        nl_socket_free(sk);
        return 0;
    }
    // Expected output (trimmed):
    // nl_cache_mngt_register: Registered cache operations genl/family
    // 0 == nl_connect(sk, NETLINK_ROUTE)
    // __nlmsg_alloc: msg 0x124e0b8: Allocated new message, maxlen=4096
    // nlmsg_alloc_simple: msg 0x124e0b8: Allocated new simple message
    // nlmsg_reserve: msg 0x124e0b8: Reserved 4 (1) bytes, pad=4, nlmsg_len=20
    // nlmsg_append: msg 0x124e0b8: Appended 1 bytes with padding 4
    // nl_sendmsg: sent 20 bytes
    // nlmsg_free: Returned message reference 0x124e0b8, 0 remaining
    // nlmsg_free: msg 0x124e0b8: Freed
    // Bytes Sent: 20
    // 0 == err
    // recvmsgs: Attempting to read from 0x124e080
    // recvmsgs: recvmsgs(0x124e080): Read 40 bytes
    // recvmsgs: recvmsgs(0x124e080): Processing valid message...
    // __nlmsg_alloc: msg 0x12520c0: Allocated new message, maxlen=40
    // recvmsgs: recvmsgs(0x124e080): Increased expected sequence number to 1424136270
    // Got something.
    // nlmsg_free: Returned message reference 0x12520c0, 0 remaining
    // nlmsg_free: msg 0x12520c0: Freed
    // -7 == nl_recvmsgs_default(sk)
    // -22 == err
    // nl_cache_mngt_unregister: Unregistered cache operations genl/family
    """
    got_something = list()

    def callback(_, err, arg):
        arg.append(err.error)
        return NL_STOP

    log.clear()
    sk = nl_socket_alloc()
    nl_connect(sk, NETLINK_ROUTE)
    rt_hdr = rtgenmsg(rtgen_family=socket.AF_PACKET)
    assert 20 == nl_send_simple(sk, RTM_GETLINK, 0, rt_hdr, rt_hdr.SIZEOF)

    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message, maxlen=4096', log, True)
    assert match('nlmsg_alloc_simple: msg 0x[a-f0-9]+: Allocated new simple message', log, True)
    assert match('nlmsg_reserve: msg 0x[a-f0-9]+: Reserved 4 \(1\) bytes, pad=4, nlmsg_len=20', log, True)
    assert match('nlmsg_append: msg 0x[a-f0-9]+: Appended 1 bytes with padding 4', log, True)
    assert match('nl_sendmsg: sent 20 bytes', log)
    assert not log

    assert 0 == nl_socket_modify_err_cb(sk, NL_CB_CUSTOM, callback, got_something)
    assert -7 == nl_recvmsgs_default(sk)
    assert [-22] == got_something

    assert match('recvmsgs: Attempting to read from 0x[a-f0-9]+', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Read 40 bytes', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Processing valid message...', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message, maxlen=40', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Increased expected sequence number to \d{4,}', log, True)

    nl_socket_free(sk)
    assert not log
