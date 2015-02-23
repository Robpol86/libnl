import re

import pytest

from libnl.attr import nla_put_string
from libnl.genl.ctrl import genl_ctrl_resolve
from libnl.genl.family import genl_family_set_name, genl_family_alloc
from libnl.genl.genl import genl_connect, genlmsg_put
from libnl.handlers import NL_CB_VALID, NL_CB_CUSTOM, NL_OK, nl_cb_overwrite_send
from libnl.linux_private.genetlink import GENL_ID_CTRL, CTRL_CMD_GETFAMILY, CTRL_ATTR_FAMILY_NAME
from libnl.msg import nlmsg_alloc, NL_AUTO_PORT, NL_AUTO_SEQ, dump_hex, nlmsg_hdr
from libnl.nl import nl_send_auto, nl_recvmsgs_default, nl_send_iovec
from libnl.socket_ import nl_socket_alloc, nl_socket_modify_cb, nl_socket_free


def match(expected, log, is_regex=False):
    log_statement = log.pop(0)
    if is_regex:
        assert re.match(expected, log_statement)
    else:
        assert expected == log_statement
    return True


@pytest.mark.skipif('True')
def test_ctrl_cmd_getfamily_hex_dump(log):
    """// gcc $(pkg-config --cflags --libs libnl-genl-3.0) a.c && NLDBG=4 ./a.out
    #include <netlink/msg.h>
    struct nl_sock {
        struct sockaddr_nl s_local; struct sockaddr_nl s_peer; int s_fd; int s_proto; unsigned int s_seq_next;
        unsigned int s_seq_expect; int s_flags; struct nl_cb *s_cb; size_t s_bufsize;
    };
    static void prefix_line(FILE *ofd, int prefix) { int i; for (i = 0; i < prefix; i++) fprintf(ofd, "  "); }
    static inline void dump_hex(FILE *ofd, char *start, int len, int prefix) {
        int i, a, c, limit; char ascii[21] = {0}; limit = 16 - (prefix * 2); prefix_line(ofd, prefix);
        fprintf(ofd, "    ");
        for (i = 0, a = 0, c = 0; i < len; i++) {
            int v = *(uint8_t *) (start + i); fprintf(ofd, "%02x ", v); ascii[a++] = isprint(v) ? v : '.';
            if (++c >= limit) {
                fprintf(ofd, "%s\n", ascii);
                if (i < (len - 1)) { prefix_line(ofd, prefix); fprintf(ofd, "    "); }
                a = c = 0;
                memset(ascii, 0, sizeof(ascii));
            }
        }
        if (c != 0) { for (i = 0; i < (limit - c); i++) fprintf(ofd, "   "); fprintf(ofd, "%s\n", ascii); }
    }
    struct ucred { pid_t pid; uid_t uid; gid_t gid; };
    struct nl_msg {
        int nm_protocol; int nm_flags; struct sockaddr_nl nm_src; struct sockaddr_nl nm_dst; struct ucred nm_creds;
        struct nlmsghdr *nm_nlh; size_t nm_size; int nm_refcnt;
    };
    static int callback_send(struct nl_sock *sk, struct nl_msg *msg) {
        printf("%d == msg.nm_protocol\n", msg->nm_protocol);
        printf("%d == msg.nm_flags\n", msg->nm_flags);
        printf("%d == msg.nm_src.nl_family\n", msg->nm_src.nl_family);
        printf("%d == msg.nm_src.nl_pid\n", msg->nm_src.nl_pid);
        printf("%d == msg.nm_src.nl_groups\n", msg->nm_src.nl_groups);
        printf("%d == msg.nm_dst.nl_family\n", msg->nm_dst.nl_family);
        printf("%d == msg.nm_dst.nl_pid\n", msg->nm_dst.nl_pid);
        printf("%d == msg.nm_dst.nl_groups\n", msg->nm_dst.nl_groups);
        printf("%d == msg.nm_creds.pid\n", msg->nm_creds.pid);
        printf("%d == msg.nm_creds.uid\n", msg->nm_creds.uid);
        printf("%d == msg.nm_creds.gid\n", msg->nm_creds.gid);
        printf("%d == msg.nm_nlh.nlmsg_type\n", msg->nm_nlh->nlmsg_type);
        printf("%d == msg.nm_nlh.nlmsg_flags\n", msg->nm_nlh->nlmsg_flags);
        printf("%d == msg.nm_nlh.nlmsg_pid\n", msg->nm_nlh->nlmsg_pid);
        printf("%d == msg.nm_size\n", msg->nm_size);
        printf("%d == msg.nm_refcnt\n", msg->nm_refcnt);
        dump_hex(stdout, (char *) msg, msg->nm_size, 0);
        struct iovec iov = { .iov_base = (void *) nlmsg_hdr(msg), .iov_len = nlmsg_hdr(msg)->nlmsg_len, };
        return nl_send_iovec(sk, msg, &iov, 1);
    }
    static int callback_recv(struct nl_msg *msg, void *arg) {
        printf("%d == msg.nm_protocol\n", msg->nm_protocol);
        printf("%d == msg.nm_flags\n", msg->nm_flags);
        printf("%d == msg.nm_src.nl_family\n", msg->nm_src.nl_family);
        printf("%d == msg.nm_src.nl_pid\n", msg->nm_src.nl_pid);
        printf("%d == msg.nm_src.nl_groups\n", msg->nm_src.nl_groups);
        printf("%d == msg.nm_dst.nl_family\n", msg->nm_dst.nl_family);
        printf("%d == msg.nm_dst.nl_pid\n", msg->nm_dst.nl_pid);
        printf("%d == msg.nm_dst.nl_groups\n", msg->nm_dst.nl_groups);
        printf("%d == msg.nm_creds.pid\n", msg->nm_creds.pid);
        printf("%d == msg.nm_creds.uid\n", msg->nm_creds.uid);
        printf("%d == msg.nm_creds.gid\n", msg->nm_creds.gid);
        printf("%d == msg.nm_nlh.nlmsg_type\n", msg->nm_nlh->nlmsg_type);
        printf("%d == msg.nm_nlh.nlmsg_flags\n", msg->nm_nlh->nlmsg_flags);
        printf("%d == msg.nm_nlh.nlmsg_pid\n", msg->nm_nlh->nlmsg_pid);
        printf("%d == msg.nm_size\n", msg->nm_size);
        printf("%d == msg.nm_refcnt\n", msg->nm_refcnt);
        dump_hex(stdout, (char *) msg, msg->nm_size, 0);
        return NL_OK;
    }
    int main() {
        struct nl_sock *sk = nl_socket_alloc();
        nl_cb_overwrite_send(sk->s_cb, callback_send);
        printf("%d == genl_connect(sk)\n", genl_connect(sk));
        struct genl_family *ret = (struct genl_family *) genl_family_alloc();
        genl_family_set_name(ret, "nl80211");
        struct nl_msg *msg = nlmsg_alloc();
        genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, GENL_ID_CTRL, 0, 0, CTRL_CMD_GETFAMILY, 1);
        nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, "nl80211");
        nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, callback_recv, NULL);
        printf("%d == nl_send_auto(sk, msg)\n", nl_send_auto(sk, msg));
        printf("%d == nl_recvmsgs_default(sk)\n", nl_recvmsgs_default(sk));
        nl_socket_free(sk);
        return 0;
    }
    // Expected output (trimmed):
    // nl_cache_mngt_register: Registered cache operations genl/family
    // 0 == genl_connect(sk)
    //  nl_object_alloc: Allocated new object 0x2b50b8
    // __nlmsg_alloc: msg 0x2b5110: Allocated new message, maxlen=4096
    // nlmsg_put: msg 0x2b5110: Added netlink header type=16, flags=0, pid=0, seq=0
    // nlmsg_reserve: msg 0x2b5110: Reserved 4 (4) bytes, pad=4, nlmsg_len=20
    // genlmsg_put: msg 0x2b5110: Added generic netlink header cmd=3 version=1
    // nla_reserve: msg 0x2b5110: attr <0x2b5164> 2: Reserved 12 (8) bytes at offset +4 nlmsg_len=32
    // nla_put: msg 0x2b5110: attr <0x2b5164> 2: Wrote 8 bytes at offset +4
    // 16 == msg.nm_protocol
    // 0 == msg.nm_flags
    // 0 == msg.nm_src.nl_family
    // 0 == msg.nm_src.nl_pid
    // 0 == msg.nm_src.nl_groups
    // 0 == msg.nm_dst.nl_family
    // 0 == msg.nm_dst.nl_pid
    // 0 == msg.nm_dst.nl_groups
    // 0 == msg.nm_creds.pid
    // 0 == msg.nm_creds.uid
    // 0 == msg.nm_creds.gid
    // 16 == msg.nm_nlh.nlmsg_type
    // 5 == msg.nm_nlh.nlmsg_flags
    // 26270 == msg.nm_nlh.nlmsg_pid
    // 4096 == msg.nm_size
    // 1 == msg.nm_refcnt
    //     10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
    //     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
    //     00 00 00 00 00 00 00 00 00 00 00 00 50 91 46 00 ............P.F.
    //     00 10 00 00 01 00 00 00 00 00 00 00 09 10 00 00 ................
    //     20 00 00 00 10 00 05 00 ff 7a ea 54 9e 66 00 00  ........z.T.f..
    //     03 01 00 00 0c 00 02 00 6e 6c 38 30 32 31 31 00 ........nl80211.
    //     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
    //     <trimmed>
    //     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
    // nl_sendmsg: sent 32 bytes
    // 32 == nl_send_auto(sk, msg)
    // recvmsgs: Attempting to read from 0x2b5080
    // recvmsgs: recvmsgs(0x2b5080): Read 1836 bytes
    // recvmsgs: recvmsgs(0x2b5080): Processing valid message...
    // __nlmsg_alloc: msg 0x2ba160: Allocated new message, maxlen=1836
    // 16 == msg.nm_protocol
    // 0 == msg.nm_flags
    // 16 == msg.nm_src.nl_family
    // 0 == msg.nm_src.nl_pid
    // 0 == msg.nm_src.nl_groups
    // 0 == msg.nm_dst.nl_family
    // 0 == msg.nm_dst.nl_pid
    // 0 == msg.nm_dst.nl_groups
    // 0 == msg.nm_creds.pid
    // 0 == msg.nm_creds.uid
    // 0 == msg.nm_creds.gid
    // 16 == msg.nm_nlh.nlmsg_type
    // 0 == msg.nm_nlh.nlmsg_flags
    // 25390 == msg.nm_nlh.nlmsg_pid
    // 1836 == msg.nm_size
    // 1 == msg.nm_refcnt
    //     10 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00 ................
    //     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
    //     00 00 00 00 00 00 00 00 00 00 00 00 a0 d1 23 01 ..............#.
    //     2c 07 00 00 01 00 00 00 00 00 00 00 31 07 00 00 ,...........1...
    //     2c 07 00 00 10 00 00 00 02 57 ea 54 89 5b 00 00 ,........W.T.[..
    //     01 02 00 00 0c 00 02 00 6e 6c 38 30 32 31 31 00 ........nl80211.
    //     06 00 01 00 16 00 00 00 08 00 03 00 01 00 00 00 ................
    //     08 00 04 00 00 00 00 00 08 00 05 00 d5 00 00 00 ................
    //     6c 06 06 00 14 00 01 00 08 00 01 00 01 00 00 00 l...............
    //     08 00 02 00 0e 00 00 00 14 00 02 00 08 00 01 00 ................
    //     <trimmed>
    //     63 6f 6e 66 69 67 00 00 18 00 02 00 08 00 02 00 config..........
    //     04 00 00 00 09 00 01 00 73 63 61 6e 00 00 00 00 ........scan....
    //     1c 00 03 00 08 00 02 00 05 00 00 00             ............
    // nlmsg_free: Returned message reference 0x2ba160, 0 remaining
    // nlmsg_free: msg 0x2ba160: Freed
    // 0 == nl_recvmsgs_default(sk)
    // nl_cache_mngt_unregister: Unregistered cache operations genl/family
    """
    def callback_send(sk, msg):
        assert 16 == msg.nm_protocol
        assert 0 == msg.nm_flags
        assert 0 == msg.nm_src.nl_family
        assert 0 == msg.nm_src.nl_pid
        assert 0 == msg.nm_src.nl_groups
        assert 0 == msg.nm_dst.nl_family
        assert 0 == msg.nm_dst.nl_pid
        assert 0 == msg.nm_dst.nl_groups
        assert msg.nm_creds is None
        assert 16 == msg.nm_nlh.nlmsg_type
        assert 5 == msg.nm_nlh.nlmsg_flags
        assert 10000 < msg.nm_nlh.nlmsg_pid
        # assert 4096 == msg.nm_size TODO implement
        assert 1 == msg.nm_refcnt
        # dump_hex(bytes(msg), 0)  TODO test
        iov = bytes(nlmsg_hdr(msg))
        return nl_send_iovec(sk, msg, iov)

    def callback_recv(msg, _):
        assert 16 == msg.nm_protocol
        assert 0 == msg.nm_flags
        assert 16 == msg.nm_src.nl_family
        assert 0 == msg.nm_src.nl_pid
        assert 0 == msg.nm_src.nl_groups
        assert 0 == msg.nm_dst.nl_family
        assert 0 == msg.nm_dst.nl_pid
        assert 0 == msg.nm_dst.nl_groups
        assert msg.nm_creds is None
        assert 16 == msg.nm_nlh.nlmsg_type
        assert 0 == msg.nm_nlh.nlmsg_flags
        assert 10000 < msg.nm_nlh.nlmsg_pid
        assert 1836 == msg.nm_size
        assert 1 == msg.nm_refcnt
        dump_hex(bytes(msg), 0)
        return NL_OK

    log.clear()
    sk_main = nl_socket_alloc()
    nl_cb_overwrite_send(sk_main.s_cb, callback_send)
    genl_connect(sk_main)
    ret = genl_family_alloc()
    genl_family_set_name(ret, b'nl80211')
    msg_main = nlmsg_alloc()
    genlmsg_put(msg_main, NL_AUTO_PORT, NL_AUTO_SEQ, GENL_ID_CTRL, 0, 0, CTRL_CMD_GETFAMILY, 1)
    nla_put_string(msg_main, CTRL_ATTR_FAMILY_NAME, b'nl80211')
    nl_socket_modify_cb(sk_main, NL_CB_VALID, NL_CB_CUSTOM, callback_recv, None)
    assert 32 == nl_send_auto(sk_main, msg_main)
    assert 0 == nl_recvmsgs_default(sk_main)
    nl_socket_free(sk_main)

    assert match('nl_object_alloc: Allocated new object 0x[a-f0-9]+', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message', log, True)
    assert match('nlmsg_put: msg 0x[a-f0-9]+: Added netlink header type=16, flags=0, pid=0, seq=0', log, True)
    assert match('genlmsg_put: msg 0x[a-f0-9]+: Added generic netlink header cmd=3 version=1', log, True)
    assert match('nla_put: msg 0x[a-f0-9]+: attr <0x[a-f0-9]+> 2: Wrote 8 bytes', log, True)
    """ TODO test
    assert match('dump_hex:     10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................', log)
    assert match('dump_hex:     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................', log)
    assert match('dump_hex:     00 00 00 00 00 00 00 00 00 00 00 00 50 .. .. 00 ............P...', log, True)
    assert match('dump_hex:     00 10 00 00 01 00 00 00 00 00 00 00 09 10 00 00 ................', log)
    assert match('dump_hex:     20 00 00 00 10 00 05 00 .. .. ea 54 .. .. 00 00  ..........T....', log, True)
    assert match('dump_hex:     03 01 00 00 0c 00 02 00 6e 6c 38 30 32 31 31 00 ........nl80211.', log)
    for _ in range(250):
        assert match('dump_hex:     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................', log)
    """
    assert match('nl_sendmsg: sent 32 bytes', log)
    assert match('recvmsgs: Attempting to read from 0x[a-f0-9]+', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Read 1836 bytes', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Processing valid message...', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message', log, True)

    assert match('dump_hex:     10 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00 ................', log)
    assert match('dump_hex:     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................', log)
    assert match('dump_hex:     00 00 00 00 00 00 00 00 00 00 00 00 a0 .. .. .. ................', log, True)
    assert match('dump_hex:     2c 07 00 00 01 00 00 00 00 00 00 00 31 07 00 00 ,...........1...', log)
    assert match('dump_hex:     2c 07 00 00 10 00 00 00 .. .. ea 54 .. .. 00 00 ,..........T....', log, True)
    assert match('dump_hex:     01 02 00 00 0c 00 02 00 6e 6c 38 30 32 31 31 00 ........nl80211.', log)
    assert match('dump_hex:     06 00 01 00 16 00 00 00 08 00 03 00 01 00 00 00 ................', log)
    assert match('dump_hex:     08 00 04 00 00 00 00 00 08 00 05 00 d5 00 00 00 ................', log)
    assert match('dump_hex:     6c 06 06 00 14 00 01 00 08 00 01 00 01 00 00 00 l...............', log)
    assert match('dump_hex:     08 00 02 00 0e 00 00 00 14 00 02 00 08 00 01 00 ................', log)
    assert match('dump_hex:     02 00 00 00 08 00 02 00 0b 00 00 00 14 00 03 00 ................', log)
    assert match('dump_hex:     08 00 01 00 05 00 00 00 08 00 02 00 0e 00 00 00 ................', log)
    assert match('dump_hex:     14 00 04 00 08 00 01 00 06 00 00 00 08 00 02 00 ................', log)
    assert match('dump_hex:     0b 00 00 00 14 00 05 00 08 00 01 00 07 00 00 00 ................', log)
    assert match('dump_hex:     08 00 02 00 0b 00 00 00 14 00 06 00 08 00 01 00 ................', log)
    assert match('dump_hex:     08 00 00 00 08 00 02 00 0b 00 00 00 14 00 07 00 ................', log)
    assert match('dump_hex:     08 00 01 00 09 00 00 00 08 00 02 00 0b 00 00 00 ................', log)
    assert match('dump_hex:     14 00 08 00 08 00 01 00 0a 00 00 00 08 00 02 00 ................', log)
    assert match('dump_hex:     0b 00 00 00 14 00 09 00 08 00 01 00 0b 00 00 00 ................', log)
    assert match('dump_hex:     08 00 02 00 0b 00 00 00 14 00 0a 00 08 00 01 00 ................', log)
    assert match('dump_hex:     0c 00 00 00 08 00 02 00 0b 00 00 00 14 00 0b 00 ................', log)
    assert match('dump_hex:     08 00 01 00 0e 00 00 00 08 00 02 00 0b 00 00 00 ................', log)
    assert match('dump_hex:     14 00 0c 00 08 00 01 00 0f 00 00 00 08 00 02 00 ................', log)
    assert match('dump_hex:     0b 00 00 00 14 00 0d 00 08 00 01 00 10 00 00 00 ................', log)
    assert match('dump_hex:     08 00 02 00 0b 00 00 00 14 00 0e 00 08 00 01 00 ................', log)
    assert match('dump_hex:     11 00 00 00 08 00 02 00 0e 00 00 00 14 00 0f 00 ................', log)
    assert match('dump_hex:     08 00 01 00 12 00 00 00 08 00 02 00 0b 00 00 00 ................', log)
    assert match('dump_hex:     14 00 10 00 08 00 01 00 13 00 00 00 08 00 02 00 ................', log)
    assert match('dump_hex:     0b 00 00 00 14 00 11 00 08 00 01 00 14 00 00 00 ................', log)
    assert match('dump_hex:     08 00 02 00 0b 00 00 00 14 00 12 00 08 00 01 00 ................', log)
    assert match('dump_hex:     15 00 00 00 08 00 02 00 0f 00 00 00 14 00 13 00 ................', log)
    assert match('dump_hex:     08 00 01 00 16 00 00 00 08 00 02 00 0b 00 00 00 ................', log)
    assert match('dump_hex:     14 00 14 00 08 00 01 00 17 00 00 00 08 00 02 00 ................', log)
    assert match('dump_hex:     0b 00 00 00 14 00 15 00 08 00 01 00 18 00 00 00 ................', log)
    assert match('dump_hex:     08 00 02 00 0b 00 00 00 14 00 16 00 08 00 01 00 ................', log)
    assert match('dump_hex:     19 00 00 00 08 00 02 00 0b 00 00 00 14 00 17 00 ................', log)
    assert match('dump_hex:     08 00 01 00 1f 00 00 00 08 00 02 00 0a 00 00 00 ................', log)
    assert match('dump_hex:     14 00 18 00 08 00 01 00 1a 00 00 00 08 00 02 00 ................', log)
    assert match('dump_hex:     0b 00 00 00 14 00 19 00 08 00 01 00 1b 00 00 00 ................', log)
    assert match('dump_hex:     08 00 02 00 0b 00 00 00 14 00 1a 00 08 00 01 00 ................', log)
    assert match('dump_hex:     1c 00 00 00 08 00 02 00 0a 00 00 00 14 00 1b 00 ................', log)
    assert match('dump_hex:     08 00 01 00 1d 00 00 00 08 00 02 00 0b 00 00 00 ................', log)
    assert match('dump_hex:     14 00 1c 00 08 00 01 00 21 00 00 00 08 00 02 00 ........!.......', log)
    assert match('dump_hex:     0b 00 00 00 14 00 1d 00 08 00 01 00 20 00 00 00 ............ ...', log)
    assert match('dump_hex:     08 00 02 00 0c 00 00 00 14 00 1e 00 08 00 01 00 ................', log)
    assert match('dump_hex:     4b 00 00 00 08 00 02 00 0b 00 00 00 14 00 1f 00 K...............', log)
    assert match('dump_hex:     08 00 01 00 4c 00 00 00 08 00 02 00 0b 00 00 00 ....L...........', log)
    assert match('dump_hex:     14 00 20 00 08 00 01 00 25 00 00 00 08 00 02 00 .. .....%.......', log)
    assert match('dump_hex:     0b 00 00 00 14 00 21 00 08 00 01 00 26 00 00 00 ......!.....&...', log)
    assert match('dump_hex:     08 00 02 00 0b 00 00 00 14 00 22 00 08 00 01 00 ..........".....', log)
    assert match("dump_hex:     27 00 00 00 08 00 02 00 0b 00 00 00 14 00 23 00 '.............#.", log)
    assert match('dump_hex:     08 00 01 00 28 00 00 00 08 00 02 00 0b 00 00 00 ....(...........', log)
    assert match('dump_hex:     14 00 24 00 08 00 01 00 2b 00 00 00 08 00 02 00 ..$.....+.......', log)
    assert match('dump_hex:     0b 00 00 00 14 00 25 00 08 00 01 00 2c 00 00 00 ......%.....,...', log)
    assert match('dump_hex:     08 00 02 00 0b 00 00 00 14 00 26 00 08 00 01 00 ..........&.....', log)
    assert match("dump_hex:     2e 00 00 00 08 00 02 00 0b 00 00 00 14 00 27 00 ..............'.", log)
    assert match('dump_hex:     08 00 01 00 30 00 00 00 08 00 02 00 0b 00 00 00 ....0...........', log)
    assert match('dump_hex:     14 00 28 00 08 00 01 00 31 00 00 00 08 00 02 00 ..(.....1.......', log)
    assert match('dump_hex:     0b 00 00 00 14 00 29 00 08 00 01 00 32 00 00 00 ......).....2...', log)
    assert match('dump_hex:     08 00 02 00 0c 00 00 00 14 00 2a 00 08 00 01 00 ..........*.....', log)
    assert match('dump_hex:     34 00 00 00 08 00 02 00 0b 00 00 00 14 00 2b 00 4.............+.', log)
    assert match('dump_hex:     08 00 01 00 35 00 00 00 08 00 02 00 0b 00 00 00 ....5...........', log)
    assert match('dump_hex:     14 00 2c 00 08 00 01 00 36 00 00 00 08 00 02 00 ..,.....6.......', log)
    assert match('dump_hex:     0b 00 00 00 14 00 2d 00 08 00 01 00 37 00 00 00 ......-.....7...', log)
    assert match('dump_hex:     08 00 02 00 0b 00 00 00 14 00 2e 00 08 00 01 00 ................', log)
    assert match('dump_hex:     38 00 00 00 08 00 02 00 0b 00 00 00 14 00 2f 00 8............./.', log)
    assert match('dump_hex:     08 00 01 00 39 00 00 00 08 00 02 00 0b 00 00 00 ....9...........', log)
    assert match('dump_hex:     14 00 30 00 08 00 01 00 3a 00 00 00 08 00 02 00 ..0.....:.......', log)
    assert match('dump_hex:     0b 00 00 00 14 00 31 00 08 00 01 00 3b 00 00 00 ......1.....;...', log)
    assert match('dump_hex:     08 00 02 00 0b 00 00 00 14 00 32 00 08 00 01 00 ..........2.....', log)
    assert match('dump_hex:     43 00 00 00 08 00 02 00 0b 00 00 00 14 00 33 00 C.............3.', log)
    assert match('dump_hex:     08 00 01 00 3d 00 00 00 08 00 02 00 0b 00 00 00 ....=...........', log)
    assert match('dump_hex:     14 00 34 00 08 00 01 00 3e 00 00 00 08 00 02 00 ..4.....>.......', log)
    assert match('dump_hex:     0a 00 00 00 14 00 35 00 08 00 01 00 3f 00 00 00 ......5.....?...', log)
    assert match('dump_hex:     08 00 02 00 0b 00 00 00 14 00 36 00 08 00 01 00 ..........6.....', log)
    assert match('dump_hex:     41 00 00 00 08 00 02 00 0b 00 00 00 14 00 37 00 A.............7.', log)
    assert match('dump_hex:     08 00 01 00 42 00 00 00 08 00 02 00 0b 00 00 00 ....B...........', log)
    assert match('dump_hex:     14 00 38 00 08 00 01 00 44 00 00 00 08 00 02 00 ..8.....D.......', log)
    assert match('dump_hex:     0b 00 00 00 14 00 39 00 08 00 01 00 45 00 00 00 ......9.....E...', log)
    assert match('dump_hex:     08 00 02 00 0b 00 00 00 14 00 3a 00 08 00 01 00 ..........:.....', log)
    assert match('dump_hex:     49 00 00 00 08 00 02 00 0a 00 00 00 14 00 3b 00 I.............;.', log)
    assert match('dump_hex:     08 00 01 00 4a 00 00 00 08 00 02 00 0b 00 00 00 ....J...........', log)
    assert match('dump_hex:     14 00 3c 00 08 00 01 00 4f 00 00 00 08 00 02 00 ..<.....O.......', log)
    assert match('dump_hex:     0b 00 00 00 14 00 3d 00 08 00 01 00 52 00 00 00 ......=.....R...', log)
    assert match('dump_hex:     08 00 02 00 0b 00 00 00 14 00 3e 00 08 00 01 00 ..........>.....', log)
    assert match('dump_hex:     51 00 00 00 08 00 02 00 0b 00 00 00 14 00 3f 00 Q.............?.', log)
    assert match('dump_hex:     08 00 01 00 53 00 00 00 08 00 02 00 0b 00 00 00 ....S...........', log)
    assert match('dump_hex:     14 00 40 00 08 00 01 00 54 00 00 00 08 00 02 00 ..@.....T.......', log)
    assert match('dump_hex:     0b 00 00 00 14 00 41 00 08 00 01 00 55 00 00 00 ......A.....U...', log)
    assert match('dump_hex:     08 00 02 00 0b 00 00 00 14 00 42 00 08 00 01 00 ..........B.....', log)
    assert match('dump_hex:     57 00 00 00 08 00 02 00 0b 00 00 00 14 00 43 00 W.............C.', log)
    assert match('dump_hex:     08 00 01 00 59 00 00 00 08 00 02 00 0b 00 00 00 ....Y...........', log)
    assert match('dump_hex:     14 00 44 00 08 00 01 00 5a 00 00 00 08 00 02 00 ..D.....Z.......', log)
    assert match('dump_hex:     0b 00 00 00 14 00 45 00 08 00 01 00 5c 00 00 00 ......E.....\...', log)
    assert match('dump_hex:     08 00 02 00 0b 00 00 00 14 00 46 00 08 00 01 00 ..........F.....', log)
    assert match('dump_hex:     5d 00 00 00 08 00 02 00 0b 00 00 00 14 00 47 00 ].............G.', log)
    assert match('dump_hex:     08 00 01 00 5e 00 00 00 08 00 02 00 0b 00 00 00 ....^...........', log)
    assert match('dump_hex:     14 00 48 00 08 00 01 00 5f 00 00 00 08 00 02 00 ..H....._.......', log)
    assert match('dump_hex:     0a 00 00 00 14 00 49 00 08 00 01 00 60 00 00 00 ......I.....`...', log)
    assert match('dump_hex:     08 00 02 00 0b 00 00 00 14 00 4a 00 08 00 01 00 ..........J.....', log)
    assert match('dump_hex:     62 00 00 00 08 00 02 00 0b 00 00 00 14 00 4b 00 b.............K.', log)
    assert match('dump_hex:     08 00 01 00 63 00 00 00 08 00 02 00 0b 00 00 00 ....c...........', log)
    assert match('dump_hex:     14 00 4c 00 08 00 01 00 64 00 00 00 08 00 02 00 ..L.....d.......', log)
    assert match('dump_hex:     0a 00 00 00 14 00 4d 00 08 00 01 00 65 00 00 00 ......M.....e...', log)
    assert match('dump_hex:     08 00 02 00 0b 00 00 00 14 00 4e 00 08 00 01 00 ..........N.....', log)
    assert match('dump_hex:     66 00 00 00 08 00 02 00 0b 00 00 00 14 00 4f 00 f.............O.', log)
    assert match('dump_hex:     08 00 01 00 67 00 00 00 08 00 02 00 0b 00 00 00 ....g...........', log)
    assert match('dump_hex:     14 00 50 00 08 00 01 00 68 00 00 00 08 00 02 00 ..P.....h.......', log)
    assert match('dump_hex:     0b 00 00 00 14 00 51 00 08 00 01 00 69 00 00 00 ......Q.....i...', log)
    assert match('dump_hex:     08 00 02 00 0b 00 00 00 14 00 52 00 08 00 01 00 ..........R.....', log)
    assert match('dump_hex:     6a 00 00 00 08 00 02 00 0b 00 00 00 80 00 07 00 j...............', log)
    assert match('dump_hex:     18 00 01 00 08 00 02 00 03 00 00 00 0b 00 01 00 ................', log)
    assert match('dump_hex:     63 6f 6e 66 69 67 00 00 18 00 02 00 08 00 02 00 config..........', log)
    assert match('dump_hex:     04 00 00 00 09 00 01 00 73 63 61 6e 00 00 00 00 ........scan....', log)
    assert match('dump_hex:     1c 00 03 00 08 00 02 00 05 00 00 00             ............', log)
    assert not log


@pytest.mark.skipif('True')  # @pytest.mark.usefixtures('nlcb_debug')
def test_genl_ctrl_resolve(log):
    """// gcc $(pkg-config --cflags --libs libnl-genl-3.0) a.c && NLDBG=4 NLCB=debug ./a.out
    #include <netlink/msg.h>
    int main() {
        struct nl_sock *sk = nl_socket_alloc();
        printf("%d == genl_connect(sk)\n", genl_connect(sk));
        int driver_id = genl_ctrl_resolve(sk, "nl80211");
        printf("%d == driver_id\n", driver_id);
        nl_socket_free(sk);
        return 0;
    }
    // Expected output (trimmed):
    // nl_cache_mngt_register: Registered cache operations genl/family
    // 0 == genl_connect(sk)
    //  nl_object_alloc: Allocated new object 0x11fd0b8
    // __nlmsg_alloc: msg 0x11fd110: Allocated new message, maxlen=4096
    // nlmsg_put: msg 0x11fd110: Added netlink header type=16, flags=0, pid=0, seq=0
    // nlmsg_reserve: msg 0x11fd110: Reserved 4 (4) bytes, pad=4, nlmsg_len=20
    // genlmsg_put: msg 0x11fd110: Added generic netlink header cmd=3 version=1
    // nla_reserve: msg 0x11fd110: attr <0x11fd164> 2: Reserved 12 (8) bytes at offset +4 nlmsg_len=32
    // nla_put: msg 0x11fd110: attr <0x11fd164> 2: Wrote 8 bytes at offset +4
    // -- Debug: Sent Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 32
    //     .type = 16 <genl/family::nlctrl>
    //     .flags = 5 <REQUEST,ACK>
    //     .seq = 1424231241
    //     .port = 28482
    //   [GENERIC NETLINK HEADER] 4 octets
    //     .cmd = 3
    //     .version = 1
    //     .unused = 0
    //   [ATTR 02] 8 octets
    //     6e 6c 38 30 32 31 31 00                         nl80211.
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // nl_sendmsg: sent 32 bytes
    // recvmsgs: Attempting to read from 0x11fd080
    // recvmsgs: recvmsgs(0x11fd080): Read 1732 bytes
    // recvmsgs: recvmsgs(0x11fd080): Processing valid message...
    // __nlmsg_alloc: msg 0x12021d8: Allocated new message, maxlen=1732
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 1732
    //     .type = 16 <genl/family::nlctrl>
    //     .flags = 0 <>
    //     .seq = 1424231241
    //     .port = 28482
    //   [GENERIC NETLINK HEADER] 4 octets
    //     .cmd = 1
    //     .version = 2
    //     .unused = 0
    //   [ATTR 02] 8 octets
    //     6e 6c 38 30 32 31 31 00                         nl80211.
    //   [ATTR 01] 2 octets
    //     14 00                                           ..
    //   [PADDING] 2 octets
    //     00 00                                           ..
    //   [ATTR 03] 4 octets
    //     01 00 00 00                                     ....
    //   [ATTR 04] 4 octets
    //     00 00 00 00                                     ....
    //   [ATTR 05] 4 octets
    //     bc 00 00 00                                     ....
    //   [ATTR 06] 1560 octets
    //     14 00 01 00 08 00 01 00 01 00 00 00 08 00 02 00 ................
    //     <trimmed>
    //     08 00 02 00 0b 00 00 00                         ........
    //   [ATTR 07] 100 octets
    //     18 00 01 00 08 00 02 00 02 00 00 00 0b 00 01 00 ................
    //     63 6f 6e 66 69 67 00 00 18 00 02 00 08 00 02 00 config..........
    //     03 00 00 00 09 00 01 00 73 63 61 6e 00 00 00 00 ........scan....
    //     1c 00 03 00 08 00 02 00 04 00 00 00 0f 00 01 00 ................
    //     72 65 67 75 6c 61 74 6f 72 79 00 00 18 00 04 00 regulatory......
    //     08 00 02 00 05 00 00 00 09 00 01 00 6d 6c 6d 65 ............mlme
    //     00 00 00 00                                     ....
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // nlmsg_free: Returned message reference 0x12021d8, 0 remaining
    // nlmsg_free: msg 0x12021d8: Freed
    // recvmsgs: Attempting to read from 0x11fd080
    // recvmsgs: recvmsgs(0x11fd080): Read 36 bytes
    // recvmsgs: recvmsgs(0x11fd080): Processing valid message...
    // __nlmsg_alloc: msg 0x12021d8: Allocated new message, maxlen=36
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 36
    //     .type = 2 <ERROR>
    //     .flags = 0 <>
    //     .seq = 1424231241
    //     .port = 28482
    //   [ERRORMSG] 20 octets
    //     .error = 0 "Success"
    //   [ORIGINAL MESSAGE] 16 octets
    // __nlmsg_alloc: msg 0x12022b8: Allocated new message, maxlen=4096
    //     .nlmsg_len = 16
    //     .type = 16 <0x10>
    //     .flags = 5 <REQUEST,ACK>
    //     .seq = 1424231241
    //     .port = 28482
    // nlmsg_free: Returned message reference 0x12022b8, 0 remaining
    // nlmsg_free: msg 0x12022b8: Freed
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // recvmsgs: recvmsgs(0x11fd080): Increased expected sequence number to 1424231242
    // nlmsg_free: Returned message reference 0x12021d8, 0 remaining
    // nlmsg_free: msg 0x12021d8: Freed
    // nlmsg_free: Returned message reference 0x11fd110, 0 remaining
    // nlmsg_free: msg 0x11fd110: Freed
    // nl_object_put: Returned object reference 0x11fd0b8, 0 remaining
    // nl_object_free: Freed object 0x11fd0b8
    // 20 == driver_id
    // nl_cache_mngt_unregister: Unregistered cache operations genl/family
    """
    log.clear()

    sk = nl_socket_alloc()
    assert 0 == genl_connect(sk)
    assert not log
    assert 20 == genl_ctrl_resolve(sk, b'nl80211')

    assert match('nl_object_alloc: Allocated new object 0x[a-f0-9]+', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message', log, True)
    assert match('nlmsg_put: msg 0x[a-f0-9]+: Added netlink header type=16, flags=0, pid=0, seq=0', log, True)
    assert match('genlmsg_put: msg 0x[a-f0-9]+: Added generic netlink header cmd=3 version=1', log, True)
    assert match('nla_put: msg 0x[a-f0-9]+: attr <0x[a-f0-9]+> 2: Wrote 8 bytes', log, True)
    assert match('nl_msg_out_handler_debug: -- Debug: Sent Message:', log)
    assert match('nl_msg_dump: --------------------------   BEGIN NETLINK MESSAGE ---------------------------', log)
    assert match('nl_msg_dump:   [NETLINK HEADER] 16 octets', log)
    assert match('print_hdr:     .nlmsg_len = 32', log)
    assert match('print_hdr:     .type = 16 <genl/family::nlctrl>', log)
    assert match('print_hdr:     .flags = 5 <REQUEST,ACK>', log)
    assert match('print_hdr:     .seq = \d{10}', log, True)
    assert match('print_hdr:     .port = \d{3,}', log, True)
    assert match('print_genl_hdr:   [GENERIC NETLINK HEADER] 4 octets', log)
    assert match('print_genl_hdr:     .cmd = 3', log)
    assert match('print_genl_hdr:     .version = 1', log)
    assert match('print_genl_hdr:     .unused = 0', log)
    assert match('dump_attrs:   [ATTR 02] 8 octets', log)
    assert match('dump_hex:     6e 6c 38 30 32 31 31 00                         nl80211.', log)
    assert match('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------', log)
    assert match('nl_sendmsg: sent 32 bytes', log)

    assert match('recvmsgs: Attempting to read from 0x[a-f0-9]+', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Read \d{4,} bytes', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Processing valid message...', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message', log, True)
    assert match('nl_msg_in_handler_debug: -- Debug: Received Message:', log)
    assert match('nl_msg_dump: --------------------------   BEGIN NETLINK MESSAGE ---------------------------', log)
    assert match('nl_msg_dump:   [NETLINK HEADER] 16 octets', log)
    assert match('print_hdr:     .nlmsg_len = \d{4,}', log, True)
    assert match('print_hdr:     .type = 16 <genl/family::nlctrl>', log)
    assert match('print_hdr:     .flags = 0 <>', log)
    assert match('print_hdr:     .seq = \d{10}', log, True)
    assert match('print_hdr:     .port = \d{3,}', log, True)
    assert match('print_genl_hdr:   [GENERIC NETLINK HEADER] 4 octets', log)
    assert match('print_genl_hdr:     .cmd = 1', log)
    assert match('print_genl_hdr:     .version = 2', log)
    assert match('print_genl_hdr:     .unused = 0', log)
    assert match('dump_attrs:   [ATTR 02] 8 octets', log)
    assert match('dump_hex:     6e 6c 38 30 32 31 31 00                         nl80211.', log)
    assert match('dump_attrs:   [ATTR 01] 2 octets', log)
    assert match('dump_hex:     14 00                                           ..', log)
    assert match('dump_attrs:   [ATTR 03] 4 octets', log)
    assert match('dump_hex:     01 00 00 00                                     ....', log)
    assert match('dump_attrs:   [ATTR 04] 4 octets', log)
    assert match('dump_hex:     00 00 00 00                                     ....', log)
    assert match('dump_attrs:   [ATTR 05] 4 octets', log)
    assert match('dump_hex:     .. 00 00 00                                     ....', log, True)
    assert match('dump_attrs:   \[ATTR 06\] \d{4,} octets', log, True)
    assert match('dump_hex:     14 00 01 00 08 00 01 00 01 00 00 00 08 00 02 00 ................', log)

    # Done testing this payload. Too big.
    rem = log.index('dump_hex:     08 00 02 00 0b 00 00 00                         ........')
    assert 20 < rem  # At least check that there were a lot of log statements skipped.
    log = log[rem:]

    assert match('dump_hex:     08 00 02 00 0b 00 00 00                         ........', log)
    assert match('dump_attrs:   [ATTR 07] 100 octets', log)
    assert match('dump_hex:     18 00 01 00 08 00 02 00 02 00 00 00 0b 00 01 00 ................', log)
    assert match('dump_hex:     63 6f 6e 66 69 67 00 00 18 00 02 00 08 00 02 00 config..........', log)
    assert match('dump_hex:     03 00 00 00 09 00 01 00 73 63 61 6e 00 00 00 00 ........scan....', log)
    assert match('dump_hex:     1c 00 03 00 08 00 02 00 04 00 00 00 0f 00 01 00 ................', log)
    assert match('dump_hex:     72 65 67 75 6c 61 74 6f 72 79 00 00 18 00 04 00 regulatory......', log)
    assert match('dump_hex:     08 00 02 00 05 00 00 00 09 00 01 00 6d 6c 6d 65 ............mlme', log)
    assert match('dump_hex:     00 00 00 00                                     ....', log)
    assert match('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------', log)

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
    assert match('print_hdr:     .port = \d{3,}', log, True)
    assert match('  [ERRORMSG] 20 octets', log)
    assert match('print_hdr:     .error = 0 "Success"', log)
    assert match('  [ORIGINAL MESSAGE] 16 octets', log)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message', log, True)
    assert match('print_hdr:     .nlmsg_len = 16', log)
    assert match('print_hdr:     .type = 16 <0x[a-f0-9]+>', log, True)
    assert match('print_hdr:     .flags = 5 <REQUEST,ACK>', log)
    assert match('print_hdr:     .seq = \d{10}', log, True)
    assert match('print_hdr:     .port = \d{3,}', log, True)
    assert match('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------', log)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Increased expected sequence number to \d{10}', log, True)

    assert not log
