import logging
import re

import pytest

from libnl.attr import nla_put_string
from libnl.genl.ctrl import genl_ctrl_probe_by_name, genl_ctrl_resolve
from libnl.genl.family import genl_family_alloc, genl_family_set_name
from libnl.genl.genl import genl_connect, genlmsg_put
from libnl.handlers import NL_CB_CUSTOM, nl_cb_overwrite_recv, nl_cb_overwrite_send, NL_CB_VALID, NL_OK
from libnl.linux_private.genetlink import CTRL_ATTR_FAMILY_NAME, CTRL_CMD_GETFAMILY, GENL_ID_CTRL
from libnl.msg import dump_hex, NL_AUTO_PORT, NL_AUTO_SEQ, nlmsg_alloc, nlmsg_hdr
from libnl.msg_ import nlmsg_datalen
from libnl.nl import nl_recv, nl_recvmsgs_default, nl_send_auto, nl_send_iovec
from libnl.socket_ import nl_socket_alloc, nl_socket_free, nl_socket_modify_cb


def match(expected, log, is_regex=False):
    log_statement = log.pop(0)
    if is_regex:
        assert re.match(expected + '$', log_statement)
    else:
        assert expected == log_statement
    return True


@pytest.mark.skipif('not os.path.exists("/sys/module/mac80211")')
def test_ctrl_cmd_getfamily_hex_dump(log):
    """// gcc a.c $(pkg-config --cflags --libs libnl-genl-3.0) && NLDBG=4 ./a.out
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
        struct iovec iov = { .iov_base = (void *) nlmsg_hdr(msg), .iov_len = nlmsg_hdr(msg)->nlmsg_len, };
        dump_hex(stdout, iov.iov_base, iov.iov_len, 0);
        return nl_send_iovec(sk, msg, &iov, 1);
    }
    static int callback_recv(struct nl_sock *sk, struct sockaddr_nl *nla, unsigned char **buf, struct ucred **creds) {
        int n = nl_recv(sk, nla, buf, creds);
        dump_hex(stdout, (void *) *buf, n, 0);
        return n;
    }
    static int callback_recv_msg(struct nl_msg *msg, void *arg) {
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
        dump_hex(stdout, (char *) msg->nm_nlh, nlmsg_datalen(msg->nm_nlh), 0);
        return NL_OK;
    }
    int main() {
        struct nl_sock *sk = nl_socket_alloc();
        nl_cb_overwrite_send(sk->s_cb, callback_send);
        nl_cb_overwrite_recv(sk->s_cb, callback_recv);
        printf("%d == genl_connect(sk)\n", genl_connect(sk));
        struct genl_family *ret = (struct genl_family *) genl_family_alloc();
        genl_family_set_name(ret, "nl80211");
        struct nl_msg *msg = nlmsg_alloc();
        genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, GENL_ID_CTRL, 0, 0, CTRL_CMD_GETFAMILY, 1);
        nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, "nl80211");
        nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, callback_recv_msg, NULL);
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
    // 14272 == msg.nm_nlh.nlmsg_pid
    // 4096 == msg.nm_size
    // 1 == msg.nm_refcnt
    //     20 00 00 00 10 00 05 00 af aa f6 54 c0 37 00 00  ..........T.7..
    //     03 01 00 00 0c 00 02 00 6e 6c 38 30 32 31 31 00 ........nl80211.
    // nl_sendmsg: sent 32 bytes
    // 32 == nl_send_auto(sk, msg)
    // recvmsgs: Attempting to read from 0x2b5080
    //     2c 07 00 00 10 00 00 00 af aa f6 54 c0 37 00 00 ,..........T.7..
    //     01 02 00 00 0c 00 02 00 6e 6c 38 30 32 31 31 00 ........nl80211.
    //     06 00 01 00 16 00 00 00 08 00 03 00 01 00 00 00 ................
    //     08 00 04 00 00 00 00 00 08 00 05 00 d5 00 00 00 ................
    //     6c 06 06 00 14 00 01 00 08 00 01 00 01 00 00 00 l...............
    //     08 00 02 00 0e 00 00 00 14 00 02 00 08 00 01 00 ................
    //     <trimmed>
    //     63 6f 6e 66 69 67 00 00 18 00 02 00 08 00 02 00 config..........
    //     04 00 00 00 09 00 01 00 73 63 61 6e 00 00 00 00 ........scan....
    //     1c 00 03 00 08 00 02 00 05 00 00 00 0f 00 01 00 ................
    //     72 65 67 75 6c 61 74 6f 72 79 00 00 18 00 04 00 regulatory......
    //     08 00 02 00 06 00 00 00 09 00 01 00 6d 6c 6d 65 ............mlme
    //     00 00 00 00 18 00 05 00 08 00 02 00 07 00 00 00 ................
    //     0b 00 01 00 76 65 6e 64 6f 72 00 00             ....vendor..
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
    // 14272 == msg.nm_nlh.nlmsg_pid
    // 1836 == msg.nm_size
    // 1 == msg.nm_refcnt
    //     2c 07 00 00 10 00 00 00 af aa f6 54 c0 37 00 00 ,..........T.7..
    //     01 02 00 00 0c 00 02 00 6e 6c 38 30 32 31 31 00 ........nl80211.
    //     06 00 01 00 16 00 00 00 08 00 03 00 01 00 00 00 ................
    //     08 00 04 00 00 00 00 00 08 00 05 00 d5 00 00 00 ................
    //     6c 06 06 00 14 00 01 00 08 00 01 00 01 00 00 00 l...............
    //     08 00 02 00 0e 00 00 00 14 00 02 00 08 00 01 00 ................
    //     <trimmed>
    //     63 6f 6e 66 69 67 00 00 18 00 02 00 08 00 02 00 config..........
    //     04 00 00 00 09 00 01 00 73 63 61 6e 00 00 00 00 ........scan....
    //     1c 00 03 00 08 00 02 00 05 00 00 00 0f 00 01 00 ................
    //     72 65 67 75 6c 61 74 6f 72 79 00 00 18 00 04 00 regulatory......
    //     08 00 02 00 06 00 00 00 09 00 01 00 6d 6c 6d 65 ............mlme
    //     00 00 00 00 18 00 05 00 08 00 02 00             ............
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
        assert 100 < msg.nm_nlh.nlmsg_pid
        assert 1 == msg.nm_refcnt
        hdr = nlmsg_hdr(msg)
        iov = hdr.bytearray[:hdr.nlmsg_len]
        dump_hex(logging.getLogger().debug, iov, len(iov), 0)
        return nl_send_iovec(sk, msg, iov, 1)

    def callback_recv(sk, nla, buf, creds):
        n = nl_recv(sk, nla, buf, creds)
        dump_hex(logging.getLogger().debug, buf, len(buf), 0)
        return n

    def callback_recv_msg(msg, _):
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
        assert 100 < msg.nm_nlh.nlmsg_pid
        assert 1000 < msg.nm_size
        assert 1 == msg.nm_refcnt
        dump_hex(logging.getLogger().debug, msg.nm_nlh.bytearray, nlmsg_datalen(msg.nm_nlh), 0)
        return NL_OK

    del log[:]
    sk_main = nl_socket_alloc()
    nl_cb_overwrite_send(sk_main.s_cb, callback_send)
    nl_cb_overwrite_recv(sk_main.s_cb, callback_recv)
    genl_connect(sk_main)
    ret = genl_family_alloc()
    genl_family_set_name(ret, b'nl80211')
    msg_main = nlmsg_alloc()
    genlmsg_put(msg_main, NL_AUTO_PORT, NL_AUTO_SEQ, GENL_ID_CTRL, 0, 0, CTRL_CMD_GETFAMILY, 1)
    nla_put_string(msg_main, CTRL_ATTR_FAMILY_NAME, b'nl80211')
    nl_socket_modify_cb(sk_main, NL_CB_VALID, NL_CB_CUSTOM, callback_recv_msg, None)
    assert 32 == nl_send_auto(sk_main, msg_main)
    assert 0 == nl_recvmsgs_default(sk_main)
    nl_socket_free(sk_main)

    assert match('nl_object_alloc: Allocated new object 0x[a-f0-9]+', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message, maxlen=4096', log, True)
    assert match('nlmsg_put: msg 0x[a-f0-9]+: Added netlink header type=16, flags=0, pid=0, seq=0', log, True)
    assert match('nlmsg_reserve: msg 0x[a-f0-9]+: Reserved 4 \(4\) bytes, pad=4, nlmsg_len=20', log, True)
    assert match('genlmsg_put: msg 0x[a-f0-9]+: Added generic netlink header cmd=3 version=1', log, True)
    assert match(
        'nla_reserve: msg 0x[a-f0-9]+: attr <0x[a-f0-9]+> 2: Reserved 12 \(8\) bytes at offset \+4 nlmsg_len=32',
        log, True)
    assert match('nla_put: msg 0x[a-f0-9]+: attr <0x[a-f0-9]+> 2: Wrote 8 bytes at offset \+4', log, True)

    assert match('dump_hex:     20 00 00 00 10 00 05 00 .. .. .. .. .. .. 00 00  ...............', log, True)
    assert match('dump_hex:     03 01 00 00 0c 00 02 00 6e 6c 38 30 32 31 31 00 ........nl80211.', log)

    assert match('nl_sendmsg: sent 32 bytes', log)
    assert match('recvmsgs: Attempting to read from 0x[a-f0-9]+', log, True)

    assert match('dump_hex:     .. .. 00 00 10 00 00 00 .. .. .. .. .. .. 00 00 ................', log, True)
    assert match('dump_hex:     01 02 00 00 0c 00 02 00 6e 6c 38 30 32 31 31 00 ........nl80211.', log)
    assert match('dump_hex:     06 00 01 00 .. 00 00 00 08 00 03 00 01 00 00 00 ................', log, True)
    assert match('dump_hex:     08 00 04 00 00 00 00 00 08 00 05 00 .. 00 00 00 ................', log, True)

    for i in range(len(log)):
        if re.match(r'recvmsgs: recvmsgs\(0x[a-f0-9]+\): Read \d{4,} bytes', log[i]):
            log = log[i:]
            break

    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Read \d{3,} bytes', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Processing valid message...', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message, maxlen=\d{3,}', log, True)

    assert match('dump_hex:     .. .. 00 00 10 00 00 00 .. .. .. .. .. .. 00 00 ................', log, True)
    assert match('dump_hex:     01 02 00 00 0c 00 02 00 6e 6c 38 30 32 31 31 00 ........nl80211.', log)
    assert match('dump_hex:     06 00 01 00 .. 00 00 00 08 00 03 00 01 00 00 00 ................', log, True)
    assert match('dump_hex:     08 00 04 00 00 00 00 00 08 00 05 00 .. 00 00 00 ................', log, True)

    while log and log[0].startswith('dump_hex:'):
        log.pop(0)
    assert not log


@pytest.mark.skipif('not os.path.exists("/sys/module/mac80211")')
def test_genl_ctrl_probe_by_name():
    """// gcc a.c $(pkg-config --cflags --libs libnl-genl-3.0) && ./a.out
    #include <netlink/msg.h>
    #define NL_NO_AUTO_ACK (1<<4)
    struct nl_sock {
        struct sockaddr_nl s_local; struct sockaddr_nl s_peer; int s_fd; int s_proto; unsigned int s_seq_next;
        unsigned int s_seq_expect; int s_flags; struct nl_cb *s_cb; size_t s_bufsize;
    };
    struct genl_family {
        int ce_refcnt; struct nl_object_ops *ce_ops; struct nl_cache *ce_cache; struct nl_list_head ce_list;
        int ce_msgtype; int ce_flags; uint32_t ce_mask; uint16_t gf_id; char gf_name[GENL_NAMSIZ]; uint32_t gf_version;
        uint32_t gf_hdrsize; uint32_t gf_maxattr; struct nl_list_head gf_ops; struct nl_list_head gf_mc_grps;
    };
    static struct nla_policy ctrl_policy[CTRL_ATTR_MAX+1] = {
        [CTRL_ATTR_FAMILY_ID] = { .type = NLA_U16 },
        [CTRL_ATTR_FAMILY_NAME] = { .type = NLA_STRING, .maxlen = GENL_NAMSIZ },
        [CTRL_ATTR_VERSION] = { .type = NLA_U32 }, [CTRL_ATTR_HDRSIZE] = { .type = NLA_U32 },
        [CTRL_ATTR_MAXATTR] = { .type = NLA_U32 }, [CTRL_ATTR_OPS] = { .type = NLA_NESTED },
        [CTRL_ATTR_MCAST_GROUPS] = { .type = NLA_NESTED },
    };
    static struct nla_policy family_grp_policy[CTRL_ATTR_MCAST_GRP_MAX+1] = {
        [CTRL_ATTR_MCAST_GRP_NAME] = { .type = NLA_STRING }, [CTRL_ATTR_MCAST_GRP_ID] = { .type = NLA_U32 },
    };
    static inline int wait_for_ack(struct nl_sock *sk) {
        if (sk->s_flags & NL_NO_AUTO_ACK) return 0;
        else return nl_wait_for_ack(sk);
    }
    static int parse_mcast_grps(struct genl_family *family, struct nlattr *grp_attr) {
        struct nlattr *nla; int remaining, err;
        nla_for_each_nested(nla, grp_attr, remaining) {
            struct nlattr *tb[CTRL_ATTR_MCAST_GRP_MAX+1];
            int id;
            const char *name;
            err = nla_parse_nested(tb, CTRL_ATTR_MCAST_GRP_MAX, nla, family_grp_policy);
            if (err < 0) goto errout;
            if (tb[CTRL_ATTR_MCAST_GRP_ID] == NULL) { err = -NLE_MISSING_ATTR; goto errout; }
            id = nla_get_u32(tb[CTRL_ATTR_MCAST_GRP_ID]);
            if (tb[CTRL_ATTR_MCAST_GRP_NAME] == NULL) { err = -NLE_MISSING_ATTR; goto errout; }
            name = nla_get_string(tb[CTRL_ATTR_MCAST_GRP_NAME]);
            err = genl_family_add_grp(family, id, name);
            if (err < 0) goto errout;
        }
        err = 0;
        errout:
            return err;
    }
    static int probe_response(struct nl_msg *msg, void *arg) {
        struct nlattr *tb[CTRL_ATTR_MAX+1];
        struct nlmsghdr *nlh = nlmsg_hdr(msg);
        struct genl_family *ret = (struct genl_family *)arg;
        if (genlmsg_parse(nlh, 0, tb, CTRL_ATTR_MAX, ctrl_policy)) return NL_SKIP;
        if (tb[CTRL_ATTR_FAMILY_ID]) genl_family_set_id(ret, nla_get_u16(tb[CTRL_ATTR_FAMILY_ID]));
        if (tb[CTRL_ATTR_MCAST_GROUPS])
            if (parse_mcast_grps(ret, tb[CTRL_ATTR_MCAST_GROUPS]) < 0)
                return NL_SKIP;
        return NL_STOP;
    }
    static struct genl_family *genl_ctrl_probe_by_name(struct nl_sock *sk, const char *name) {
        struct nl_msg *msg;
        struct genl_family *ret;
        struct nl_cb *cb, *orig;
        int rc;
        ret = (struct genl_family *) genl_family_alloc();
        if (!ret) goto out;
        genl_family_set_name(ret, name);
        msg = nlmsg_alloc();
        if (!msg) goto out_fam_free;
        if (!(orig = nl_socket_get_cb(sk))) goto out_msg_free;
        cb = nl_cb_clone(orig);
        nl_cb_put(orig);
        if (!cb) goto out_msg_free;
        if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, GENL_ID_CTRL, 0, 0, CTRL_CMD_GETFAMILY, 1)) goto out_cb_free;
        if (nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, name) < 0) goto out_cb_free;
        rc = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, probe_response, (void *) ret);
        if (rc < 0) goto out_cb_free;
        rc = nl_send_auto_complete(sk, msg);
        if (rc < 0) goto out_cb_free;
        rc = nl_recvmsgs(sk, cb);
        if (rc < 0) goto out_cb_free;
        rc = wait_for_ack(sk);
        if (rc < 0) goto out_cb_free;
        if (genl_family_get_id(ret) != 0) {
            nlmsg_free(msg);
            nl_cb_put(cb);
            return ret;
        }
        out_cb_free:
            nl_cb_put(cb);
        out_msg_free:
            nlmsg_free(msg);
        out_fam_free:
            genl_family_put(ret);
        ret = NULL;
        out:
            return ret;
    }
    int main() {
        struct nl_sock *sk = nl_socket_alloc();
        printf("%d == genl_connect(sk)\n", genl_connect(sk));
        struct genl_family *ret = genl_ctrl_probe_by_name(sk, "nl80211");
        printf("%d == ret.ce_msgtype\n", ret->ce_msgtype);
        printf("%d == ret.ce_flags\n", ret->ce_flags);
        printf("%d == ret.ce_mask\n", ret->ce_mask);
        printf("%d == ret.gf_id\n", ret->gf_id);
        printf("%s == ret.gf_name\n", ret->gf_name);
        printf("%d == ret.gf_version\n", ret->gf_version);
        printf("%d == ret.gf_hdrsize\n", ret->gf_hdrsize);
        printf("%d == ret.gf_maxattr\n", ret->gf_maxattr);
        nl_socket_free(sk);
        return 0;
    }
    // Expected output:
    // 0 == genl_connect(sk)
    // 0 == ret.ce_msgtype
    // 0 == ret.ce_flags
    // 3 == ret.ce_mask
    // 22 == ret.gf_id
    // nl80211 == ret.gf_name
    // 0 == ret.gf_version
    // 0 == ret.gf_hdrsize
    // 0 == ret.gf_maxattr
    """
    sk = nl_socket_alloc()
    assert 0 == genl_connect(sk)
    ret = genl_ctrl_probe_by_name(sk, b'nl80211')
    assert 0 == ret.ce_msgtype
    assert 0 == ret.ce_flags
    assert 3 == ret.ce_mask
    assert 20 <= ret.gf_id
    assert b'nl80211' == ret.gf_name
    assert 0 == ret.gf_version
    assert 0 == ret.gf_hdrsize
    assert 0 == ret.gf_maxattr
    nl_socket_free(sk)


@pytest.mark.skipif('not os.path.exists("/sys/module/mac80211")')
@pytest.mark.usefixtures('nlcb_debug')
def test_genl_ctrl_resolve(log):
    """// gcc a.c $(pkg-config --cflags --libs libnl-genl-3.0) && NLDBG=4 NLCB=debug ./a.out
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
    //  nl_object_alloc: Allocated new object 0x6f90b8
    // __nlmsg_alloc: msg 0x6f9110: Allocated new message, maxlen=4096
    // nlmsg_put: msg 0x6f9110: Added netlink header type=16, flags=0, pid=0, seq=0
    // nlmsg_reserve: msg 0x6f9110: Reserved 4 (4) bytes, pad=4, nlmsg_len=20
    // genlmsg_put: msg 0x6f9110: Added generic netlink header cmd=3 version=1
    // nla_reserve: msg 0x6f9110: attr <0x6f9164> 2: Reserved 12 (8) bytes at offset +4 nlmsg_len=32
    // nla_put: msg 0x6f9110: attr <0x6f9164> 2: Wrote 8 bytes at offset +4
    // -- Debug: Sent Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 32
    //     .type = 16 <genl/family::nlctrl>
    //     .flags = 5 <REQUEST,ACK>
    //     .seq = 1425769691
    //     .port = 2568
    //   [GENERIC NETLINK HEADER] 4 octets
    //     .cmd = 3
    //     .version = 1
    //     .unused = 0
    //   [ATTR 02] 8 octets
    //     6e 6c 38 30 32 31 31 00                         nl80211.
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // nl_sendmsg: sent 32 bytes
    // recvmsgs: Attempting to read from 0x6f9080
    // recvmsgs: recvmsgs(0x6f9080): Read 1836 bytes
    // recvmsgs: recvmsgs(0x6f9080): Processing valid message...
    // __nlmsg_alloc: msg 0x6fe1d8: Allocated new message, maxlen=1836
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 1836
    //     .type = 16 <genl/family::nlctrl>
    //     .flags = 0 <>
    //     .seq = 1425769691
    //     .port = 2568
    //   [GENERIC NETLINK HEADER] 4 octets
    //     .cmd = 1
    //     .version = 2
    //     .unused = 0
    //   [ATTR 02] 8 octets
    //     6e 6c 38 30 32 31 31 00                         nl80211.
    //   [ATTR 01] 2 octets
    //     16 00                                           ..
    //   [PADDING] 2 octets
    //     00 00                                           ..
    //   [ATTR 03] 4 octets
    //     01 00 00 00                                     ....
    //   [ATTR 04] 4 octets
    //     00 00 00 00                                     ....
    //   [ATTR 05] 4 octets
    //     d5 00 00 00                                     ....
    //   [ATTR 06] 1640 octets
    //     14 00 01 00 08 00 01 00 01 00 00 00 08 00 02 00 ................
    //     <trimmed>
    //     08 00 02 00 0b 00 00 00                         ........
    //   [ATTR 07] 124 octets
    //     18 00 01 00 08 00 02 00 03 00 00 00 0b 00 01 00 ................
    //     63 6f 6e 66 69 67 00 00 18 00 02 00 08 00 02 00 config..........
    //     04 00 00 00 09 00 01 00 73 63 61 6e 00 00 00 00 ........scan....
    //     1c 00 03 00 08 00 02 00 05 00 00 00 0f 00 01 00 ................
    //     72 65 67 75 6c 61 74 6f 72 79 00 00 18 00 04 00 regulatory......
    //     08 00 02 00 06 00 00 00 09 00 01 00 6d 6c 6d 65 ............mlme
    //     00 00 00 00 18 00 05 00 08 00 02 00 07 00 00 00 ................
    //     0b 00 01 00 76 65 6e 64 6f 72 00 00             ....vendor..
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // nlmsg_free: Returned message reference 0x6fe1d8, 0 remaining
    // nlmsg_free: msg 0x6fe1d8: Freed
    // recvmsgs: Attempting to read from 0x6f9080
    // recvmsgs: recvmsgs(0x6f9080): Read 36 bytes
    // recvmsgs: recvmsgs(0x6f9080): Processing valid message...
    // __nlmsg_alloc: msg 0x6fe1d8: Allocated new message, maxlen=36
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 36
    //     .type = 2 <ERROR>
    //     .flags = 0 <>
    //     .seq = 1425769691
    //     .port = 2568
    //   [ERRORMSG] 20 octets
    //     .error = 0 "Success"
    //   [ORIGINAL MESSAGE] 16 octets
    // __nlmsg_alloc: msg 0x6fe2b8: Allocated new message, maxlen=4096
    //     .nlmsg_len = 16
    //     .type = 16 <0x10>
    //     .flags = 5 <REQUEST,ACK>
    //     .seq = 1425769691
    //     .port = 2568
    // nlmsg_free: Returned message reference 0x6fe2b8, 0 remaining
    // nlmsg_free: msg 0x6fe2b8: Freed
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // recvmsgs: recvmsgs(0x6f9080): Increased expected sequence number to 1425769692
    // nlmsg_free: Returned message reference 0x6fe1d8, 0 remaining
    // nlmsg_free: msg 0x6fe1d8: Freed
    // nlmsg_free: Returned message reference 0x6f9110, 0 remaining
    // nlmsg_free: msg 0x6f9110: Freed
    // nl_object_put: Returned object reference 0x6f90b8, 0 remaining
    // nl_object_free: Freed object 0x6f90b8
    // 22 == driver_id
    // nl_cache_mngt_unregister: Unregistered cache operations genl/family
    """
    del log[:]

    sk = nl_socket_alloc()
    assert 0 == genl_connect(sk)
    assert not log
    assert 20 <= genl_ctrl_resolve(sk, b'nl80211')
    nl_socket_free(sk)

    assert match('nl_object_alloc: Allocated new object 0x[a-f0-9]+', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message, maxlen=4096', log, True)
    assert match('nlmsg_put: msg 0x[a-f0-9]+: Added netlink header type=16, flags=0, pid=0, seq=0', log, True)
    assert match('nlmsg_reserve: msg 0x[a-f0-9]+: Reserved 4 \(4\) bytes, pad=4, nlmsg_len=20', log, True)
    assert match('genlmsg_put: msg 0x[a-f0-9]+: Added generic netlink header cmd=3 version=1', log, True)
    assert match(
        'nla_reserve: msg 0x[a-f0-9]+: attr <0x[a-f0-9]+> 2: Reserved 12 \(8\) bytes at offset \+4 nlmsg_len=32',
        log, True)
    assert match('nla_put: msg 0x[a-f0-9]+: attr <0x[a-f0-9]+> 2: Wrote 8 bytes at offset \+4', log, True)
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
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Read \d{3,} bytes', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Processing valid message...', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message, maxlen=\d{3,}', log, True)
    assert match('nl_msg_in_handler_debug: -- Debug: Received Message:', log)
    assert match('nl_msg_dump: --------------------------   BEGIN NETLINK MESSAGE ---------------------------', log)
    assert match('nl_msg_dump:   [NETLINK HEADER] 16 octets', log)
    assert match('print_hdr:     .nlmsg_len = \d{3,}', log, True)
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
    assert match('dump_hex:     .. 00                                           ..', log, True)
    assert match('dump_attrs:   [PADDING] 2 octets', log)
    assert match('dump_hex:     00 00                                           ..', log)
    assert match('dump_attrs:   [ATTR 03] 4 octets', log)
    assert match('dump_hex:     01 00 00 00                                     ....', log)
    assert match('dump_attrs:   [ATTR 04] 4 octets', log)
    assert match('dump_hex:     00 00 00 00                                     ....', log)
    assert match('dump_attrs:   [ATTR 05] 4 octets', log)
    assert match('dump_hex:     .. 00 00 00                                     ....', log, True)
    assert match('dump_attrs:   \[ATTR 06\] \d{4,} octets', log, True)
    assert match('dump_hex:     14 00 01 00 08 00 01 00 01 00 00 00 08 00 02 00 ................', log)

    # Done testing this payload. Too big.
    for line in log:
        if line.startswith('dump_hex'):
            continue
        rem = log.index(line)
        assert 20 < rem  # At least check that there were a lot of log statements skipped.
        log = log[rem:]
        break

    assert match('dump_attrs:   \[ATTR 07\] \d{3,} octets', log, True)
    assert match('dump_hex:     18 00 01 00 08 00 02 00 .. 00 00 00 0b 00 01 00 ................', log, True)
    assert match('dump_hex:     63 6f 6e 66 69 67 00 00 18 00 02 00 08 00 02 00 config..........', log)
    assert match('dump_hex:     .. 00 00 00 09 00 01 00 73 63 61 6e 00 00 00 00 ........scan....', log, True)
    assert match('dump_hex:     1c 00 03 00 08 00 02 00 .. 00 00 00 0f 00 01 00 ................', log, True)
    assert match('dump_hex:     72 65 67 75 6c 61 74 6f 72 79 00 00 18 00 04 00 regulatory......', log)
    assert match('dump_hex:     08 00 02 00 .. 00 00 00 09 00 01 00 6d 6c 6d 65 ............mlme', log, True)
    rem = log.index('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------')
    log = log[rem:]
    assert match('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------', log)

    assert match('recvmsgs: Attempting to read from 0x[a-f0-9]+', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Read 36 bytes', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Processing valid message...', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message, maxlen=36', log, True)
    assert match('nl_msg_in_handler_debug: -- Debug: Received Message:', log)
    assert match('nl_msg_dump: --------------------------   BEGIN NETLINK MESSAGE ---------------------------', log)
    assert match('nl_msg_dump:   [NETLINK HEADER] 16 octets', log)
    assert match('print_hdr:     .nlmsg_len = 36', log)
    assert match('print_hdr:     .type = 2 <ERROR>', log)
    assert match('print_hdr:     .flags = 0 <>', log)
    assert match('print_hdr:     .seq = \d{10}', log, True)
    assert match('print_hdr:     .port = \d{3,}', log, True)
    assert match('dump_error_msg:   [ERRORMSG] 20 octets', log)
    assert match('dump_error_msg:     .error = 0 "Success"', log)
    assert match('dump_error_msg:   [ORIGINAL MESSAGE] 16 octets', log)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message, maxlen=4096', log, True)
    assert match('print_hdr:     .nlmsg_len = 16', log)
    assert match('print_hdr:     .type = 16 <0x[a-f0-9]+>', log, True)
    assert match('print_hdr:     .flags = 5 <REQUEST,ACK>', log)
    assert match('print_hdr:     .seq = \d{10}', log, True)
    assert match('print_hdr:     .port = \d{3,}', log, True)
    assert match('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------', log)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Increased expected sequence number to \d{10}', log, True)

    assert not log
