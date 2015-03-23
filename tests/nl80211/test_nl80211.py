import re

import pytest

from libnl.attr import nla_put_u32, nla_get_u32, nla_parse, nla_get_string, nla_data, nla_put, nla_put_nested
from libnl.genl.ctrl import genl_ctrl_resolve, genl_ctrl_resolve_grp
from libnl.genl.genl import genl_connect, genlmsg_put, genlmsg_attrdata, genlmsg_attrlen
from libnl.linux_private.genetlink import genlmsghdr
from libnl.linux_private.netlink import NLM_F_DUMP
from libnl.misc import c_int
from libnl.msg import nlmsg_alloc, nlmsg_hdr
from libnl.msg_ import nlmsg_data
from libnl.nl import nl_send_auto, nl_recvmsgs_default, nl_wait_for_ack, nl_recvmsgs
from libnl.nl80211 import nl80211
import libnl.handlers
import libnl.socket_


def match(expected, log, is_regex=False):
    log_statement = log.pop(0)
    if is_regex:
        assert re.match(expected + '$', log_statement)
    else:
        assert expected == log_statement
    return True


@pytest.mark.skipif('not os.path.exists("/sys/class/net/wlan0")')
@pytest.mark.usefixtures('nlcb_debug')
def test_cmd_get_interface(log, wlan0_info, ifacesi):
    """// gcc a.c $(pkg-config --cflags --libs libnl-genl-3.0) && NLDBG=4 NLCB=debug ./a.out
    #include <netlink/netlink.h>
    #include <netlink/genl/genl.h>
    #include <linux/nl80211.h>
    void print_mac(void *arg) {
        unsigned char *mac = (unsigned char *) arg;
        printf("%02x:%02x:%02x:%02x:%02x:%02x == NL80211_ATTR_MAC\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
    static int callback(struct nl_msg *msg, void *arg) {
        struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
        struct nlattr *tb[NL80211_ATTR_MAX + 1];
        nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);
        if (tb[NL80211_ATTR_IFNAME]) printf("%s == NL80211_ATTR_IFNAME\n", nla_get_string(tb[NL80211_ATTR_IFNAME]));
        else printf("Unnamed Interface\n");
        if (tb[NL80211_ATTR_WIPHY]) printf("%d == NL80211_ATTR_WIPHY\n", nla_get_u32(tb[NL80211_ATTR_WIPHY]));
        if (tb[NL80211_ATTR_MAC]) print_mac(nla_data(tb[NL80211_ATTR_MAC]));
        if (tb[NL80211_ATTR_IFINDEX]) printf("%d == NL80211_ATTR_IFINDEX\n", nla_get_u32(tb[NL80211_ATTR_IFINDEX]));
        if (tb[NL80211_ATTR_WDEV]) printf("%llu == NL80211_ATTR_WDEV\n", nla_get_u64(tb[NL80211_ATTR_WDEV]));
        if (tb[NL80211_ATTR_IFTYPE]) printf("%d == NL80211_ATTR_IFTYPE\n", nla_get_u32(tb[NL80211_ATTR_IFTYPE]));
        return NL_SKIP;
    }
    int main() {
        int if_index = if_nametoindex("wlan0");
        struct nl_sock *sk = nl_socket_alloc();
        struct nl_msg *msg = nlmsg_alloc();
        genl_connect(sk);
        int driver_id = genl_ctrl_resolve(sk, "nl80211");
        nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, callback, NULL);
        genlmsg_put(msg, 0, 0, driver_id, 0, 0, NL80211_CMD_GET_INTERFACE, 0);
        nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
        printf("%d == nl_send_auto(sk, msg)\n", nl_send_auto(sk, msg));
        printf("%d == nl_recvmsgs_default(sk)\n", nl_recvmsgs_default(sk));
        nl_wait_for_ack(sk);
        nl_socket_free(sk);
        return 0;
        nla_put_failure:
            nlmsg_free(msg);
            return 1;
    }
    // Expected output (trimmed):
    // nl_cache_mngt_register: Registered cache operations genl/family
    // __nlmsg_alloc: msg 0x17020b8: Allocated new message, maxlen=4096
    //  nl_object_alloc: Allocated new object 0x1703100
    // __nlmsg_alloc: msg 0x1703158: Allocated new message, maxlen=4096
    // nlmsg_put: msg 0x1703158: Added netlink header type=16, flags=0, pid=0, seq=0
    // nlmsg_reserve: msg 0x1703158: Reserved 4 (4) bytes, pad=4, nlmsg_len=20
    // genlmsg_put: msg 0x1703158: Added generic netlink header cmd=3 version=1
    // nla_reserve: msg 0x1703158: attr <0x17031ac> 2: Reserved 12 (8) bytes at offset +4 nlmsg_len=32
    // nla_put: msg 0x1703158: attr <0x17031ac> 2: Wrote 8 bytes at offset +4
    // -- Debug: Sent Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 32
    //     .type = 16 <genl/family::nlctrl>
    //     .flags = 5 <REQUEST,ACK>
    //     .seq = 1425782700
    //     .port = 8178
    //   [GENERIC NETLINK HEADER] 4 octets
    //     .cmd = 3
    //     .version = 1
    //     .unused = 0
    //   [ATTR 02] 8 octets
    //     6e 6c 38 30 32 31 31 00                         nl80211.
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // nl_sendmsg: sent 32 bytes
    // recvmsgs: Attempting to read from 0x1702080
    // recvmsgs: recvmsgs(0x1702080): Read 1836 bytes
    // recvmsgs: recvmsgs(0x1702080): Processing valid message...
    // __nlmsg_alloc: msg 0x1708220: Allocated new message, maxlen=1836
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 1836
    //     .type = 16 <genl/family::nlctrl>
    //     .flags = 0 <>
    //     .seq = 1425782700
    //     .port = 8178
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
    // nlmsg_free: Returned message reference 0x1708220, 0 remaining
    // nlmsg_free: msg 0x1708220: Freed
    // recvmsgs: Attempting to read from 0x1702080
    // recvmsgs: recvmsgs(0x1702080): Read 36 bytes
    // recvmsgs: recvmsgs(0x1702080): Processing valid message...
    // __nlmsg_alloc: msg 0x1708220: Allocated new message, maxlen=36
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 36
    //     .type = 2 <ERROR>
    //     .flags = 0 <>
    //     .seq = 1425782700
    //     .port = 8178
    //   [ERRORMSG] 20 octets
    //     .error = 0 "Success"
    //   [ORIGINAL MESSAGE] 16 octets
    // __nlmsg_alloc: msg 0x1708300: Allocated new message, maxlen=4096
    //     .nlmsg_len = 16
    //     .type = 16 <0x10>
    //     .flags = 5 <REQUEST,ACK>
    //     .seq = 1425782700
    //     .port = 8178
    // nlmsg_free: Returned message reference 0x1708300, 0 remaining
    // nlmsg_free: msg 0x1708300: Freed
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // recvmsgs: recvmsgs(0x1702080): Increased expected sequence number to 1425782701
    // nlmsg_free: Returned message reference 0x1708220, 0 remaining
    // nlmsg_free: msg 0x1708220: Freed
    // nlmsg_free: Returned message reference 0x1703158, 0 remaining
    // nlmsg_free: msg 0x1703158: Freed
    // nl_object_put: Returned object reference 0x1703100, 0 remaining
    // nl_object_free: Freed object 0x1703100
    // nlmsg_put: msg 0x17020b8: Added netlink header type=22, flags=0, pid=0, seq=0
    // nlmsg_reserve: msg 0x17020b8: Reserved 4 (4) bytes, pad=4, nlmsg_len=20
    // genlmsg_put: msg 0x17020b8: Added generic netlink header cmd=5 version=0
    // nla_reserve: msg 0x17020b8: attr <0x170210c> 3: Reserved 8 (4) bytes at offset +4 nlmsg_len=28
    // nla_put: msg 0x17020b8: attr <0x170210c> 3: Wrote 4 bytes at offset +4
    // -- Debug: Sent Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 28
    //     .type = 22 <0x16>
    //     .flags = 5 <REQUEST,ACK>
    //     .seq = 1425782701
    //     .port = 8178
    //   [GENERIC NETLINK HEADER] 4 octets
    //     .cmd = 5
    //     .version = 0
    //     .unused = 0
    //   [PAYLOAD] 8 octets
    //     08 00 03 00 03 00 00 00                         ........
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // nl_sendmsg: sent 28 bytes
    // 28 == nl_send_auto(sk, msg)
    // recvmsgs: Attempting to read from 0x1702080
    // recvmsgs: recvmsgs(0x1702080): Read 88 bytes
    // recvmsgs: recvmsgs(0x1702080): Processing valid message...
    // __nlmsg_alloc: msg 0x1707108: Allocated new message, maxlen=88
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 88
    //     .type = 22 <0x16>
    //     .flags = 0 <>
    //     .seq = 1425782701
    //     .port = 8178
    //   [GENERIC NETLINK HEADER] 4 octets
    //     .cmd = 7
    //     .version = 1
    //     .unused = 0
    //   [PAYLOAD] 68 octets
    //     08 00 03 00 03 00 00 00 0a 00 04 00 77 6c 61 6e ............wlan
    //     30 00 00 00 08 00 01 00 00 00 00 00 08 00 05 00 0...............
    //     02 00 00 00 0c 00 99 00 01 00 00 00 00 00 00 00 ................
    //     0a 00 06 00 00 0f b5 d3 fa 76 00 00 08 00 2e 00 .........v......
    //     05 00 00 00                                     ....
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // wlan0 == NL80211_ATTR_IFNAME
    // 0 == NL80211_ATTR_WIPHY
    // 00:0f:b5:d3:fa:76 == NL80211_ATTR_MAC
    // 3 == NL80211_ATTR_IFINDEX
    // 1 == NL80211_ATTR_WDEV
    // 2 == NL80211_ATTR_IFTYPE
    // nlmsg_free: Returned message reference 0x1707108, 0 remaining
    // nlmsg_free: msg 0x1707108: Freed
    // 0 == nl_recvmsgs_default(sk)
    // recvmsgs: Attempting to read from 0x1702080
    // recvmsgs: recvmsgs(0x1702080): Read 36 bytes
    // recvmsgs: recvmsgs(0x1702080): Processing valid message...
    // __nlmsg_alloc: msg 0x1707180: Allocated new message, maxlen=36
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 36
    //     .type = 2 <ERROR>
    //     .flags = 0 <>
    //     .seq = 1425782701
    //     .port = 8178
    //   [ERRORMSG] 20 octets
    //     .error = 0 "Success"
    //   [ORIGINAL MESSAGE] 16 octets
    // __nlmsg_alloc: msg 0x17071e8: Allocated new message, maxlen=4096
    //     .nlmsg_len = 16
    //     .type = 22 <0x16>
    //     .flags = 5 <REQUEST,ACK>
    //     .seq = 1425782701
    //     .port = 8178
    // nlmsg_free: Returned message reference 0x17071e8, 0 remaining
    // nlmsg_free: msg 0x17071e8: Freed
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // recvmsgs: recvmsgs(0x1702080): Increased expected sequence number to 1425782702
    // nlmsg_free: Returned message reference 0x1707180, 0 remaining
    // nlmsg_free: msg 0x1707180: Freed
    // nl_cache_mngt_unregister: Unregistered cache operations genl/family
    """
    def callback(msg, _):
        gnlh = genlmsghdr(nlmsg_data(nlmsg_hdr(msg)))
        tb = dict((i, None) for i in range(nl80211.NL80211_ATTR_MAX + 1))
        nla_parse(tb, nl80211.NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), None)
        assert b'wlan0' == nla_get_string(tb[nl80211.NL80211_ATTR_IFNAME])
        assert wlan0_info['mac'] == ':'.join(format(x, '02x') for x in nla_data(tb[nl80211.NL80211_ATTR_MAC])[:6])
        assert wlan0_info['ifindex'] == nla_get_u32(tb[nl80211.NL80211_ATTR_IFINDEX])
        assert 2 == nla_get_u32(tb[nl80211.NL80211_ATTR_IFTYPE])
        return libnl.handlers.NL_SKIP
    if_index = dict((n, i) for i, n in ifacesi).get('wlan0')
    sk = libnl.socket_.nl_socket_alloc()
    msg_main = nlmsg_alloc()
    genl_connect(sk)
    driver_id = genl_ctrl_resolve(sk, b'nl80211')
    del log[:]
    libnl.socket_.nl_socket_modify_cb(sk, libnl.handlers.NL_CB_VALID, libnl.handlers.NL_CB_CUSTOM, callback, None)
    genlmsg_put(msg_main, 0, 0, driver_id, 0, 0, nl80211.NL80211_CMD_GET_INTERFACE, 0)
    nla_put_u32(msg_main, nl80211.NL80211_ATTR_IFINDEX, if_index)
    assert 28 == nl_send_auto(sk, msg_main)
    assert 0 == nl_recvmsgs_default(sk)
    nl_wait_for_ack(sk)
    libnl.socket_.nl_socket_free(sk)

    assert match('nlmsg_put: msg 0x[a-f0-9]+: Added netlink header type=\d{2}, flags=0, pid=0, seq=0', log, True)
    assert match('nlmsg_reserve: msg 0x[a-f0-9]+: Reserved 4 \(4\) bytes, pad=4, nlmsg_len=20', log, True)
    assert match('genlmsg_put: msg 0x[a-f0-9]+: Added generic netlink header cmd=5 version=0', log, True)
    assert match(
        'nla_reserve: msg 0x[a-f0-9]+: attr <0x[a-f0-9]+> 3: Reserved 8 \(4\) bytes at offset \+4 nlmsg_len=28',
        log, True)
    assert match('nla_put: msg 0x[a-f0-9]+: attr <0x[a-f0-9]+> 3: Wrote 4 bytes at offset \+4', log, True)
    assert match('nl_msg_out_handler_debug: -- Debug: Sent Message:', log)
    assert match('nl_msg_dump: --------------------------   BEGIN NETLINK MESSAGE ---------------------------', log)
    assert match('nl_msg_dump:   [NETLINK HEADER] 16 octets', log)
    assert match('print_hdr:     .nlmsg_len = 28', log)
    assert match('print_hdr:     .type = \d{2} <0x\w{2}>', log, True)
    assert match('print_hdr:     .flags = 5 <REQUEST,ACK>', log)
    assert match('print_hdr:     .seq = \d{10}', log, True)
    assert match('print_hdr:     .port = \d{3,}', log, True)
    assert match('print_genl_hdr:   [GENERIC NETLINK HEADER] 4 octets', log)
    assert match('print_genl_hdr:     .cmd = 5', log)
    assert match('print_genl_hdr:     .version = 0', log)
    assert match('print_genl_hdr:     .unused = 0', log)
    assert match('print_msg:   [PAYLOAD] 8 octets', log)
    assert match('dump_hex:     08 00 03 00 .. 00 00 00                         ........', log, True)
    assert match('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------', log)
    assert match('nl_sendmsg: sent 28 bytes', log)

    assert match('recvmsgs: Attempting to read from 0x[a-f0-9]+', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Read \d{2,} bytes', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Processing valid message...', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message, maxlen=\d{2,}', log, True)
    assert match('nl_msg_in_handler_debug: -- Debug: Received Message:', log)
    assert match('nl_msg_dump: --------------------------   BEGIN NETLINK MESSAGE ---------------------------', log)
    assert match('nl_msg_dump:   [NETLINK HEADER] 16 octets', log)
    assert match('print_hdr:     .nlmsg_len = \d{2,}', log, True)
    assert match('print_hdr:     .type = \d{2} <0x\w{2}>', log, True)
    assert match('print_hdr:     .flags = 0 <>', log)
    assert match('print_hdr:     .seq = \d{10}', log, True)
    assert match('print_hdr:     .port = \d{3,}', log, True)
    assert match('print_genl_hdr:   [GENERIC NETLINK HEADER] 4 octets', log)
    assert match('print_genl_hdr:     .cmd = 7', log)
    assert match('print_genl_hdr:     .version = 1', log)
    assert match('print_genl_hdr:     .unused = 0', log)
    assert match('print_msg:   [PAYLOAD] 68 octets', log)
    assert match('dump_hex:     08 00 03 00 .. 00 00 00 0a 00 04 00 77 6c 61 6e ............wlan', log, True)
    assert match('dump_hex:     30 00 00 00 08 00 01 00 .. 00 00 00 08 00 05 00 0...............', log, True)
    assert match('dump_hex:     02 00 00 00 0c 00 99 00 01 00 00 00 .. 00 00 00 ................', log, True)
    assert match('dump_hex:     0a 00 06 00 .. .. .. .. .. .. 00 00 08 00 2e 00 ................', log, True)
    assert match('dump_hex:     .. 00 00 00                                     ....', log, True)
    assert match('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------', log)

    assert match('recvmsgs: Attempting to read from 0x[a-f0-9]+', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Read 36 bytes', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Processing valid message...', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message, maxlen=36', log, True)
    assert match('nl_msg_in_handler_debug: -- Debug: Received Message:', log)
    assert match('nl_msg_dump: --------------------------   BEGIN NETLINK MESSAGE ---------------------------', log)
    assert match('nl_msg_dump:   [NETLINK HEADER] 16 octets', log)
    assert match('print_hdr:     .nlmsg_len = 36', log, True)
    assert match('print_hdr:     .type = 2 <ERROR>', log)
    assert match('print_hdr:     .flags = 0 <>', log)
    assert match('print_hdr:     .seq = \d{10}', log, True)
    assert match('print_hdr:     .port = \d{3,}', log, True)
    assert match('dump_error_msg:   [ERRORMSG] 20 octets', log)
    assert match('dump_error_msg:     .error = 0 "Success"', log)
    assert match('dump_error_msg:   [ORIGINAL MESSAGE] 16 octets', log)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message, maxlen=4096', log, True)
    assert match('print_hdr:     .nlmsg_len = 16', log)
    assert match('print_hdr:     .type = \d{2} <0x\w{2}>', log, True)
    assert match('print_hdr:     .flags = 5 <REQUEST,ACK>', log)
    assert match('print_hdr:     .seq = \d{10}', log, True)
    assert match('print_hdr:     .port = \d{3,}', log, True)
    assert match('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------', log)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Increased expected sequence number to \d{10}', log, True)

    assert not log


@pytest.mark.skipif('not os.path.exists("/sys/class/net/wlan0") or os.getuid() != 0')
@pytest.mark.usefixtures('nlcb_debug')
def test_cmd_trigger_scan(log, ifacesi):
    """// gcc a.c $(pkg-config --cflags --libs libnl-genl-3.0) && sudo NLDBG=4 NLCB=debug ./a.out
    #include <netlink/genl/genl.h>
    #include <linux/nl80211.h>
    static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg) {
        int *ret = arg; *ret = err->error; printf("error %d\n", *ret); return NL_STOP;
    }
    static int finish_handler(struct nl_msg *msg, void *arg) {
        int *ret = arg; *ret = 0; printf("finish %d\n", *ret); return NL_SKIP;
    }
    static int ack_handler(struct nl_msg *msg, void *arg) {
        int *ret = arg; *ret = 0; printf("ack %d\n", *ret); return NL_STOP;
    }
    static int no_seq_check(struct nl_msg *msg, void *arg) { printf("no_seq\n"); return NL_OK; }
    static int callback_trigger(struct nl_msg *msg, void *arg) {
        int *ret = arg; struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
        if (gnlh->cmd == NL80211_CMD_SCAN_ABORTED) *ret = 1;
        else if (gnlh->cmd == NL80211_CMD_NEW_SCAN_RESULTS) *ret = 0;
        printf("cb_trigger %d\n", *ret); return NL_SKIP;
    }
    int do_scan_trigger(struct nl_sock *sk, int if_index, int driver_id) {
        int ret, err = 1;
        int results = -1;  // -1 = not done, 0 = success; 1 = error.
        int mcid = genl_ctrl_resolve_grp(sk, "nl80211", "scan");
        printf("%d == mcid\n", mcid);
        printf("%d == nl_socket_add_membership(sk, mcid)\n", nl_socket_add_membership(sk, mcid));
        struct nl_msg *msg = nlmsg_alloc();
        struct nl_msg *msg_ssids = nlmsg_alloc();
        struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
        genlmsg_put(msg, 0, 0, driver_id, 0, 0, NL80211_CMD_TRIGGER_SCAN, 0);
        nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
        nla_put(msg_ssids, 1, 0, "");
        nla_put_nested(msg, NL80211_ATTR_SCAN_SSIDS, msg_ssids);
        nlmsg_free(msg_ssids);
        nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, callback_trigger, &results);
        nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
        nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
        nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
        nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
        printf("%d == nl_send_auto(sk, msg)\n", nl_send_auto(sk, msg));
        while (err > 0) {
            ret = nl_recvmsgs(sk, cb); printf("%d == nl_recvmsgs err\n", ret); printf("%d == err\n", err);
        }
        if (ret < 0) return ret;
        while (results < 0) printf("%d == nl_recvmsgs results\n", nl_recvmsgs(sk, cb));
        printf("%d == nl_socket_drop_membership(sk, mcid)\n", nl_socket_drop_membership(sk, mcid));
        return results;
    }
    static int callback_dump(struct nl_msg *msg, void *arg) {
        struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
        struct nlattr *tb[NL80211_ATTR_MAX + 1];
        nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);
        int i, j = 0; for (i = 0; i < NL80211_ATTR_MAX + 1; i++) if (tb[i]) j++;
        printf("%d == len(i for i in tb.values() if i)\n", j);
        return NL_SKIP;
    }
    int main() {
        int if_index = if_nametoindex("wlan0");
        struct nl_sock *sk = nl_socket_alloc();
        genl_connect(sk);
        int driver_id = genl_ctrl_resolve(sk, "nl80211");
        int err = do_scan_trigger(sk, if_index, driver_id);
        if (err != 0) { printf("FAILED %d\n", err); return err; }
        struct nl_msg *msg = nlmsg_alloc();
        genlmsg_put(msg, 0, 0, driver_id, 0, NLM_F_DUMP, NL80211_CMD_GET_SCAN, 0);
        nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
        nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, callback_dump, NULL);
        printf("%d == nl_send_auto(sk, msg)\n", nl_send_auto(sk, msg));
        printf("%d == nl_recvmsgs_default(sk)\n", nl_recvmsgs_default(sk));
        return 0;
    }
    // Expected output (trimmed):
    // nl_cache_mngt_register: Registered cache operations genl/family
    //  nl_object_alloc: Allocated new object 0xa330b8
    // __nlmsg_alloc: msg 0xa33110: Allocated new message, maxlen=4096
    // nlmsg_put: msg 0xa33110: Added netlink header type=16, flags=0, pid=0, seq=0
    // nlmsg_reserve: msg 0xa33110: Reserved 4 (4) bytes, pad=4, nlmsg_len=20
    // genlmsg_put: msg 0xa33110: Added generic netlink header cmd=3 version=1
    // nla_reserve: msg 0xa33110: attr <0xa33164> 2: Reserved 12 (8) bytes at offset +4 nlmsg_len=32
    // nla_put: msg 0xa33110: attr <0xa33164> 2: Wrote 8 bytes at offset +4
    // -- Debug: Sent Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 32
    //     .type = 16 <genl/family::nlctrl>
    //     .flags = 5 <REQUEST,ACK>
    //     .seq = 1425856951
    //     .port = 28841
    //   [GENERIC NETLINK HEADER] 4 octets
    //     .cmd = 3
    //     .version = 1
    //     .unused = 0
    //   [ATTR 02] 8 octets
    //     6e 6c 38 30 32 31 31 00                         nl80211.
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // nl_sendmsg: sent 32 bytes
    // recvmsgs: Attempting to read from 0xa33080
    // recvmsgs: recvmsgs(0xa33080): Read 1836 bytes
    // recvmsgs: recvmsgs(0xa33080): Processing valid message...
    // __nlmsg_alloc: msg 0xa381d8: Allocated new message, maxlen=1836
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 1836
    //     .type = 16 <genl/family::nlctrl>
    //     .flags = 0 <>
    //     .seq = 1425856951
    //     .port = 28841
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
    // nlmsg_free: Returned message reference 0xa381d8, 0 remaining
    // nlmsg_free: msg 0xa381d8: Freed
    // recvmsgs: Attempting to read from 0xa33080
    // recvmsgs: recvmsgs(0xa33080): Read 36 bytes
    // recvmsgs: recvmsgs(0xa33080): Processing valid message...
    // __nlmsg_alloc: msg 0xa381d8: Allocated new message, maxlen=36
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 36
    //     .type = 2 <ERROR>
    //     .flags = 0 <>
    //     .seq = 1425856951
    //     .port = 28841
    //   [ERRORMSG] 20 octets
    //     .error = 0 "Success"
    //   [ORIGINAL MESSAGE] 16 octets
    // __nlmsg_alloc: msg 0xa382b8: Allocated new message, maxlen=4096
    //     .nlmsg_len = 16
    //     .type = 16 <0x10>
    //     .flags = 5 <REQUEST,ACK>
    //     .seq = 1425856951
    //     .port = 28841
    // nlmsg_free: Returned message reference 0xa382b8, 0 remaining
    // nlmsg_free: msg 0xa382b8: Freed
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // recvmsgs: recvmsgs(0xa33080): Increased expected sequence number to 1425856952
    // nlmsg_free: Returned message reference 0xa381d8, 0 remaining
    // nlmsg_free: msg 0xa381d8: Freed
    // nlmsg_free: Returned message reference 0xa33110, 0 remaining
    // nlmsg_free: msg 0xa33110: Freed
    // nl_object_put: Returned object reference 0xa330b8, 0 remaining
    // nl_object_free: Freed object 0xa330b8
    //  nl_object_alloc: Allocated new object 0xa330b8
    // __nlmsg_alloc: msg 0xa33110: Allocated new message, maxlen=4096
    // nlmsg_put: msg 0xa33110: Added netlink header type=16, flags=0, pid=0, seq=0
    // nlmsg_reserve: msg 0xa33110: Reserved 4 (4) bytes, pad=4, nlmsg_len=20
    // genlmsg_put: msg 0xa33110: Added generic netlink header cmd=3 version=1
    // nla_reserve: msg 0xa33110: attr <0xa33164> 2: Reserved 12 (8) bytes at offset +4 nlmsg_len=32
    // nla_put: msg 0xa33110: attr <0xa33164> 2: Wrote 8 bytes at offset +4
    // -- Debug: Sent Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 32
    //     .type = 16 <genl/family::nlctrl>
    //     .flags = 5 <REQUEST,ACK>
    //     .seq = 1425856952
    //     .port = 28841
    //   [GENERIC NETLINK HEADER] 4 octets
    //     .cmd = 3
    //     .version = 1
    //     .unused = 0
    //   [ATTR 02] 8 octets
    //     6e 6c 38 30 32 31 31 00                         nl80211.
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // nl_sendmsg: sent 32 bytes
    // recvmsgs: Attempting to read from 0xa33080
    // recvmsgs: recvmsgs(0xa33080): Read 1836 bytes
    // recvmsgs: recvmsgs(0xa33080): Processing valid message...
    // __nlmsg_alloc: msg 0xa381d8: Allocated new message, maxlen=1836
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 1836
    //     .type = 16 <genl/family::nlctrl>
    //     .flags = 0 <>
    //     .seq = 1425856952
    //     .port = 28841
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
    // nlmsg_free: Returned message reference 0xa381d8, 0 remaining
    // nlmsg_free: msg 0xa381d8: Freed
    // recvmsgs: Attempting to read from 0xa33080
    // recvmsgs: recvmsgs(0xa33080): Read 36 bytes
    // recvmsgs: recvmsgs(0xa33080): Processing valid message...
    // __nlmsg_alloc: msg 0xa381d8: Allocated new message, maxlen=36
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 36
    //     .type = 2 <ERROR>
    //     .flags = 0 <>
    //     .seq = 1425856952
    //     .port = 28841
    //   [ERRORMSG] 20 octets
    //     .error = 0 "Success"
    //   [ORIGINAL MESSAGE] 16 octets
    // __nlmsg_alloc: msg 0xa382b8: Allocated new message, maxlen=4096
    //     .nlmsg_len = 16
    //     .type = 16 <0x10>
    //     .flags = 5 <REQUEST,ACK>
    //     .seq = 1425856952
    //     .port = 28841
    // nlmsg_free: Returned message reference 0xa382b8, 0 remaining
    // nlmsg_free: msg 0xa382b8: Freed
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // recvmsgs: recvmsgs(0xa33080): Increased expected sequence number to 1425856953
    // nlmsg_free: Returned message reference 0xa381d8, 0 remaining
    // nlmsg_free: msg 0xa381d8: Freed
    // nlmsg_free: Returned message reference 0xa33110, 0 remaining
    // nlmsg_free: msg 0xa33110: Freed
    // nl_object_put: Returned object reference 0xa330b8, 0 remaining
    // nl_object_free: Freed object 0xa330b8
    // 4 == mcid
    // 0 == nl_socket_add_membership(sk, mcid)
    // __nlmsg_alloc: msg 0xa33110: Allocated new message, maxlen=4096
    // __nlmsg_alloc: msg 0xa330b8: Allocated new message, maxlen=4096
    // nlmsg_put: msg 0xa33110: Added netlink header type=22, flags=0, pid=0, seq=0
    // nlmsg_reserve: msg 0xa33110: Reserved 4 (4) bytes, pad=4, nlmsg_len=20
    // genlmsg_put: msg 0xa33110: Added generic netlink header cmd=33 version=0
    // nla_reserve: msg 0xa33110: attr <0xa33164> 3: Reserved 8 (4) bytes at offset +4 nlmsg_len=28
    // nla_put: msg 0xa33110: attr <0xa33164> 3: Wrote 4 bytes at offset +4
    // nla_reserve: msg 0xa330b8: attr <0xa34168> 1: Reserved 4 (0) bytes at offset +0 nlmsg_len=20
    // nla_put_nested: msg 0xa33110: attr <> 45: adding msg 0xa330b8 as nested attribute
    // nla_reserve: msg 0xa33110: attr <0xa3316c> 45: Reserved 8 (4) bytes at offset +12 nlmsg_len=36
    // nla_put: msg 0xa33110: attr <0xa3316c> 45: Wrote 4 bytes at offset +12
    // nlmsg_free: Returned message reference 0xa330b8, 0 remaining
    // nlmsg_free: msg 0xa330b8: Freed
    // -- Debug: Sent Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 36
    //     .type = 22 <0x16>
    //     .flags = 5 <REQUEST,ACK>
    //     .seq = 1425856953
    //     .port = 28841
    //   [GENERIC NETLINK HEADER] 4 octets
    //     .cmd = 33
    //     .version = 0
    //     .unused = 0
    //   [PAYLOAD] 16 octets
    //     08 00 03 00 03 00 00 00 08 00 2d 00 04 00 01 00 ..........-.....
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // nl_sendmsg: sent 36 bytes
    // 36 == nl_send_auto(sk, msg)
    // recvmsgs: Attempting to read from 0xa33080
    // recvmsgs: recvmsgs(0xa33080): Read 172 bytes
    // recvmsgs: recvmsgs(0xa33080): Processing valid message...
    // __nlmsg_alloc: msg 0xa330b8: Allocated new message, maxlen=172
    // no_seq
    // cb_trigger -1
    // nlmsg_free: Returned message reference 0xa330b8, 0 remaining
    // nlmsg_free: msg 0xa330b8: Freed
    // 0 == nl_recvmsgs err
    // 1 == err
    // recvmsgs: Attempting to read from 0xa33080
    // recvmsgs: recvmsgs(0xa33080): Read 36 bytes
    // recvmsgs: recvmsgs(0xa33080): Processing valid message...
    // __nlmsg_alloc: msg 0xa330b8: Allocated new message, maxlen=36
    // no_seq
    // recvmsgs: recvmsgs(0xa33080): Increased expected sequence number to 1425856954
    // ack 0
    // nlmsg_free: Returned message reference 0xa330b8, 0 remaining
    // nlmsg_free: msg 0xa330b8: Freed
    // 0 == nl_recvmsgs err
    // 0 == err
    // recvmsgs: Attempting to read from 0xa33080
    // recvmsgs: recvmsgs(0xa33080): Read 172 bytes
    // recvmsgs: recvmsgs(0xa33080): Processing valid message...
    // __nlmsg_alloc: msg 0xa330b8: Allocated new message, maxlen=172
    // no_seq
    // cb_trigger 0
    // nlmsg_free: Returned message reference 0xa330b8, 0 remaining
    // nlmsg_free: msg 0xa330b8: Freed
    // 0 == nl_recvmsgs results
    // 0 == nl_socket_drop_membership(sk, mcid)
    // __nlmsg_alloc: msg 0xa330b8: Allocated new message, maxlen=4096
    // nlmsg_put: msg 0xa330b8: Added netlink header type=22, flags=768, pid=0, seq=0
    // nlmsg_reserve: msg 0xa330b8: Reserved 4 (4) bytes, pad=4, nlmsg_len=20
    // genlmsg_put: msg 0xa330b8: Added generic netlink header cmd=32 version=0
    // nla_reserve: msg 0xa330b8: attr <0xa3416c> 3: Reserved 8 (4) bytes at offset +4 nlmsg_len=28
    // nla_put: msg 0xa330b8: attr <0xa3416c> 3: Wrote 4 bytes at offset +4
    // -- Debug: Sent Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 28
    //     .type = 22 <0x16>
    //     .flags = 773 <REQUEST,ACK,ROOT,MATCH>
    //     .seq = 1425856954
    //     .port = 28841
    //   [GENERIC NETLINK HEADER] 4 octets
    //     .cmd = 32
    //     .version = 0
    //     .unused = 0
    //   [PAYLOAD] 8 octets
    //     08 00 03 00 03 00 00 00                         ........
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // nl_sendmsg: sent 28 bytes
    // 28 == nl_send_auto(sk, msg)
    // recvmsgs: Attempting to read from 0xa33080
    // recvmsgs: recvmsgs(0xa33080): Read 4516 bytes
    // recvmsgs: recvmsgs(0xa33080): Processing valid message...
    // __nlmsg_alloc: msg 0xa391e0: Allocated new message, maxlen=456
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 456
    //     .type = 22 <0x16>
    //     .flags = 2 <MULTI>
    //     .seq = 1425856954
    //     .port = 28841
    //   [GENERIC NETLINK HEADER] 4 octets
    //     .cmd = 34
    //     .version = 1
    //     .unused = 0
    //   [PAYLOAD] 436 octets
    //     08 00 2e 00 a0 b9 4b 00 08 00 03 00 03 00 00 00 ......K.........
    //     <trimmed>
    //     48 f4 ff ff                                     H...
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // 4 == len(i for i in tb.values() if i)
    // recvmsgs: recvmsgs(0xa33080): Processing valid message...
    // nlmsg_free: Returned message reference 0xa391e0, 0 remaining
    // nlmsg_free: msg 0xa391e0: Freed
    // __nlmsg_alloc: msg 0xa391e0: Allocated new message, maxlen=744
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 744
    //     .type = 22 <0x16>
    //     .flags = 2 <MULTI>
    //     .seq = 1425856954
    //     .port = 28841
    //   [GENERIC NETLINK HEADER] 4 octets
    //     .cmd = 34
    //     .version = 1
    //     .unused = 0
    //   [PAYLOAD] 724 octets
    //     08 00 2e 00 a0 b9 4b 00 08 00 03 00 03 00 00 00 ......K.........
    //     <trimmed>
    //     bc e9 ff ff                                     ....
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // 4 == len(i for i in tb.values() if i)
    // recvmsgs: recvmsgs(0xa33080): Processing valid message...
    // nlmsg_free: Returned message reference 0xa391e0, 0 remaining
    // nlmsg_free: msg 0xa391e0: Freed
    // __nlmsg_alloc: msg 0xa391e0: Allocated new message, maxlen=748
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 748
    //     .type = 22 <0x16>
    //     .flags = 2 <MULTI>
    //     .seq = 1425856954
    //     .port = 28841
    //   [GENERIC NETLINK HEADER] 4 octets
    //     .cmd = 34
    //     .version = 1
    //     .unused = 0
    //   [PAYLOAD] 728 octets
    //     08 00 2e 00 a0 b9 4b 00 08 00 03 00 03 00 00 00 ......K.........
    //     <trimmed>
    //     08 00 07 00 78 ec ff ff                         ....x...
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // 4 == len(i for i in tb.values() if i)
    // recvmsgs: recvmsgs(0xa33080): Processing valid message...
    // nlmsg_free: Returned message reference 0xa391e0, 0 remaining
    // nlmsg_free: msg 0xa391e0: Freed
    // __nlmsg_alloc: msg 0xa391e0: Allocated new message, maxlen=584
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 584
    //     .type = 22 <0x16>
    //     .flags = 2 <MULTI>
    //     .seq = 1425856954
    //     .port = 28841
    //   [GENERIC NETLINK HEADER] 4 octets
    //     .cmd = 34
    //     .version = 1
    //     .unused = 0
    //   [PAYLOAD] 564 octets
    //     08 00 2e 00 a0 b9 4b 00 08 00 03 00 03 00 00 00 ......K.........
    //     <trimmed>
    //     00 00 00 00 08 00 0a 00 ae 06 00 00 08 00 07 00 ................
    //     64 e7 ff ff                                     d...
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // 4 == len(i for i in tb.values() if i)
    // recvmsgs: recvmsgs(0xa33080): Processing valid message...
    // nlmsg_free: Returned message reference 0xa391e0, 0 remaining
    // nlmsg_free: msg 0xa391e0: Freed
    // __nlmsg_alloc: msg 0xa391e0: Allocated new message, maxlen=464
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 464
    //     .type = 22 <0x16>
    //     .flags = 2 <MULTI>
    //     .seq = 1425856954
    //     .port = 28841
    //   [GENERIC NETLINK HEADER] 4 octets
    //     .cmd = 34
    //     .version = 1
    //     .unused = 0
    //   [PAYLOAD] 444 octets
    //     08 00 2e 00 a0 b9 4b 00 08 00 03 00 03 00 00 00 ......K.........
    //     <trimmed>
    //     c2 06 00 00 08 00 07 00 70 e5 ff ff             ........p...
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // 4 == len(i for i in tb.values() if i)
    // recvmsgs: recvmsgs(0xa33080): Processing valid message...
    // nlmsg_free: Returned message reference 0xa391e0, 0 remaining
    // nlmsg_free: msg 0xa391e0: Freed
    // __nlmsg_alloc: msg 0xa391e0: Allocated new message, maxlen=560
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 560
    //     .type = 22 <0x16>
    //     .flags = 2 <MULTI>
    //     .seq = 1425856954
    //     .port = 28841
    //   [GENERIC NETLINK HEADER] 4 octets
    //     .cmd = 34
    //     .version = 1
    //     .unused = 0
    //   [PAYLOAD] 540 octets
    //     08 00 2e 00 a0 b9 4b 00 08 00 03 00 03 00 00 00 ......K.........
    //     <trimmed>
    //     9e 6b 00 00 08 00 07 00 b4 e2 ff ff             .k..........
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // 4 == len(i for i in tb.values() if i)
    // recvmsgs: recvmsgs(0xa33080): Processing valid message...
    // nlmsg_free: Returned message reference 0xa391e0, 0 remaining
    // nlmsg_free: msg 0xa391e0: Freed
    // __nlmsg_alloc: msg 0xa391e0: Allocated new message, maxlen=472
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 472
    //     .type = 22 <0x16>
    //     .flags = 2 <MULTI>
    //     .seq = 1425856954
    //     .port = 28841
    //   [GENERIC NETLINK HEADER] 4 octets
    //     .cmd = 34
    //     .version = 1
    //     .unused = 0
    //   [PAYLOAD] 452 octets
    //     08 00 2e 00 a0 b9 4b 00 08 00 03 00 03 00 00 00 ......K.........
    //     <trimmed>
    //     70 e5 ff ff                                     p...
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // 4 == len(i for i in tb.values() if i)
    // recvmsgs: recvmsgs(0xa33080): Processing valid message...
    // nlmsg_free: Returned message reference 0xa391e0, 0 remaining
    // nlmsg_free: msg 0xa391e0: Freed
    // __nlmsg_alloc: msg 0xa391e0: Allocated new message, maxlen=488
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 488
    //     .type = 22 <0x16>
    //     .flags = 2 <MULTI>
    //     .seq = 1425856954
    //     .port = 28841
    //   [GENERIC NETLINK HEADER] 4 octets
    //     .cmd = 34
    //     .version = 1
    //     .unused = 0
    //   [PAYLOAD] 468 octets
    //     08 00 2e 00 a0 b9 4b 00 08 00 03 00 03 00 00 00 ......K.........
    //     <trimmed>
    //     d4 e5 ff ff                                     ....
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // 4 == len(i for i in tb.values() if i)
    // nlmsg_free: Returned message reference 0xa391e0, 0 remaining
    // nlmsg_free: msg 0xa391e0: Freed
    // recvmsgs: Attempting to read from 0xa33080
    // recvmsgs: recvmsgs(0xa33080): Read 20 bytes
    // recvmsgs: recvmsgs(0xa33080): Processing valid message...
    // __nlmsg_alloc: msg 0xa391e0: Allocated new message, maxlen=20
    // -- Debug: Received Message:
    // --------------------------   BEGIN NETLINK MESSAGE ---------------------------
    //   [NETLINK HEADER] 16 octets
    //     .nlmsg_len = 20
    //     .type = 3 <DONE>
    //     .flags = 2 <MULTI>
    //     .seq = 1425856954
    //     .port = 28841
    //   [GENERIC NETLINK HEADER] 4 octets
    //     .cmd = 0
    //     .version = 0
    //     .unused = 0
    // ---------------------------  END NETLINK MESSAGE   ---------------------------
    // recvmsgs: recvmsgs(0xa33080): Increased expected sequence number to 1425856955
    // -- Debug: End of multipart message block: type=DONE length=20 flags=<MULTI> sequence-nr=1425856954 pid=28841
    // nlmsg_free: Returned message reference 0xa391e0, 0 remaining
    // nlmsg_free: msg 0xa391e0: Freed
    // 0 == nl_recvmsgs_default(sk)
    // nl_cache_mngt_unregister: Unregistered cache operations genl/family
    """
    callbacks_called = dict(ack=False, trigger=False, error_not_called=True, seq=False)

    def error_handler(_, err, arg):
        callbacks_called['error_not_called'] = False
        arg.value = err.error
        return libnl.handlers.NL_STOP

    def ack_handler(_, arg):
        callbacks_called['ack'] = True
        arg.value = 0
        return libnl.handlers.NL_STOP

    def no_seq_check(*_):
        callbacks_called['seq'] = True
        return libnl.handlers.NL_OK

    def callback_trigger(msg, arg):
        callbacks_called['trigger'] = True
        gnlh = genlmsghdr(nlmsg_data(nlmsg_hdr(msg)))
        if gnlh.cmd == nl80211.NL80211_CMD_SCAN_ABORTED:
            arg.value = 1
        elif gnlh.cmd == nl80211.NL80211_CMD_NEW_SCAN_RESULTS:
            arg.value = 0
        return libnl.handlers.NL_SKIP

    def do_scan_trigger(sk, if_index, driver_id):
        err = c_int(1)
        results = c_int(-1)
        mcid = genl_ctrl_resolve_grp(sk, b'nl80211', b'scan')
        assert 0 < mcid
        assert 0 == libnl.socket_.nl_socket_add_membership(sk, mcid)
        msg = nlmsg_alloc()
        msg_ssids = nlmsg_alloc()
        cb = libnl.handlers.nl_cb_alloc(libnl.handlers.NL_CB_DEFAULT)
        genlmsg_put(msg, 0, 0, driver_id, 0, 0, nl80211.NL80211_CMD_TRIGGER_SCAN, 0)
        nla_put_u32(msg, nl80211.NL80211_ATTR_IFINDEX, if_index)
        nla_put(msg_ssids, 1, 0, b'')
        nla_put_nested(msg, nl80211.NL80211_ATTR_SCAN_SSIDS, msg_ssids)
        libnl.handlers.nl_cb_set(cb, libnl.handlers.NL_CB_VALID, libnl.handlers.NL_CB_CUSTOM, callback_trigger, results)
        libnl.handlers.nl_cb_err(cb, libnl.handlers.NL_CB_CUSTOM, error_handler, err)
        libnl.handlers.nl_cb_set(cb, libnl.handlers.NL_CB_ACK, libnl.handlers.NL_CB_CUSTOM, ack_handler, err)
        libnl.handlers.nl_cb_set(cb, libnl.handlers.NL_CB_SEQ_CHECK, libnl.handlers.NL_CB_CUSTOM, no_seq_check, None)
        36 == nl_send_auto(sk, msg)
        while err.value > 0:
            assert 0 == nl_recvmsgs(sk, cb)
        assert 0 == err.value
        while results.value < 0:
            assert 0 == nl_recvmsgs(sk, cb)
        assert 0 == libnl.socket_.nl_socket_drop_membership(sk, mcid)
        assert 0 == results.value
        return results.value

    def callback_dump(msg, _):
        gnlh = genlmsghdr(nlmsg_data(nlmsg_hdr(msg)))
        tb = dict((i, None) for i in range(nl80211.NL80211_ATTR_MAX + 1))
        nla_parse(tb, nl80211.NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), None)
        assert 4 == len([i for i in tb.values() if i])
        return libnl.handlers.NL_SKIP

    if_index_main = dict((n, i) for i, n in ifacesi).get('wlan0')
    sk_main = libnl.socket_.nl_socket_alloc()
    genl_connect(sk_main)
    driver_id_main = genl_ctrl_resolve(sk_main, b'nl80211')
    del log[:]
    assert 0 == do_scan_trigger(sk_main, if_index_main, driver_id_main)
    msg_main = nlmsg_alloc()
    genlmsg_put(msg_main, 0, 0, driver_id_main, 0, NLM_F_DUMP, nl80211.NL80211_CMD_GET_SCAN, 0)
    nla_put_u32(msg_main, nl80211.NL80211_ATTR_IFINDEX, if_index_main)
    libnl.socket_.nl_socket_modify_cb(sk_main, libnl.handlers.NL_CB_VALID, libnl.handlers.NL_CB_CUSTOM, callback_dump,
                                      None)
    assert 28 == nl_send_auto(sk_main, msg_main)
    assert 0 == nl_recvmsgs_default(sk_main)
    assert all(callbacks_called.values())
    libnl.socket_.nl_socket_free(sk_main)

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
    assert match('dump_hex:     6e 6c 38 30 32 31 31 00                         nl80211.', log, True)
    assert match('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------', log)
    assert match('nl_sendmsg: sent 32 bytes', log)

    assert match('recvmsgs: Attempting to read from 0x[a-f0-9]+', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Read \d{4} bytes', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Processing valid message...', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message, maxlen=\d{4}', log, True)
    assert match('nl_msg_in_handler_debug: -- Debug: Received Message:', log)
    assert match('nl_msg_dump: --------------------------   BEGIN NETLINK MESSAGE ---------------------------', log)
    assert match('nl_msg_dump:   [NETLINK HEADER] 16 octets', log)
    assert match('print_hdr:     .nlmsg_len = \d{4}', log, True)
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
    assert match('dump_attrs:   \[ATTR 06\] \d{4} octets', log, True)
    assert match('dump_hex:     14 00 01 00 08 00 01 00 01 00 00 00 08 00 02 00 ................', log)
    assert match('dump_hex:     0e 00 00 00 14 00 02 00 08 00 01 00 02 00 00 00 ................', log)
    assert match('dump_hex:     08 00 02 00 0b 00 00 00 14 00 03 00 08 00 01 00 ................', log)
    assert match('dump_hex:     05 00 00 00 08 00 02 00 0e 00 00 00 14 00 04 00 ................', log)
    assert match('dump_hex:     08 00 01 00 06 00 00 00 08 00 02 00 0b 00 00 00 ................', log)
    assert match('dump_hex:     14 00 05 00 08 00 01 00 07 00 00 00 08 00 02 00 ................', log)
    assert match('dump_hex:     0b 00 00 00 14 00 06 00 08 00 01 00 08 00 00 00 ................', log)
    assert match('dump_hex:     08 00 02 00 0b 00 00 00 14 00 07 00 08 00 01 00 ................', log)
    assert match('dump_hex:     09 00 00 00 08 00 02 00 0b 00 00 00 14 00 08 00 ................', log)
    assert match('dump_hex:     08 00 01 00 0a 00 00 00 08 00 02 00 0b 00 00 00 ................', log)
    assert match('dump_hex:     14 00 09 00 08 00 01 00 0b 00 00 00 08 00 02 00 ................', log)
    assert match('dump_hex:     0b 00 00 00 14 00 0a 00 08 00 01 00 0c 00 00 00 ................', log)
    assert match('dump_hex:     08 00 02 00 0b 00 00 00 14 00 0b 00 08 00 01 00 ................', log)
    assert match('dump_hex:     0e 00 00 00 08 00 02 00 0b 00 00 00 14 00 0c 00 ................', log)
    assert match('dump_hex:     08 00 01 00 0f 00 00 00 08 00 02 00 0b 00 00 00 ................', log)
    assert match('dump_hex:     14 00 0d 00 08 00 01 00 10 00 00 00 08 00 02 00 ................', log)
    assert match('dump_hex:     0b 00 00 00 14 00 0e 00 08 00 01 00 11 00 00 00 ................', log)
    assert match('dump_hex:     08 00 02 00 0e 00 00 00 14 00 0f 00 08 00 01 00 ................', log)
    assert match('dump_hex:     12 00 00 00 08 00 02 00 0b 00 00 00 14 00 10 00 ................', log)
    assert match('dump_hex:     08 00 01 00 13 00 00 00 08 00 02 00 0b 00 00 00 ................', log)
    assert match('dump_hex:     14 00 11 00 08 00 01 00 14 00 00 00 08 00 02 00 ................', log)
    assert match('dump_hex:     0b 00 00 00 14 00 12 00 08 00 01 00 15 00 00 00 ................', log)
    assert match('dump_hex:     08 00 02 00 0f 00 00 00 14 00 13 00 08 00 01 00 ................', log)
    assert match('dump_hex:     16 00 00 00 08 00 02 00 0b 00 00 00 14 00 14 00 ................', log)
    assert match('dump_hex:     08 00 01 00 17 00 00 00 08 00 02 00 0b 00 00 00 ................', log)
    assert match('dump_hex:     14 00 15 00 08 00 01 00 18 00 00 00 08 00 02 00 ................', log)
    assert match('dump_hex:     0b 00 00 00 14 00 16 00 08 00 01 00 19 00 00 00 ................', log)
    assert match('dump_hex:     08 00 02 00 0b 00 00 00 14 00 17 00 08 00 01 00 ................', log)
    assert match('dump_hex:     1f 00 00 00 08 00 02 00 0a 00 00 00 14 00 18 00 ................', log)
    assert match('dump_hex:     08 00 01 00 1a 00 00 00 08 00 02 00 0b 00 00 00 ................', log)
    assert match('dump_hex:     14 00 19 00 08 00 01 00 1b 00 00 00 08 00 02 00 ................', log)
    assert match('dump_hex:     0b 00 00 00 14 00 1a 00 08 00 01 00 1c 00 00 00 ................', log)
    assert match('dump_hex:     08 00 02 00 0a 00 00 00 14 00 1b 00 08 00 01 00 ................', log)
    assert match('dump_hex:     1d 00 00 00 08 00 02 00 0b 00 00 00 14 00 1c 00 ................', log)
    assert match('dump_hex:     08 00 01 00 21 00 00 00 08 00 02 00 0b 00 00 00 ....!...........', log)
    assert match('dump_hex:     14 00 1d 00 08 00 01 00 20 00 00 00 08 00 02 00 ........ .......', log)
    assert match('dump_hex:     0c 00 00 00 14 00 1e 00 08 00 01 00 4b 00 00 00 ............K...', log)
    assert match('dump_hex:     08 00 02 00 0b 00 00 00 14 00 1f 00 08 00 01 00 ................', log)
    assert match('dump_hex:     4c 00 00 00 08 00 02 00 0b 00 00 00 14 00 20 00 L............. .', log)
    assert match('dump_hex:     08 00 01 00 25 00 00 00 08 00 02 00 0b 00 00 00 ....%...........', log)
    assert match('dump_hex:     14 00 21 00 08 00 01 00 26 00 00 00 08 00 02 00 ..!.....&.......', log)

    # Done testing this payload. Too big.
    for line in log:
        if line.startswith('dump_hex'):
            continue
        rem = log.index(line)
        assert 20 < rem  # At least check that there were a lot of log statements skipped.
        log = log[rem:]
        break

    assert match('dump_attrs:   \[ATTR 07\] \d{3} octets', log, True)
    assert match('dump_hex:     18 00 01 00 08 00 02 00 .. 00 00 00 0b 00 01 00 ................', log, True)
    assert match('dump_hex:     63 6f 6e 66 69 67 00 00 18 00 02 00 08 00 02 00 config..........', log)
    assert match('dump_hex:     .. 00 00 00 09 00 01 00 73 63 61 6e 00 00 00 00 ........scan....', log, True)
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
    assert match('print_hdr:     .type = 16 <0x10>', log)
    assert match('print_hdr:     .flags = 5 <REQUEST,ACK>', log)
    assert match('print_hdr:     .seq = \d{10}', log, True)
    assert match('print_hdr:     .port = \d{3,}', log, True)
    assert match('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------', log)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Increased expected sequence number to \d{10}', log, True)

    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message, maxlen=4096', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message, maxlen=4096', log, True)
    assert match('nlmsg_put: msg 0x[a-f0-9]+: Added netlink header type=\d{2}, flags=0, pid=0, seq=0', log, True)
    assert match('nlmsg_reserve: msg 0x[a-f0-9]+: Reserved 4 \(4\) bytes, pad=4, nlmsg_len=20', log, True)
    assert match('genlmsg_put: msg 0x[a-f0-9]+: Added generic netlink header cmd=33 version=0', log, True)
    assert match(
        'nla_reserve: msg 0x[a-f0-9]+: attr <0x[a-f0-9]+> 3: Reserved 8 \(4\) bytes at offset \+4 nlmsg_len=28',
        log, True)
    assert match('nla_put: msg 0x[a-f0-9]+: attr <0x[a-f0-9]+> 3: Wrote 4 bytes at offset \+4', log, True)
    assert match(
        'nla_reserve: msg 0x[a-f0-9]+: attr <0x[a-f0-9]+> 1: Reserved 4 \(0\) bytes at offset \+0 nlmsg_len=20',
        log, True)
    assert match('nla_put_nested: msg 0x[a-f0-9]+: attr <> 45: adding msg 0x[a-f0-9]+ as nested attribute', log, True)
    assert match(
        'nla_reserve: msg 0x[a-f0-9]+: attr <0x[a-f0-9]+> 45: Reserved 8 \(4\) bytes at offset \+12 nlmsg_len=36',
        log, True)
    assert match('nla_put: msg 0x[a-f0-9]+: attr <0x[a-f0-9]+> 45: Wrote 4 bytes at offset \+12', log, True)
    assert match('nl_msg_out_handler_debug: -- Debug: Sent Message:', log)
    assert match('nl_msg_dump: --------------------------   BEGIN NETLINK MESSAGE ---------------------------', log)
    assert match('nl_msg_dump:   [NETLINK HEADER] 16 octets', log)
    assert match('print_hdr:     .nlmsg_len = 36', log)
    assert match('print_hdr:     .type = \d{2} <0x\w{2}>', log, True)
    assert match('print_hdr:     .flags = 5 <REQUEST,ACK>', log)
    assert match('print_hdr:     .seq = \d{10}', log, True)
    assert match('print_hdr:     .port = \d{3,}', log, True)
    assert match('print_genl_hdr:   [GENERIC NETLINK HEADER] 4 octets', log)
    assert match('print_genl_hdr:     .cmd = 33', log)
    assert match('print_genl_hdr:     .version = 0', log)
    assert match('print_genl_hdr:     .unused = 0', log)
    assert match('print_msg:   [PAYLOAD] 16 octets', log)
    assert match('dump_hex:     08 00 03 00 .. 00 00 00 08 00 2d 00 04 00 01 00 ..........-.....', log, True)
    assert match('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------', log)
    assert match('nl_sendmsg: sent 36 bytes', log)
    assert match('recvmsgs: Attempting to read from 0x[a-f0-9]+', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Read \d{3} bytes', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Processing valid message...', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message, maxlen=\d{3}', log, True)
    assert match('recvmsgs: Attempting to read from 0x[a-f0-9]+', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Read 36 bytes', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Processing valid message...', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message, maxlen=36', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Increased expected sequence number to \d{10}', log, True)
    assert match('recvmsgs: Attempting to read from 0x[a-f0-9]+', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Read \d{3} bytes', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Processing valid message...', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message, maxlen=\d{3}', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message, maxlen=4096', log, True)
    assert match('nlmsg_put: msg 0x[a-f0-9]+: Added netlink header type=\d{2,}, flags=768, pid=0, seq=0', log, True)
    assert match('nlmsg_reserve: msg 0x[a-f0-9]+: Reserved 4 \(4\) bytes, pad=4, nlmsg_len=20', log, True)
    assert match('genlmsg_put: msg 0x[a-f0-9]+: Added generic netlink header cmd=32 version=0', log, True)
    assert match(
        'nla_reserve: msg 0x[a-f0-9]+: attr <0x[a-f0-9]+> 3: Reserved 8 \(4\) bytes at offset \+4 nlmsg_len=28',
        log, True)
    assert match('nla_put: msg 0x[a-f0-9]+: attr <0x[a-f0-9]+> 3: Wrote 4 bytes at offset \+4', log, True)
    assert match('nl_msg_out_handler_debug: -- Debug: Sent Message:', log)
    assert match('nl_msg_dump: --------------------------   BEGIN NETLINK MESSAGE ---------------------------', log)
    assert match('nl_msg_dump:   [NETLINK HEADER] 16 octets', log)
    assert match('print_hdr:     .nlmsg_len = 28', log)
    assert match('print_hdr:     .type = \d{2} <0x\w{2}>', log, True)
    assert match('print_hdr:     .flags = 773 <REQUEST,ACK,ROOT,MATCH>', log)
    assert match('print_hdr:     .seq = \d{10}', log, True)
    assert match('print_hdr:     .port = \d{3,}', log, True)
    assert match('print_genl_hdr:   [GENERIC NETLINK HEADER] 4 octets', log)
    assert match('print_genl_hdr:     .cmd = 32', log)
    assert match('print_genl_hdr:     .version = 0', log)
    assert match('print_genl_hdr:     .unused = 0', log)
    assert match('print_msg:   [PAYLOAD] 8 octets', log)
    assert match('dump_hex:     08 00 03 00 .. 00 00 00                         ........', log, True)
    assert match('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------', log)
    assert match('nl_sendmsg: sent 28 bytes', log)

    # Skip any SSIDs found.
    rem = log.index('print_hdr:     .type = 3 <DONE>') - 8
    log = log[rem:]

    assert match('recvmsgs: Attempting to read from 0x[a-f0-9]+', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Read 20 bytes', log, True)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Processing valid message...', log, True)
    assert match('nlmsg_alloc: msg 0x[a-f0-9]+: Allocated new message, maxlen=20', log, True)
    assert match('nl_msg_in_handler_debug: -- Debug: Received Message:', log)
    assert match('nl_msg_dump: --------------------------   BEGIN NETLINK MESSAGE ---------------------------', log)
    assert match('nl_msg_dump:   [NETLINK HEADER] 16 octets', log)
    assert match('print_hdr:     .nlmsg_len = 20', log)
    assert match('print_hdr:     .type = 3 <DONE>', log)
    assert match('print_hdr:     .flags = 2 <MULTI>', log)
    assert match('print_hdr:     .seq = \d{10}', log, True)
    assert match('print_hdr:     .port = \d{3,}', log, True)
    assert match('print_genl_hdr:   [GENERIC NETLINK HEADER] 4 octets', log)
    assert match('print_genl_hdr:     .cmd = 0', log)
    assert match('print_genl_hdr:     .version = 0', log)
    assert match('print_genl_hdr:     .unused = 0', log)
    assert match('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------', log)
    assert match('recvmsgs: recvmsgs\(0x[a-f0-9]+\): Increased expected sequence number to \d{10}', log, True)
    assert match(('nl_finish_handler_debug: -- Debug: End of multipart message block: type=DONE length=20 '
                  'flags=<MULTI> sequence-nr=\d{10} pid=\d{3,}'), log, True)

    assert not log
