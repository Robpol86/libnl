import re
import socket

import pytest

from libnl.attr import nla_put_u32, nla_get_u32, nla_parse, nla_get_string, nla_get_u64, nla_data
from libnl.genl.ctrl import genl_ctrl_resolve
from libnl.genl.genl import genl_connect, genlmsg_put, genlmsg_attrdata, genlmsg_attrlen
from libnl.handlers import NL_CB_VALID, NL_CB_CUSTOM, NL_SKIP
from libnl.linux_private.genetlink import genlmsghdr
from libnl.msg import nlmsg_alloc, nlmsg_hdr
from libnl.msg_ import nlmsg_data
from libnl.nl import nl_send_auto, nl_recvmsgs_default, nl_wait_for_ack
from libnl import nl80211
from libnl.socket_ import nl_socket_alloc, nl_socket_modify_cb, nl_socket_free


def match(expected, log, is_regex=False):
    log_statement = log.pop(0)
    if is_regex:
        assert re.match(expected + '$', log_statement)
    else:
        assert expected == log_statement
    return True


@pytest.mark.skipif('True')  # @pytest.mark.skipif('not os.path.exists("/sys/class/net/wlan0")')
@pytest.mark.usefixtures('nlcb_debug')
def test_cmd_get_interface(log):
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
        if (tb[NL80211_ATTR_WDEV]) printf("%d == NL80211_ATTR_WDEV\n", nla_get_u64(tb[NL80211_ATTR_WDEV]));
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
    // 0 == NL80211_ATTR_WDEV
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
        tb = {i: None for i in range(nl80211.NL80211_ATTR_MAX + 1)}
        nla_parse(tb, nl80211.NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), None)
        assert b'wlan0' == nla_get_string(tb[nl80211.NL80211_ATTR_IFNAME])
        assert 0 == nla_get_u32(tb[nl80211.NL80211_ATTR_WIPHY])
        assert '00:0f:b5:d3:fa:76' == ':'.join(format(x, '02x') for x in nla_data(tb[nl80211.NL80211_ATTR_MAC])[:6])
        assert 3 == nla_get_u32(tb[nl80211.NL80211_ATTR_IFINDEX])
        assert 0 == nla_get_u64(tb[nl80211.NL80211_ATTR_WDEV])
        assert 2 == nla_get_u32(tb[nl80211.NL80211_ATTR_IFTYPE])
        return NL_SKIP
    if_index = socket.if_nametoindex('wlan0')
    sk = nl_socket_alloc()
    msg_main = nlmsg_alloc()
    genl_connect(sk)
    driver_id = genl_ctrl_resolve(sk, b'nl80211')
    log.clear()
    nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, callback, None)
    genlmsg_put(msg_main, 0, 0, driver_id, 0, 0, nl80211.NL80211_CMD_GET_INTERFACE, 0)
    nla_put_u32(msg_main, nl80211.NL80211_ATTR_IFINDEX, if_index)
    assert 28 == nl_send_auto(sk, msg_main)
    assert 0 == nl_recvmsgs_default(sk)
    nl_wait_for_ack(sk)
    nl_socket_free(sk)

    assert match('nlmsg_put: msg 0x[a-f0-9]+: Added netlink header type=22, flags=0, pid=0, seq=0', log, True)
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
    assert match('print_hdr:     .type = 22 <0x16>', log)
    assert match('print_hdr:     .flags = 5 <REQUEST,ACK>', log)
    assert match('print_hdr:     .seq = \d{10}', log, True)
    assert match('print_hdr:     .port = \d{3,}', log, True)
    assert match('print_genl_hdr:   [GENERIC NETLINK HEADER] 4 octets', log)
    assert match('print_genl_hdr:     .cmd = 5', log)
    assert match('print_genl_hdr:     .version = 0', log)
    assert match('print_genl_hdr:     .unused = 0', log)
    assert match('print_msg:   [PAYLOAD] 8 octets', log)
    assert match('dump_hex:     08 00 03 00 03 00 00 00                         ........', log)
    assert match('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------', log)
    assert match('nl_sendmsg: sent 28 bytes', log)

    assert not log
