import re

import pytest

from libnl.genl.ctrl import genl_ctrl_resolve
from libnl.genl.genl import genl_connect
from libnl.socket_ import nl_socket_alloc


def match(expected, log, is_regex=False):
    log_statement = log.pop(0)
    if is_regex:
        assert re.match(expected, log_statement)
    else:
        assert expected == log_statement
    return True


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
    driver_id = genl_ctrl_resolve(sk, 'nl80211'.encode('ascii'))

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
    assert match('print_hdr:     .port = \d{4,}', log, True)
    assert match('print_msg:   [GENERIC NETLINK HEADER] 4 octets', log)
    assert match('print_hdr:     .cmd = 3', log)
    assert match('print_hdr:     .version = 1', log)
    assert match('print_hdr:     .unused = 0', log)
    assert match('print_msg:   [ATTR 02] 8 octets', log)
    assert match('dump_hex:     6e 6c 38 30 32 31 31 00                         nl80211.', log)
    assert match('nl_msg_dump: ---------------------------  END NETLINK MESSAGE   ---------------------------', log)
    assert match('nl_sendmsg: sent 32 bytes', log)

    assert 20 == driver_id
    assert not log
