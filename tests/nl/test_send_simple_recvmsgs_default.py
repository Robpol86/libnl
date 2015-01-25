from ctypes import c_int
from socket import AF_PACKET, NETLINK_ROUTE

import pytest

from libnl.handlers import NL_OK, NL_CB_VALID, NL_CB_CUSTOM
from libnl.linux_private.netlink import NLM_F_REQUEST, NLM_F_DUMP
from libnl.socket_ import nl_socket_alloc


@pytest.mark.skipif('True')
def test_callback():
    """// gcc $(pkg-config --cflags --libs libnl-genl-3.0) a.c && ./a.out
    #include <netlink/msg.h>
    static int callback(struct nl_msg *msg, void *arg) { int *ret = arg; *ret = 123; return NL_OK; }
    int main() {
        struct nl_sock *socket = nl_socket_alloc();
        nl_connect(socket, NETLINK_ROUTE);  // Create file descriptor and bind socket.
        struct rtgenmsg rt_hdr = { .rtgen_family = AF_PACKET, };
        printf("Bytes: %d\n", nl_send_simple(socket, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, &rt_hdr, sizeof(rt_hdr)));
        int ret = 0;
        nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, callback, &ret);
        nl_recvmsgs_default(socket);
        printf("Should be 123: %d\n", ret);
        return 0;
    }
    // Expected output:
    // Bytes sent: 20
    // Should be 123: 123
    """
    def callback(_, arg):
        arg.value = 123
        return NL_OK
    socket = nl_socket_alloc()
    nl_connect(socket, NETLINK_ROUTE)
    rt_hdr = rtgenmsg(rtgen_family=AF_PACKET)
    assert 20 == nl_send_simple(socket, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, rt_hdr)
    ret = c_int(0)
    nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, callback, ret)
    nl_recvmsgs_default(socket)
    assert 123 == ret.value
