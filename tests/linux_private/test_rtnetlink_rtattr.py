import socket

from libnl.handlers import NL_OK, NL_CB_VALID, NL_CB_CUSTOM
from libnl.linux_private.if_link import IFLA_IFNAME, IFLA_RTA
from libnl.linux_private.netlink import NETLINK_ROUTE, NLM_F_REQUEST, NLM_F_DUMP, NLMSG_LENGTH
from libnl.linux_private.rtnetlink import rtgenmsg, RTM_GETLINK, ifinfomsg, RTA_NEXT, RTA_DATA, RTA_OK
from libnl.misc import get_string, c_int
from libnl.msg import nlmsg_hdr, nlmsg_data
from libnl.nl import nl_connect, nl_recvmsgs_default, nl_send_simple
from libnl.socket_ import nl_socket_alloc, nl_socket_free, nl_socket_modify_cb


def test_list_interfaces(ifacesi):
    """// gcc a.c $(pkg-config --cflags --libs libnl-genl-3.0) && ./a.out
    #include <netlink/msg.h>
    static int callback(struct nl_msg *msg, void *arg) {
        struct nlmsghdr *nlh = nlmsg_hdr(msg);
        struct ifinfomsg *iface = NLMSG_DATA(nlh);
        struct rtattr *hdr = IFLA_RTA(iface);
        int remaining = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*iface));

        while (RTA_OK(hdr, remaining)) {
            if (hdr->rta_type == IFLA_IFNAME) {
                printf("Found network interface %d: %s\n", iface->ifi_index, (char *) RTA_DATA(hdr));
            }
            hdr = RTA_NEXT(hdr, remaining);
        }
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
    // Expected output:
    // 0 == nl_connect(sk, NETLINK_ROUTE)
    // Bytes Sent: 20
    // Found network interface 1: lo
    // Found network interface 2: eth0
    // Found network interface 4: wlan0
    // 0 == nl_recvmsgs_default(sk)
    """
    got_something = dict()

    def callback(msg, arg):
        nlh = nlmsg_hdr(msg)
        iface = ifinfomsg(nlmsg_data(nlh))
        hdr = IFLA_RTA(iface)
        remaining = c_int(nlh.nlmsg_len - NLMSG_LENGTH(iface.SIZEOF))

        while RTA_OK(hdr, remaining):
            if hdr.rta_type == IFLA_IFNAME:
                arg[int(iface.ifi_index)] = str(get_string(RTA_DATA(hdr)).decode('ascii'))
            hdr = RTA_NEXT(hdr, remaining)
        return NL_OK

    sk = nl_socket_alloc()
    nl_connect(sk, NETLINK_ROUTE)
    rt_hdr = rtgenmsg(rtgen_family=socket.AF_PACKET)
    assert 20 == nl_send_simple(sk, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, rt_hdr, rt_hdr.SIZEOF)

    assert 0 == nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, callback, got_something)
    assert 0 == nl_recvmsgs_default(sk)
    assert dict(ifacesi) == got_something

    nl_socket_free(sk)
