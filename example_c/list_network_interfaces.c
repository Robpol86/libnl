/*
 * "Staging" code before porting it to Python. Lists network interfaces on the host through libnl (netlink).
 *
 * I don't know C so it was hard to get a Python application to talk to the kernel by looking at C code, trying to
 * resolve header files and variable origins/values in my head.
 *
 * I'm "staging" my code here in C and once it's working I'll port it over to Python. Here I can insert printf
 * statements to learn what the values of some variables are, and so on.
 *
 * None of this code is used by the Python library/module.
 *
 * Raspbian prerequisites:
 *      sudo apt-get install libnl-genl-3-dev
 *
 * Build and execute:
 *      gcc -o program list_network_interfaces.c $(pkg-config --cflags --libs libnl-genl-3.0) && ./program
 *
 * Resources:
 *      http://lwn.net/Articles/208755/
 *      http://www.carisma.slowglass.com/~tgr/libnl/doc/core.html
 *      http://stackoverflow.com/questions/3299386/
 *      http://iijean.blogspot.com/2010/03/howto-get-list-of-network-interfaces-in.html
 *      https://github.com/ruslanti/rubicon/blob/master/stats/stats.c
 *      https://github.com/Robpol86/libnl/tree/master/example_c
 *
 * Expected output:
 *      nl_send_simple returned 20
 *      Found network interface 1: lo
 *      Found network interface 2: eth0
 *      Found network interface 3: wlan0
 *
 */
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>


static int callback(struct nl_msg *msg, void *arg) {
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct ifinfomsg *iface = NLMSG_DATA(nlh);
    struct rtattr *hdr = IFLA_RTA(iface);
    int remaining = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*iface));

    //printf("Got something.\n");
    //nl_msg_dump(msg, stdout);

    while (RTA_OK(hdr, remaining)) {
        //printf("Loop\n");

        if (hdr->rta_type == IFLA_IFNAME) {
            printf("Found network interface %d: %s\n", iface->ifi_index, (char *) RTA_DATA(hdr));
        }

        hdr = RTA_NEXT(hdr, remaining);
    }

    return NL_OK;
}

int main() {
    // Open socket to kernel.
    struct nl_sock *socket = nl_socket_alloc();  // Allocate new netlink socket in memory.
    nl_connect(socket, NETLINK_ROUTE);  // Create file descriptor and bind socket.

    // Send request for all network interfaces.
    struct rtgenmsg rt_hdr = { .rtgen_family = AF_PACKET, };
    int ret = nl_send_simple(socket, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, &rt_hdr, sizeof(rt_hdr));
    printf("nl_send_simple returned %d\n", ret);

    // Retrieve the kernel's answer.
    nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, callback, NULL);
    nl_recvmsgs_default(socket);

    return 0;
}
