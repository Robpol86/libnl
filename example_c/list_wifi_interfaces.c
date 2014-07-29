/*
 * "Staging" code before porting it to Python. Lists wireless interfaces on the host through nl80211.
 *
 * I don't know C so it was hard to get a Python application to talk to the kernel by looking at C code, trying to
 * resolve header files and variable origins/values in my head.
 *
 * I'm "staging" my code here in C and once it's working I'll port it over to Python. Here I can insert printf
 * statements to learn what the values of some variables are, and so on.
 *
 * None of this code is used by the Python library/module.
 *
 * Resources:
 *      http://lwn.net/Articles/208755/
 *      http://www.carisma.slowglass.com/~tgr/libnl/doc/core.html
 *      http://stackoverflow.com/questions/3299386/
 *
 */
#include <stdio.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/genl/genl.h>
#include <linux/nl80211.h>


static int callback(struct nl_msg *msg, void *arg) {
    printf("Got something.\n");
    //struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));  // TODO I don't know what this does yet.
    //struct nlattr *tb_msg[CTRL_ATTR_MAX+1];  // TODO this too.
    //printf("%s\n", nla_get_string(msg));
    return 0;
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
