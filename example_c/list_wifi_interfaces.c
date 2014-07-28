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


void interface() {
    struct rtgenmsg rt_hdr = { .rtgen_family = AF_UNSPEC, };
    struct nl_sock *sk;
    sk = nl_socket_alloc();
    
    nl_connect(sk, NETLINK_ROUTE);
    int ret = nl_send_simple(sk, RTM_GETLINK, NLM_F_DUMP, &rt_hdr, sizeof(rt_hdr));
    printf("nl_send_simple returned %d\n", ret);
}


int main() {
    printf("NL80211_CMD_GET_WIPHY: %d\n", NL80211_CMD_GET_WIPHY);
    printf("NLM_F_REQUEST: %d\n", NLM_F_REQUEST);
    printf("NLM_F_DUMP: 0x%04x\n", NLM_F_DUMP);

    interface();

    return 0;
}
