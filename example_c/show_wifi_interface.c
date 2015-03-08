/*
 * "Staging" code before porting it to Python. Shows basic info about a wireless interface using NL80211 (netlink).
 *
 * Only works on network interfaces whose drivers are compatible with Netlink. Test this by running `iw list`.
 *
 * Probably prints more data if the wireless interface is in AP mode, expected output in this comment block is only for
 * one wireless interface in regular client mode.
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
 *      gcc -o program show_wifi_interface.c $(pkg-config --cflags --libs libnl-genl-3.0) && ./program
 *
 * Resources:
 *      http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/interface.c#n303
 *      http://lxr.free-electrons.com/source/lib/nlattr.c#L169
 *      http://stackoverflow.com/questions/21601521/how-to-use-the-libnl-library-to-trigger-nl80211-commands
 *      https://github.com/Robpol86/libnl/tree/master/example_c
 *
 * Expected output:
 *      >>> Getting info for wlan0:
 *      nl_send_auto_complete returned 28
 *      Interface wlan0
 *      wiphy 0
 *      NOT IMPLEMENTED
 *      ifindex 2
 *      wdev 0x1
 *      NOT IMPLEMENTED
 *      NOT IMPLEMENTED, NOT IMPLEMENTED, center1: 2447 MHz
 *      ------------------------------
 *      >>> Getting info for all interfaces:
 *      nl_send_auto_complete returned 20
 *      Interface wlan1
 *      List mode, no interface specified.
 *      phy#1
 *      NOT IMPLEMENTED
 *      ifindex 3
 *      wdev 0x100000001
 *      NOT IMPLEMENTED
 *      ------------------------------
 *      Interface wlan0
 *      List mode, no interface specified.
 *      phy#0
 *      NOT IMPLEMENTED
 *      ifindex 2
 *      wdev 0x1
 *      NOT IMPLEMENTED
 *      NOT IMPLEMENTED, NOT IMPLEMENTED, center1: 2447 MHz
 *      ------------------------------
 *      >>> Program exit.
 *
 */
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <linux/nl80211.h>


static int callback(struct nl_msg *msg, void *arg) {
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
    unsigned int *wiphy = arg;

    //printf("Got something.\n");
    //printf("%d\n", arg);
    //nl_msg_dump(msg, stdout);

    // Looks like this parses `msg` into the `tb_msg` array with pointers.
    nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    // Print everything.
    if (tb_msg[NL80211_ATTR_IFNAME]) {
        printf("Interface %s\n", nla_get_string(tb_msg[NL80211_ATTR_IFNAME]));
    } else {
        printf("Unnamed/non-netdev interface\n");
    }
    if (wiphy && tb_msg[NL80211_ATTR_WIPHY]) {
        printf("List mode, no interface specified.\n");
        unsigned int thiswiphy = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]);
        if (*wiphy != thiswiphy) printf("phy#%d\n", thiswiphy);
        *wiphy = thiswiphy;
    } else if (tb_msg[NL80211_ATTR_WIPHY]) {  // From interface.c#n343.
        printf("wiphy %d\n", nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]));
    }
    if (tb_msg[NL80211_ATTR_MAC]) {
        //char mac_addr[20];
        //mac_addr_n2a(mac_addr, nla_data(tb_msg[NL80211_ATTR_MAC]));
        printf("NOT IMPLEMENTED\n");
        //printf("addr %s\n", mac_addr);
    }
    if (tb_msg[NL80211_ATTR_SSID]) {
        //printf("ssid ");
        //print_ssid_escaped(nla_len(tb_msg[NL80211_ATTR_SSID]), nla_data(tb_msg[NL80211_ATTR_SSID]));
        printf("NOT IMPLEMENTED\n");
        //printf("\n");
    }

    // Keep printing everything.
    if (tb_msg[NL80211_ATTR_IFINDEX]) printf("ifindex %d\n", nla_get_u32(tb_msg[NL80211_ATTR_IFINDEX]));
    // (tb_msg[NL80211_ATTR_WDEV]) printf("wdev 0x%llx\n", (unsigned long long)nla_get_u64(tb_msg[NL80211_ATTR_WDEV]));
    if (tb_msg[NL80211_ATTR_IFTYPE])
        printf("NOT IMPLEMENTED\n");
        //printf("type %s\n", iftype_name(nla_get_u32(tb_msg[NL80211_ATTR_IFTYPE])));

    // Final print.
    if (tb_msg[NL80211_ATTR_WIPHY_FREQ]) {  // git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/interface.c#n345
        uint32_t freq = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_FREQ]);
        //printf("channel %d (%d MHz)", ieee80211_frequency_to_channel(freq), freq);
        printf("NOT IMPLEMENTED");
/*
        if (tb_msg[NL80211_ATTR_CHANNEL_WIDTH]) {
            //printf(", width: %s", channel_width_name(nla_get_u32(tb_msg[NL80211_ATTR_CHANNEL_WIDTH])));
            printf(", NOT IMPLEMENTED");
            if (tb_msg[NL80211_ATTR_CENTER_FREQ1])
                printf(", center1: %d MHz", nla_get_u32(tb_msg[NL80211_ATTR_CENTER_FREQ1]));
            if (tb_msg[NL80211_ATTR_CENTER_FREQ2])
                printf(", center2: %d MHz", nla_get_u32(tb_msg[NL80211_ATTR_CENTER_FREQ2]));
        } else if (tb_msg[NL80211_ATTR_WIPHY_CHANNEL_TYPE]) {
            enum nl80211_channel_type channel_type;
            channel_type = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_CHANNEL_TYPE]);
            //printf(" %s", channel_type_name(channel_type));
            printf(" NOT IMPLEMENTED");
        }
*/
        printf("\n");
    }

    printf("------------------------------\n");

    return NL_SKIP;
}

int main() {
    struct nl_msg *msg;
    int ret;

    // Open socket to kernel.
    struct nl_sock *socket = nl_socket_alloc();  // Allocate new netlink socket in memory.
    genl_connect(socket);  // Create file descriptor and bind socket.
    int driver_id = genl_ctrl_resolve(socket, "nl80211");  // Find the nl80211 driver ID.

    // First we'll get info for wlan0.
    printf(">>> Getting info for wlan0:\n");
    nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, callback, NULL);
    msg = nlmsg_alloc();  // Allocate a message.
    int if_index = if_nametoindex("wlan0");
    genlmsg_put(msg, 0, 0, driver_id, 0, 0, NL80211_CMD_GET_INTERFACE, 0);  // Setup the message.
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, if_index);  // Add message attributes.
    ret = nl_send_auto_complete(socket, msg);  // Send the message.
    printf("nl_send_auto_complete returned %d\n", ret);
    nl_recvmsgs_default(socket);  // Retrieve the kernel's answer.
    nl_wait_for_ack(socket);

    // Now get info for all wifi interfaces.
    printf(">>> Getting info for all interfaces:\n");
    static unsigned int dev_dump_wiphy = -1;
    nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, callback, &dev_dump_wiphy);
    msg = nlmsg_alloc();  // Allocate a message.
    genlmsg_put(msg, 0, 0, driver_id, 0, NLM_F_DUMP, NL80211_CMD_GET_INTERFACE, 0);  // Setup the message.
    ret = nl_send_auto_complete(socket, msg);  // Send the message.
    printf("nl_send_auto_complete returned %d\n", ret);
    nl_recvmsgs_default(socket);  // Retrieve the kernel's answer.

    printf(">>> Program exit.\n");
    return 0;

    // Goto statement required by NLA_PUT_U32().
    nla_put_failure:
        nlmsg_free(msg);
        return 1;
}
