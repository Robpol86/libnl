/*
 * Program just prints values that the python library should mimic. Linux only.
 *
 * Raspbian prerequisites:
 *      sudo apt-get install libnl-genl-3-dev
 *
 * Execute:
 *      gcc $(pkg-config --cflags --libs libnl-genl-3.0) correct_answers.c && ./a.out
 */

#include <netlink/netlink.h>
#include <netlink/attr.h>
#include <netlink/msg.h>


void netlink_macros() {  // For tests of: libnl.linux_private.netlink
    int i, range[] = { 0, 1, 2, 19, 20, 50 };
    int i_size = sizeof(range) / sizeof(int);
    struct nlmsghdr *nlh = malloc(sizeof(struct nlmsghdr));
    nlh->nlmsg_len = 20;
    nlh->nlmsg_type = NL_CB_VALID;
    nlh->nlmsg_flags = NLM_F_DUMP;

    // NLMSG_ALIGN
    for (i = 0; i < i_size; i++) printf("\"NLMSG_ALIGN(%d)\": %d,\n", range[i], NLMSG_ALIGN(range[i]));

    // NLMSG_HDRLEN
    printf("\"NLMSG_HDRLEN\": %d,\n", NLMSG_HDRLEN);

    // NLMSG_LENGTH
    for (i = 0; i < i_size; i++) printf("\"NLMSG_LENGTH(%d)\": %d,\n", range[i], NLMSG_LENGTH(range[i]));

    // NLMSG_SPACE
    for (i = 0; i < i_size; i++) printf("\"NLMSG_SPACE(%d)\": %d,\n", range[i], NLMSG_SPACE(range[i]));

    // NLMSG_DATA
    struct nlattr *head = (struct nlattr *) (NLMSG_DATA(nlh) + NLMSG_LENGTH(sizeof(struct nlmsghdr)) - NLMSG_ALIGNTO);
    printf("\"NLMSG_DATA(sizeof)\": %d,\n", sizeof(head));
    printf("\"NLMSG_DATA(len)\": %d,\n", head->nla_len);
    printf("\"NLMSG_DATA(type)\": %d,\n", head->nla_type);

    // NLMSG_OK
    for (i = 0; i < i_size; i++)
        printf("\"NLMSG_OK(nlh, %d)\": %s,\n", range[i], NLMSG_OK(nlh, range[i]) ? "true" : "false");

    // NLMSG_PAYLOAD
    for (i = 0; i < i_size; i++) printf("\"NLMSG_PAYLOAD(nlh, %d)\": %d,\n", range[i], NLMSG_PAYLOAD(nlh, range[i]));

    // NLA_ALIGN
    for (i = 0; i < i_size; i++) printf("\"NLA_ALIGN(%d)\": %d,\n", range[i], NLA_ALIGN(range[i]));

    // NLA_HDRLEN
    printf("\"NLA_HDRLEN\": %d,\n", NLA_HDRLEN);
}


void msg_attr() {  // For tests of: libnl.msg and libnl.attr
    int rem, i, range[] = { 0, 1, 2, 19, 20, 50 };
    struct nl_msg *msg = nlmsg_alloc();
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct nlattr *nla;
    for (i = 0; i < (sizeof(range) / sizeof(int)); i++) nla_put_u32(msg, i, i + 1);
    nlmsg_for_each_attr(nla, nlh, 0, rem) printf("nla_type: %d; nla_get_u32: %d\n", nla_type(nla), nla_get_u32(nla));
    nlmsg_free(msg);
}


int main() {
    printf("{\n");
    netlink_macros();
    msg_attr();
    printf("\"end\": null}\n");
    return 0;
}
