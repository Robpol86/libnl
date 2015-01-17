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


void netlink_py() {  // For tests of: libnl.linux_private.netlink
    int i, range[] = { 0, 1, 2, 19, 20, 50 };
    int i_size = sizeof(range) / sizeof(int);
    struct nlmsghdr *nlh = malloc(sizeof(struct nlmsghdr));
    nlh->nlmsg_len = 20;
    nlh->nlmsg_type = NL_CB_VALID;
    nlh->nlmsg_flags = NLM_F_DUMP;
    static char nlh_repr[] = "pointer(nlmsghdr(nlmsg_len=20, nlmsg_type=NL_CB_VALID, nlmsg_flags=NLM_F_DUMP))";

    // NLMSG_ALIGN
    for (i = 0; i < i_size; i++) printf("assert %d == NLMSG_ALIGN(%d)\n", NLMSG_ALIGN(range[i]), range[i]);
    printf("\n");

    // NLMSG_HDRLEN
    printf("assert %d == NLMSG_HDRLEN\n\n", NLMSG_HDRLEN);

    // NLMSG_LENGTH
    for (i = 0; i < i_size; i++) printf("assert %d == NLMSG_LENGTH(%d)\n", NLMSG_LENGTH(range[i]), range[i]);
    printf("\n");

    // NLMSG_SPACE
    for (i = 0; i < i_size; i++) printf("assert %d == NLMSG_SPACE(%d)\n", NLMSG_SPACE(range[i]), range[i]);
    printf("\n");

    // NLMSG_DATA
    // printf("assert %d == NLMSG_DATA(%s)\n\n", NLMSG_DATA(nlh), nlh_repr);

    // NLMSG_OK
    printf("nlh = %s\n", nlh_repr);
    for (i = 0; i < i_size; i++)
        printf("assert %s == NLMSG_OK(nlh, %d)\n", NLMSG_OK(nlh, range[i]) ? "True" : "False", range[i]);
    printf("\n");

    // NLMSG_PAYLOAD
    // for (i = 0; i < i_size; i++)
    //     printf("assert %d == NLMSG_PAYLOAD(%s, %d)\n", NLMSG_PAYLOAD(nlh, range[i]), nlh_repr, range[i]);
    // printf("\n");
}


int main() {
    netlink_py();
    return 0;
}
