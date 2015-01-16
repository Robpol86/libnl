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
#include <netlink/genl/genl.h>


void netlink_py() {
    // NLMSG_ALIGN
    int i, range[] = { 0, 1, 2, 19, 38, 50 };
    for (i = 0; i < (sizeof(range) / sizeof(int)); i++) {
        printf("assert %d == NLMSG_ALIGN(%d)\n", NLMSG_ALIGN(range[i]), range[i]);
    }
    printf("\n");

    // NLMSG_HDRLEN
    printf("assert %d == NLMSG_HDRLEN\n\n", NLMSG_HDRLEN);

    // NLMSG_LENGTH
    for (i = 0; i < (sizeof(range) / sizeof(int)); i++) {
        printf("assert %d == NLMSG_LENGTH(%d)\n", NLMSG_LENGTH(range[i]), range[i]);
    }
    printf("\n");

    // NLMSG_SPACE
    for (i = 0; i < (sizeof(range) / sizeof(int)); i++) {
        printf("assert %d == NLMSG_SPACE(%d)\n", NLMSG_SPACE(range[i]), range[i]);
    }
    printf("\n");
}


int main() {
    netlink_py();
    return 0;
}
