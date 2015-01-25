from libnl.attr import nla_type, nla_put_u32, nla_get_u32
from libnl.msg import nlmsg_alloc, nlmsg_hdr


def test_nla_put_get_u32():
    """// gcc $(pkg-config --cflags --libs libnl-genl-3.0) a.c && ./a.out
    #include <netlink/msg.h>
    int main() {
        int rem, i, range[] = { 0, 1, 2, 19, 20, 50 };
        struct nl_msg *msg = nlmsg_alloc();
        struct nlmsghdr *nlh = nlmsg_hdr(msg);
        struct nlattr *nla;
        for (i = 0; i < (sizeof(range) / sizeof(int)); i++) nla_put_u32(msg, i, range[i]);
        nlmsg_for_each_attr(nla, nlh, 0, rem) printf("type: %d; nla_get_u32: %d\n", nla_type(nla), nla_get_u32(nla));
        nlmsg_free(msg);
        return 0;
    }
    // Expected output:
    // type: 0; nla_get_u32: 0
    // type: 1; nla_get_u32: 1
    // type: 2; nla_get_u32: 2
    // type: 3; nla_get_u32: 19
    // type: 4; nla_get_u32: 20
    // type: 5; nla_get_u32: 50
    """
    range_ = (0, 1, 2, 19, 20, 50)
    msg = nlmsg_alloc()
    for i in range(len(range_)):
        nla_put_u32(msg, i, range_[i])
    nlh = nlmsg_hdr(msg)
    i = 0
    for nla in nlh.attrs:
        assert i == nla_type(nla)
        assert range_[i] == nla_get_u32(nla)
        i += 1
