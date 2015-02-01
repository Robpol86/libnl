from libnl.linux_private.netlink import NETLINK_ROUTE
from libnl.msg import nlmsg_alloc_simple
from libnl.nl import nl_complete_msg, nl_connect
from libnl.socket_ import nl_socket_alloc, nl_socket_get_local_port


def test_defaults():  # TODO test nlmsg_seq
    """// gcc $(pkg-config --cflags --libs libnl-genl-3.0) a.c && ./a.out
    #include <netlink/msg.h>
    struct ucred { __u32 pid; __u32 uid; __u32 gid; };
    struct nl_msg {
        int nm_protocol; int nm_flags; struct sockaddr_nl nm_src; struct sockaddr_nl nm_dst; struct ucred nm_creds;
        struct nlmsghdr *nm_nlh; size_t nm_size; int nm_refcnt;
    };
    struct nl_sock {
        struct sockaddr_nl s_local; struct sockaddr_nl s_peer; int s_fd; int s_proto; unsigned int s_seq_next;
        unsigned int s_seq_expect; int s_flags; struct nl_cb *s_cb; size_t s_bufsize;
    };
    void print(struct nl_msg *msg) {
        printf("%d == msg.nm_protocol\n", msg->nm_protocol);
        printf("%d == msg.nm_flags\n", msg->nm_flags);
        printf("%d == msg.nm_src.nl_family\n", msg->nm_src.nl_family);
        printf("%d == msg.nm_src.nl_pid\n", msg->nm_src.nl_pid);
        printf("%d == msg.nm_src.nl_groups\n", msg->nm_src.nl_groups);
        printf("%d == msg.nm_dst.nl_family\n", msg->nm_dst.nl_family);
        printf("%d == msg.nm_dst.nl_pid\n", msg->nm_dst.nl_pid);
        printf("%d == msg.nm_dst.nl_groups\n", msg->nm_dst.nl_groups);
        printf("%d == msg.nm_nlh.nlmsg_type\n", msg->nm_nlh->nlmsg_type);
        printf("%d == msg.nm_nlh.nlmsg_flags\n", msg->nm_nlh->nlmsg_flags);
        printf("%d == msg.nm_nlh.nlmsg_pid\n", msg->nm_nlh->nlmsg_pid);
    }
    int main() {
        struct nl_sock *sk = nl_socket_alloc();
        struct nl_msg *msg = nlmsg_alloc_simple(0, 0);
        printf("%d == nl_socket_get_local_port(sk)\n", nl_socket_get_local_port(sk));
        printf("%d == sk.s_proto\n", sk->s_proto);
        printf("\n");
        print(msg);
        printf("\n");
        nl_complete_msg(sk, msg);
        print(msg);
        return 0;
    }
    // Expected output:
    // 10083 == nl_socket_get_local_port(sk)
    // 0 == sk.s_proto
    //
    // -1 == msg.nm_protocol
    // 0 == msg.nm_flags
    // 0 == msg.nm_src.nl_family
    // 0 == msg.nm_src.nl_pid
    // 0 == msg.nm_src.nl_groups
    // 0 == msg.nm_dst.nl_family
    // 0 == msg.nm_dst.nl_pid
    // 0 == msg.nm_dst.nl_groups
    // 0 == msg.nm_nlh.nlmsg_type
    // 0 == msg.nm_nlh.nlmsg_flags
    // 0 == msg.nm_nlh.nlmsg_pid
    //
    // 0 == msg.nm_protocol
    // 0 == msg.nm_flags
    // 0 == msg.nm_src.nl_family
    // 0 == msg.nm_src.nl_pid
    // 0 == msg.nm_src.nl_groups
    // 0 == msg.nm_dst.nl_family
    // 0 == msg.nm_dst.nl_pid
    // 0 == msg.nm_dst.nl_groups
    // 0 == msg.nm_nlh.nlmsg_type
    // 5 == msg.nm_nlh.nlmsg_flags
    // 10083 == msg.nm_nlh.nlmsg_pid
    """
    sk = nl_socket_alloc()
    msg = nlmsg_alloc_simple(0, 0)
    local_port = int(nl_socket_get_local_port(sk))
    proto = int(sk.s_proto)

    assert 0 < local_port
    assert 0 == proto

    assert -1 == msg.nm_protocol
    assert 0 == msg.nm_flags
    assert 0 == msg.nm_src.nl_family
    assert 0 == msg.nm_src.nl_pid
    assert 0 == msg.nm_src.nl_groups
    assert 0 == msg.nm_dst.nl_family
    assert 0 == msg.nm_dst.nl_pid
    assert 0 == msg.nm_dst.nl_groups
    assert 0 == msg.nm_nlh.nlmsg_type
    assert 0 == msg.nm_nlh.nlmsg_flags
    assert 0 == msg.nm_nlh.nlmsg_pid

    nl_complete_msg(sk, msg)
    assert proto == msg.nm_protocol
    assert 0 == msg.nm_flags
    assert 0 == msg.nm_src.nl_family
    assert 0 == msg.nm_src.nl_pid
    assert 0 == msg.nm_src.nl_groups
    assert 0 == msg.nm_dst.nl_family
    assert 0 == msg.nm_dst.nl_pid
    assert 0 == msg.nm_dst.nl_groups
    assert 0 == msg.nm_nlh.nlmsg_type
    assert 5 == msg.nm_nlh.nlmsg_flags
    assert local_port == msg.nm_nlh.nlmsg_pid


def test_nlmsg_pid():
    sk = nl_socket_alloc()
    msg = nlmsg_alloc_simple(0, 0)
    assert 0 == msg.nm_nlh.nlmsg_pid

    msg.nm_nlh.nlmsg_pid = 10
    nl_complete_msg(sk, msg)
    assert 10 == msg.nm_nlh.nlmsg_pid


def test_nm_protocol():
    sk = nl_socket_alloc()
    msg = nlmsg_alloc_simple(0, 0)
    assert -1 == msg.nm_protocol

    msg.nm_protocol = 10
    nl_complete_msg(sk, msg)
    assert 10 == msg.nm_protocol


def test_s_proto():
    sk = nl_socket_alloc()
    nl_connect(sk, NETLINK_ROUTE)
    msg = nlmsg_alloc_simple(0, 0)
    assert -1 == msg.nm_protocol

    nl_complete_msg(sk, msg)
    assert NETLINK_ROUTE == msg.nm_protocol
