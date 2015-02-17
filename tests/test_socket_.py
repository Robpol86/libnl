import pytest

from libnl.handlers import nl_cb_alloc, NL_CB_VERBOSE
from libnl.socket_ import nl_socket_alloc, nl_socket_free


def test_nl_socket_alloc():
    """// gcc $(pkg-config --cflags --libs libnl-genl-3.0) a.c && ./a.out
    #include <netlink/msg.h>
    struct nl_cb {
        nl_recvmsg_msg_cb_t cb_set[NL_CB_TYPE_MAX+1]; void * cb_args[NL_CB_TYPE_MAX+1]; nl_recvmsg_err_cb_t cb_err;
        void * cb_err_arg; int (*cb_recvmsgs_ow)(struct nl_sock *, struct nl_cb *);
        int (*cb_recv_ow)(struct nl_sock *, struct sockaddr_nl *, unsigned char **, struct ucred **);
        int (*cb_send_ow)(struct nl_sock *, struct nl_msg *); int cb_refcnt; enum nl_cb_type cb_active;
    };
    struct nl_sock {
        struct sockaddr_nl s_local; struct sockaddr_nl s_peer; int s_fd; int s_proto; unsigned int s_seq_next;
        unsigned int s_seq_expect; int s_flags; struct nl_cb *s_cb; size_t s_bufsize;
    };
    void print(struct nl_sock *sk) {
        printf("sk.s_local.nl_family = %d\n", sk->s_local.nl_family);
        printf("sk.s_local.nl_pid = %d  # changes every process, remains same throughout proc.\n", sk->s_local.nl_pid);
        printf("sk.s_local.nl_groups = %d\n", sk->s_local.nl_groups);
        printf("sk.s_peer.nl_family = %d\n", sk->s_peer.nl_family);
        printf("sk.s_peer.nl_pid = %d\n", sk->s_peer.nl_pid);
        printf("sk.s_peer.nl_groups = %d\n", sk->s_peer.nl_groups);
        printf("sk.s_fd = %d\n", sk->s_fd);
        printf("sk.s_proto = %d\n", sk->s_proto);
        printf("sk.s_flags = %d\n", sk->s_flags);
        printf("sk.s_cb.cb_active = %d\n", sk->s_cb->cb_active);
        printf("addr: sk.s_cb.cb_err = %p\n", sk->s_cb->cb_err);
    }
    int main() {
        struct nl_sock *sk = nl_socket_alloc();
        print(sk);
        nl_socket_free(sk);
        printf("\n");
        struct nl_cb *cb = nl_cb_alloc(NL_CB_VERBOSE);
        sk = nl_socket_alloc_cb(cb);
        nl_cb_put(cb);
        print(sk);
        nl_socket_free(sk);
        return 0;
    }
    // Expected output:
    // sk.s_local.nl_family = 16
    // sk.s_local.nl_pid = 12309  # changes every process, remains same throughout proc.
    // sk.s_local.nl_groups = 0
    // sk.s_peer.nl_family = 16
    // sk.s_peer.nl_pid = 0
    // sk.s_peer.nl_groups = 0
    // sk.s_fd = -1
    // sk.s_proto = 0
    // sk.s_flags = 0
    // sk.s_cb.cb_active = 11
    // addr: sk.s_cb.cb_err = (nil)
    //
    // sk.s_local.nl_family = 16
    // sk.s_local.nl_pid = 12309  # changes every process, remains same throughout proc.
    // sk.s_local.nl_groups = 0
    // sk.s_peer.nl_family = 16
    // sk.s_peer.nl_pid = 0
    // sk.s_peer.nl_groups = 0
    // sk.s_fd = -1
    // sk.s_proto = 0
    // sk.s_flags = 0
    // sk.s_cb.cb_active = 11
    // addr: sk.s_cb.cb_err = 0xb6f6eb40
    """
    sk = nl_socket_alloc()
    assert 16 == sk.s_local.nl_family
    assert 0 < sk.s_local.nl_pid
    assert 0 == sk.s_local.nl_groups
    assert 16 == sk.s_peer.nl_family
    assert 0 == sk.s_peer.nl_pid
    assert 0 == sk.s_peer.nl_groups
    assert -1 == sk.s_fd
    assert 0 == sk.s_proto
    assert 0 == sk.s_flags
    assert 11 == sk.s_cb.cb_active
    assert sk.s_cb.cb_err is None
    nl_socket_free(sk)

    first_pid = int(sk.s_local.nl_pid)
    sk = nl_socket_alloc(nl_cb_alloc(NL_CB_VERBOSE))
    assert 16 == sk.s_local.nl_family
    assert first_pid == sk.s_local.nl_pid
    assert 0 == sk.s_local.nl_groups
    assert 16 == sk.s_peer.nl_family
    assert 0 == sk.s_peer.nl_pid
    assert 0 == sk.s_peer.nl_groups
    assert -1 == sk.s_fd
    assert 0 == sk.s_proto
    assert 0 == sk.s_flags
    assert 11 == sk.s_cb.cb_active
    assert sk.s_cb.cb_err is not None
    nl_socket_free(sk)


@pytest.mark.skipif('True')
def test_nl_socket_modify_cb():
    """// gcc $(pkg-config --cflags --libs libnl-genl-3.0) a.c && NLDBG=4 ./a.out
    #include <netlink/msg.h>
    static int callback(struct nl_msg *msg, void *arg) {
        printf("Got something.\n");
        nl_msg_dump(msg, stdout);
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
    :return:
    """
    pass
