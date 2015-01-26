from libnl.handlers import nl_cb_alloc, NL_CB_VERBOSE
from libnl.socket_ import nl_socket_alloc


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
    assert sk.s_local.nl_family == 16
    assert sk.s_local.nl_pid == 0  # Python's socket.socket() handles selecting a port ID.  # TODO test in nl_connect().
    assert sk.s_local.nl_groups == 0
    assert sk.s_peer.nl_family == 16
    assert sk.s_peer.nl_pid == 0
    assert sk.s_peer.nl_groups == 0
    assert sk.s_fd == -1
    assert sk.s_proto == 0
    #assert sk.s_flags == 0  # TODO when (c)libnl gets pid, sets this from 4 to 0. (py)libnl doesn't get pid.   ^^^
    assert sk.s_cb.cb_active == 11
    assert sk.s_cb.cb_err is None

    first_pid = int(sk.s_local.nl_pid)
    sk = nl_socket_alloc(nl_cb_alloc(NL_CB_VERBOSE))
    assert sk.s_local.nl_family == 16
    assert sk.s_local.nl_pid == first_pid
    assert sk.s_local.nl_groups == 0
    assert sk.s_peer.nl_family == 16
    assert sk.s_peer.nl_pid == 0
    assert sk.s_peer.nl_groups == 0
    assert sk.s_fd == -1
    assert sk.s_proto == 0
    #assert sk.s_flags == 0  # TODO
    assert sk.s_cb.cb_active == 11
    assert sk.s_cb.cb_err is not None
