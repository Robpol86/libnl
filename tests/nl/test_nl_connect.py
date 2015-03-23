import os

from libnl.linux_private.netlink import NETLINK_GENERIC, NETLINK_ROUTE
from libnl.nl import nl_connect
from libnl.socket_ import nl_socket_alloc, nl_socket_free


def test_nl_connect():
    """// gcc a.c $(pkg-config --cflags --libs libnl-genl-3.0) && ./a.out
    #include <netlink/msg.h>
    #include <dirent.h>
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
    void print_fd_count() {
        int fd_count = 0; char buf[64]; struct dirent *dp;
        snprintf(buf, 256, "/proc/self/fd/");
        DIR *dir = opendir(buf); while ((dp = readdir(dir)) != NULL) fd_count++; closedir(dir);
        printf("fd_count: %d\n", fd_count);
    }
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
        print_fd_count();
        print(sk);
        printf("\n");

        printf("nl_connect(): %d\n", nl_connect(sk, NETLINK_ROUTE));
        print_fd_count();
        print(sk);
        nl_socket_free(sk);
        print_fd_count();
        print(sk);
        printf("\n");

        sk = nl_socket_alloc();
        printf("nl_connect(): %d\n", nl_connect(sk, NETLINK_GENERIC));
        print_fd_count();
        print(sk);
        nl_socket_free(sk);
        print_fd_count();
        printf("\n");
        return 0;
    }
    // Expected output:
    // fd_count: 6
    // sk.s_local.nl_family = 16
    // sk.s_local.nl_pid = 3121  # changes every process, remains same throughout proc.
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
    // nl_connect(): 0
    // fd_count: 7
    // sk.s_local.nl_family = 16
    // sk.s_local.nl_pid = 3121  # changes every process, remains same throughout proc.
    // sk.s_local.nl_groups = 0
    // sk.s_peer.nl_family = 16
    // sk.s_peer.nl_pid = 0
    // sk.s_peer.nl_groups = 0
    // sk.s_fd = 3
    // sk.s_proto = 0
    // sk.s_flags = 1
    // sk.s_cb.cb_active = 11
    // addr: sk.s_cb.cb_err = (nil)
    // fd_count: 6
    // sk.s_local.nl_family = 16
    // sk.s_local.nl_pid = 167775232  # changes every process, remains same throughout proc.
    // sk.s_local.nl_groups = 0
    // sk.s_peer.nl_family = 16
    // sk.s_peer.nl_pid = 0
    // sk.s_peer.nl_groups = 0
    // sk.s_fd = 3
    // sk.s_proto = 0
    // sk.s_flags = 1
    // sk.s_cb.cb_active = 18774
    // addr: sk.s_cb.cb_err = 0x310a0010
    //
    // nl_connect(): 0
    // fd_count: 7
    // sk.s_local.nl_family = 16
    // sk.s_local.nl_pid = 3121  # changes every process, remains same throughout proc.
    // sk.s_local.nl_groups = 0
    // sk.s_peer.nl_family = 16
    // sk.s_peer.nl_pid = 0
    // sk.s_peer.nl_groups = 0
    // sk.s_fd = 3
    // sk.s_proto = 16
    // sk.s_flags = 1
    // sk.s_cb.cb_active = 11
    // addr: sk.s_cb.cb_err = (nil)
    // fd_count: 6
    """
    initial_fd_count = len(os.listdir('/proc/self/fd'))
    assert 2 <= initial_fd_count

    # Allocate but don't connect/bind.
    sk = nl_socket_alloc()
    assert initial_fd_count == len(os.listdir('/proc/self/fd'))
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
    persistent_pid = int(sk.s_local.nl_pid)

    # Connect, then close the socket at the end.
    assert 0 == nl_connect(sk, NETLINK_ROUTE)
    assert initial_fd_count + 1 == len(os.listdir('/proc/self/fd'))
    assert 16 == sk.s_local.nl_family
    assert persistent_pid == sk.s_local.nl_pid
    assert 0 == sk.s_local.nl_groups
    assert 16 == sk.s_peer.nl_family
    assert 0 == sk.s_peer.nl_pid
    assert 0 == sk.s_peer.nl_groups
    assert 0 < sk.s_fd
    assert 0 == sk.s_proto
    assert 1 == sk.s_flags
    assert 11 == sk.s_cb.cb_active
    assert sk.s_cb.cb_err is None
    persistent_fd = int(sk.s_fd)
    nl_socket_free(sk)
    assert initial_fd_count == len(os.listdir('/proc/self/fd'))
    assert 16 == sk.s_local.nl_family
    # assert persistent_pid == sk.s_local.nl_pid  # In C, pointer points to deallocated memory. In Python, leave alone.
    assert 0 == sk.s_local.nl_groups
    assert 16 == sk.s_peer.nl_family
    assert 0 == sk.s_peer.nl_pid
    assert 0 == sk.s_peer.nl_groups
    # assert persistent_fd == sk.s_fd  # In C, s_fd is a regular int. In Python, it's a class property.
    assert 0 == sk.s_proto
    assert 1 == sk.s_flags
    # assert 11 == sk.s_cb.cb_active  # In C, pointer points to deallocated memory. In Python, leave alone.
    # assert sk.s_cb.cb_err is None  # In C, pointer points to deallocated memory. In Python, leave alone.

    # Re-allocate and connect again, pid should be the same as the previous session.
    sk = nl_socket_alloc()
    assert 0 == nl_connect(sk, NETLINK_GENERIC)
    assert initial_fd_count + 1 == len(os.listdir('/proc/self/fd'))
    assert 16 == sk.s_local.nl_family
    assert persistent_pid == sk.s_local.nl_pid
    assert 0 == sk.s_local.nl_groups
    assert 16 == sk.s_peer.nl_family
    assert 0 == sk.s_peer.nl_pid
    assert 0 == sk.s_peer.nl_groups
    assert persistent_fd == sk.s_fd
    assert 16 == sk.s_proto
    assert 1 == sk.s_flags
    assert 11 == sk.s_cb.cb_active
    assert sk.s_cb.cb_err is None
    nl_socket_free(sk)
    assert initial_fd_count == len(os.listdir('/proc/self/fd'))
