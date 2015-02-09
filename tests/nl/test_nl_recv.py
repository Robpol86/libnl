import pytest


@pytest.mark.skipif('True')
def test():
    """// gcc $(pkg-config --cflags --libs libnl-genl-3.0) a.c && (nc -l 2000 |base64 &) && sleep 0.1 && ./a.out
    #include <netlink/msg.h>
    struct nl_sock {
        struct sockaddr_nl s_local; struct sockaddr_nl s_peer; int s_fd; int s_proto; unsigned int s_seq_next;
        unsigned int s_seq_expect; int s_flags; struct nl_cb *s_cb; size_t s_bufsize;
    };
    int main() {
        struct nl_sock *sk = nl_socket_alloc();
        nl_connect(sk, NETLINK_ROUTE);
        int ret = nl_send_simple(sk, 0, NLM_F_ECHO, "PleaseReply", sizeof("PleaseReply"));
        printf("Bytes Sent: %d\n", ret);

        unsigned char *buf = NULL;
        struct sockaddr_nl nla = {0};
        int n = nl_recv(sk, &nla, &buf, NULL);
        printf("Bytes Recv: %d\n", n);

        struct sockaddr_in sin = { .sin_port = htons(2000), .sin_family = AF_INET, };
        sin.sin_addr.s_addr = inet_addr("127.0.0.1");
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        connect(fd, (struct sockaddr *) &sin, sizeof(sin));

        struct nl_msg *msg = nlmsg_alloc_simple(0, 0);
        sk->s_fd = fd;
        sk->s_local.nl_pid = 0;
        nl_complete_msg(sk, msg);

        struct iovec iov = { .iov_base = buf, .iov_len = n, };
        struct msghdr hdr = { .msg_iov = &iov, .msg_iovlen = 1, };

        ret = nl_sendmsg(sk, msg, &hdr);
        printf("Bytes: %d\n", ret);
        return 0;
    }
    // Expected bash output:
    // Bytes Sent: 28
    // Bytes Recv: 36
    // Bytes: 36
    // JAAAAAIAAABrIdhU2CkAAAAAAAAcAAAAAAANAGsh2FTYKQAA
    """
    pass
