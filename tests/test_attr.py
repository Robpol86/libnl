import base64
import ctypes
import socket
import string

import libnl.attr
from libnl.linux_private.netlink import NETLINK_ROUTE
from libnl.misc import msghdr
from libnl.msg import nlmsg_alloc, nlmsg_hdr, nlmsg_find_attr, nlmsg_for_each_attr, nlmsg_total_size
from libnl.msg_ import nlmsg_datalen
from libnl.nl import nl_sendmsg, nl_connect, nl_complete_msg
from libnl.socket_ import nl_socket_alloc, nl_socket_free


def test_nla_put_get_u32():
    """// gcc a.c $(pkg-config --cflags --libs libnl-genl-3.0) && ./a.out
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
    rem = ctypes.c_int()
    range_ = (0, 1, 2, 19, 20, 50)
    msg = nlmsg_alloc()
    nlh = nlmsg_hdr(msg)
    for i in range(len(range_)):
        libnl.attr.nla_put_u32(msg, i, range_[i])
    i = 0
    for nla in nlmsg_for_each_attr(nlh, 0, rem):
        assert i == libnl.attr.nla_type(nla)
        assert range_[i] == libnl.attr.nla_get_u32(nla)
        i += 1


def test_socket(tcp_server):
    """// gcc a.c $(pkg-config --cflags --libs libnl-genl-3.0) && (nc -l 2000 |base64 &) && sleep 0.1 && ./a.out
    #include <netlink/msg.h>
    struct nl_sock {
        struct sockaddr_nl s_local; struct sockaddr_nl s_peer; int s_fd; int s_proto; unsigned int s_seq_next;
        unsigned int s_seq_expect; int s_flags; struct nl_cb *s_cb; size_t s_bufsize;
    };
    int main() {
        struct nl_msg *msg = nlmsg_alloc();
        printf("%d == nla_put_u32()\n", nla_put_u32(msg, 4, 8));
        struct nlmsghdr *nlh = nlmsg_hdr(msg);
        struct nlattr *attr = nlmsg_find_attr(nlh, 0, 4);
        printf("%d == nla_type(attr)\n", nla_type(attr));
        printf("%d == nla_get_u32(attr)\n", nla_get_u32(attr));
        printf("%d == attr->nla_len\n", attr->nla_len);

        struct sockaddr_in sin = { .sin_port = htons(2000), .sin_family = AF_INET, };
        sin.sin_addr.s_addr = inet_addr("127.0.0.1");
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        connect(fd, (struct sockaddr *) &sin, sizeof(sin));

        struct nl_sock *sk = nl_socket_alloc();
        nl_connect(sk, NETLINK_ROUTE);
        sk->s_fd = fd;
        sk->s_local.nl_pid = 0;
        nl_complete_msg(sk, msg);

        struct iovec iov = { .iov_base = attr, .iov_len = attr->nla_len };
        struct msghdr hdr = { .msg_iov = &iov, .msg_iovlen = 1, };

        int ret = nl_sendmsg(sk, msg, &hdr);
        printf("Bytes: %d\n", ret);  // 14
        return 0;
    }
    // Expected bash output:
    // 0 == nla_put_u32()
    // 4 == nla_type(attr)
    // 8 == nla_get_u32(attr)
    // 8 == attr->nla_len
    // Bytes: 8
    // CAAEAAgAAAA=
    """
    msg = nlmsg_alloc()
    assert 0 == libnl.attr.nla_put_u32(msg, 4, 8)
    nlh = nlmsg_hdr(msg)
    attr = nlmsg_find_attr(nlh, 0, 4)
    assert 4 == libnl.attr.nla_type(attr)
    assert 8 == libnl.attr.nla_get_u32(attr)
    assert 8 == attr.nla_len

    sk = nl_socket_alloc()
    nl_connect(sk, NETLINK_ROUTE)
    sk.socket_instance.close()
    sk.socket_instance = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.socket_instance.connect(tcp_server.server.server_address)
    sk.s_local.nl_pid = 0
    nl_complete_msg(sk, msg)

    iov = bytes(attr)[:attr.nla_len]
    hdr = msghdr(msg_iov=iov)

    assert 8 == nl_sendmsg(sk, msg, hdr)
    assert 1 == len(tcp_server.data)
    assert b'CAAEAAgAAAA=' == base64.b64encode(iov)
    assert b'CAAEAAgAAAA=' == base64.b64encode(tcp_server.data[0])
    nl_socket_free(sk)


def test_ints():
    msg = nlmsg_alloc()
    assert 0 == libnl.attr.nla_put_u8(msg, 2, 10)
    assert 0 == libnl.attr.nla_put_u16(msg, 3, 11)
    assert 0 == libnl.attr.nla_put_u32(msg, 4, 12)
    assert 0 == libnl.attr.nla_put_u64(msg, 5, 13195)

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 0, 2)
    assert 2 == libnl.attr.nla_type(attr)
    assert 10 == libnl.attr.nla_get_u8(attr)
    assert 5 == attr.nla_len
    assert b'BQACAAo=' == base64.b64encode(bytes(attr)[:attr.nla_len])

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 0, 3)
    assert 3 == libnl.attr.nla_type(attr)
    assert 11 == libnl.attr.nla_get_u16(attr)
    assert 6 == attr.nla_len
    assert b'BgADAAsA' == base64.b64encode(bytes(attr)[:attr.nla_len])

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 0, 4)
    assert 4 == libnl.attr.nla_type(attr)
    assert 12 == libnl.attr.nla_get_u32(attr)
    assert 8 == attr.nla_len
    assert b'CAAEAAwAAAA=' == base64.b64encode(bytes(attr)[:attr.nla_len])

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 0, 5)
    assert 5 == libnl.attr.nla_type(attr)
    assert 13195 == libnl.attr.nla_get_u64(attr)  # printf("%llu\n", nla_get_u64(attr));
    assert 12 == attr.nla_len
    assert b'DAAFAIszAAAAAAAA' == base64.b64encode(bytes(attr)[:attr.nla_len])


def test_flag():
    msg = nlmsg_alloc()
    assert 0 == libnl.attr.nla_put_flag(msg, 7)

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 0, 7)
    assert 7 == libnl.attr.nla_type(attr)
    assert libnl.attr.nla_get_flag(attr) is True  # printf("%s\n", nla_get_flag(attr) ? "True" : "False");
    assert 4 == attr.nla_len
    assert b'BAAHAA==' == base64.b64encode(bytes(attr)[:attr.nla_len])


def test_msecs():
    msg = nlmsg_alloc()
    assert 0 == libnl.attr.nla_put_msecs(msg, 12, 99)

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 0, 12)
    assert 12 == libnl.attr.nla_type(attr)
    assert 99 == libnl.attr.nla_get_msecs(attr)
    assert 12 == attr.nla_len
    assert b'DAAMAGMAAAAAAAAA' == base64.b64encode(bytes(attr)[:attr.nla_len])


def test_string_short():
    payload = bytes('test'.encode('ascii'))
    msg = nlmsg_alloc()
    assert 0 == libnl.attr.nla_put_string(msg, 6, payload)

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 0, 6)
    assert 6 == libnl.attr.nla_type(attr)
    assert payload == libnl.attr.nla_get_string(attr)
    assert 9 == attr.nla_len
    assert b'CQAGAHRlc3QA' == base64.b64encode(bytes(attr)[:attr.nla_len])


def test_string_medium():
    payload = bytes('The quick br()wn f0x jumps over the l@zy dog!'.encode('ascii'))
    msg = nlmsg_alloc()
    assert 0 == libnl.attr.nla_put_string(msg, 6, payload)

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 0, 6)
    assert 6 == libnl.attr.nla_type(attr)
    assert payload == libnl.attr.nla_get_string(attr)
    assert 50 == attr.nla_len
    expected = b'MgAGAFRoZSBxdWljayBicigpd24gZjB4IGp1bXBzIG92ZXIgdGhlIGxAenkgZG9nIQA='
    assert expected == base64.b64encode(bytes(attr)[:attr.nla_len])


def test_string_long():
    payload = bytes(string.printable[:-2].encode('ascii'))
    msg = nlmsg_alloc()
    assert 0 == libnl.attr.nla_put_string(msg, 6, payload)

    attr = nlmsg_find_attr(nlmsg_hdr(msg), 0, 6)
    assert 6 == libnl.attr.nla_type(attr)
    assert payload == libnl.attr.nla_get_string(attr)
    assert 103 == attr.nla_len
    expected = (b'ZwAGADAxMjM0NTY3ODlhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ekFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaISIjJCUmJygp'
                b'KissLS4vOjs8PT4/QFtcXV5fYHt8fX4gCQoNAA==')
    assert expected == base64.b64encode(bytes(attr)[:attr.nla_len])


def test_nested():
    """// gcc a.c $(pkg-config --cflags --libs libnl-genl-3.0) && ./a.out
    #include <netlink/msg.h>
    int main() {
        int i, rem1, rem2;
        struct nlattr *nla;
        struct nl_msg *msg = nlmsg_alloc();
        struct nl_msg *sub = nlmsg_alloc();
        struct nlmsghdr *nlh = nlmsg_hdr(sub);
        unsigned char *buf = (unsigned char *) nlh;
        nla_put_string(sub, 0, "");
        nla_put_string(sub, 1, "Just tell me why!");
        nla_put_string(sub, 2, "Please read this 55-page warrant.");
        nla_put_string(sub, 3, "There must be robots worse than I!");
        nla_put_string(sub, 4, "We've checked around, there really aren't.");
        nlmsg_for_each_attr(nla, nlh, 0, rem1) {
            printf("type: %d len: %d; nla_get_string: %s\n", nla_type(nla), nla_len(nla), nla_get_string(nla));
        }
        for (i = 0; i < nlmsg_total_size(nlmsg_datalen(nlh)); i++) printf("%02x", buf[i]); printf("\n");
        nla_put_nested(msg, 5, sub);
        nlmsg_free(sub);

        sub = nlmsg_alloc();
        nlh = nlmsg_hdr(sub);
        buf = (unsigned char *) nlh;
        nla_put_string(sub, 6, "Aw, don't blame me,");
        nla_put_string(sub, 7, "Blame my upbringing!");
        nlmsg_for_each_attr(nla, nlh, 0, rem1) {
            printf("type: %d len: %d; nla_get_string: %s\n", nla_type(nla), nla_len(nla), nla_get_string(nla));
        }
        for (i = 0; i < nlmsg_total_size(nlmsg_datalen(nlh)); i++) printf("%02x", buf[i]); printf("\n");
        nla_put_nested(msg, 8, sub);
        nlmsg_free(sub);

        nlh = nlmsg_hdr(msg);
        buf = (unsigned char *) nlh;
        nla_put_u16(msg, 9, 666);
        for (i = 0; i < nlmsg_total_size(nlmsg_datalen(nlh)); i++) printf("%02x", buf[i]); printf("\n");

        struct nlattr *nla_outer;
        nlmsg_for_each_attr(nla_outer, nlh, 0, rem1) {
            if (nla_type(nla_outer) != 9) {
                printf("Outer type: %d len:%d\n", nla_type(nla_outer), nla_len(nla_outer));
                nla_for_each_nested(nla, nla_outer, rem2) {
                    printf("type: %d len: %d; nla_get_string: %s\n", nla_type(nla), nla_len(nla), nla_get_string(nla));
                }
            } else {
                printf("t: %d l:%d; get_u16: %d\n", nla_type(nla_outer), nla_len(nla_outer), nla_get_u16(nla_outer));
            }
        }

        nlmsg_free(msg);
        return 0;
    }
    // Expected output:
    // type: 0 len: 1; nla_get_string:
    // type: 1 len: 18; nla_get_string: Just tell me why!
    // type: 2 len: 34; nla_get_string: Please read this 55-page warrant.
    // type: 3 len: 35; nla_get_string: There must be robots worse than I!
    // type: 4 len: 43; nla_get_string: We've checked around, there really aren't.
    // b00000000000000000000000000000000500000000000000160001004a7573742074656c6c206d65207768792100000026000200506c65617
    365207265616420746869732035352d706167652077617272616e742e000000270003005468657265206d75737420626520726f626f747320776
    f727365207468616e20492100002f000400576527766520636865636b65642061726f756e642c207468657265207265616c6c79206172656e277
    42e0000
    // type: 6 len: 20; nla_get_string: Aw, don't blame me,
    // type: 7 len: 21; nla_get_string: Blame my upbringing!
    // 440000000000000000000000000000001800060041772c20646f6e277420626c616d65206d652c0019000700426c616d65206d79207570627
    2696e67696e672100000000
    // f4000000000000000000000000000000a40005000500000000000000160001004a7573742074656c6c206d652077687921000000260002005
    06c65617365207265616420746869732035352d706167652077617272616e742e000000270003005468657265206d75737420626520726f626f7
    47320776f727365207468616e20492100002f000400576527766520636865636b65642061726f756e642c207468657265207265616c6c7920617
    2656e27742e0000380008001800060041772c20646f6e277420626c616d65206d652c0019000700426c616d65206d792075706272696e67696e6
    72100000000060009009a020000
    // Outer type: 5 len:160
    // type: 0 len: 1; nla_get_string:
    // type: 1 len: 18; nla_get_string: Just tell me why!
    // type: 2 len: 34; nla_get_string: Please read this 55-page warrant.
    // type: 3 len: 35; nla_get_string: There must be robots worse than I!
    // type: 4 len: 43; nla_get_string: We've checked around, there really aren't.
    // Outer type: 8 len:52
    // type: 6 len: 20; nla_get_string: Aw, don't blame me,
    // type: 7 len: 21; nla_get_string: Blame my upbringing!
    // t: 9 l:2; get_u16: 666
    """
    rem1, rem2 = ctypes.c_int(), ctypes.c_int()
    msg = nlmsg_alloc()
    sub = nlmsg_alloc()
    nlh = nlmsg_hdr(sub)
    libnl.attr.nla_put_string(sub, 0, b'')
    libnl.attr.nla_put_string(sub, 1, b'Just tell me why!')
    libnl.attr.nla_put_string(sub, 2, b'Please read this 55-page warrant.')
    libnl.attr.nla_put_string(sub, 3, b'There must be robots worse than I!')
    libnl.attr.nla_put_string(sub, 4, b"We've checked around, there really aren't.")
    actual = list()
    for nla in nlmsg_for_each_attr(nlh, 0, rem1):
        actual.append((libnl.attr.nla_type(nla), libnl.attr.nla_len(nla), libnl.attr.nla_get_string(nla)))
    expected = [
        (0, 1, b''),
        (1, 18, b'Just tell me why!'),
        (2, 34, b'Please read this 55-page warrant.'),
        (3, 35, b'There must be robots worse than I!'),
        (4, 43, b"We've checked around, there really aren't."),
    ]
    assert expected == actual
    expected = ('b00000000000000000000000000000000500000000000000160001004a7573742074656c6c206d652077687921000000260002'
                '00506c65617365207265616420746869732035352d706167652077617272616e742e000000270003005468657265206d757374'
                '20626520726f626f747320776f727365207468616e20492100002f000400576527766520636865636b65642061726f756e642c'
                '207468657265207265616c6c79206172656e27742e0000')
    assert expected == ''.join(format(c, '02x') for c in nlh.bytearray[:nlmsg_total_size(nlmsg_datalen(nlh))])
    libnl.attr.nla_put_nested(msg, 5, sub)

    sub = nlmsg_alloc()
    nlh = nlmsg_hdr(sub)
    libnl.attr.nla_put_string(sub, 6, b"Aw, don't blame me,")
    libnl.attr.nla_put_string(sub, 7, b'Blame my upbringing!')
    actual = list()
    for nla in nlmsg_for_each_attr(nlh, 0, rem1):
        actual.append((libnl.attr.nla_type(nla), libnl.attr.nla_len(nla), libnl.attr.nla_get_string(nla)))
    expected = [
        (6, 20, b"Aw, don't blame me,"),
        (7, 21, b'Blame my upbringing!'),
    ]
    assert expected == actual
    expected = ('440000000000000000000000000000001800060041772c20646f6e277420626c616d65206d652c0019000700426c616d65206d'
                '792075706272696e67696e672100000000')
    assert expected == ''.join(format(c, '02x') for c in nlh.bytearray[:nlmsg_total_size(nlmsg_datalen(nlh))])
    libnl.attr.nla_put_nested(msg, 8, sub)

    nlh = nlmsg_hdr(msg)
    libnl.attr.nla_put_u16(msg, 9, 666)
    expected = ('f4000000000000000000000000000000a40005000500000000000000160001004a7573742074656c6c206d6520776879210000'
                '0026000200506c65617365207265616420746869732035352d706167652077617272616e742e00000027000300546865726520'
                '6d75737420626520726f626f747320776f727365207468616e20492100002f000400576527766520636865636b65642061726f'
                '756e642c207468657265207265616c6c79206172656e27742e0000380008001800060041772c20646f6e277420626c616d6520'
                '6d652c0019000700426c616d65206d792075706272696e67696e672100000000060009009a020000')
    assert expected == ''.join(format(c, '02x') for c in nlh.bytearray[:nlmsg_total_size(nlmsg_datalen(nlh))])

    actual = list()
    for nla_outer in nlmsg_for_each_attr(nlh, 0, rem1):
        if libnl.attr.nla_type(nla_outer) != 9:
            actual.append((libnl.attr.nla_type(nla_outer), libnl.attr.nla_len(nla_outer), b'Outer'))
            for nla in libnl.attr.nla_for_each_nested(nla_outer, rem2):
                actual.append((libnl.attr.nla_type(nla), libnl.attr.nla_len(nla), libnl.attr.nla_get_string(nla)))
        else:
            actual.append(
                (libnl.attr.nla_type(nla_outer), libnl.attr.nla_len(nla_outer), libnl.attr.nla_get_u16(nla_outer))
            )
    expected = [
        (5, 160, b'Outer'),
        (0, 1, b''),
        (1, 18, b'Just tell me why!'),
        (2, 34, b'Please read this 55-page warrant.'),
        (3, 35, b'There must be robots worse than I!'),
        (4, 43, b"We've checked around, there really aren't."),
        (8, 52, b'Outer'),
        (6, 20, b"Aw, don't blame me,"),
        (7, 21, b'Blame my upbringing!'),
        (9, 2, 666),
    ]
    assert expected == actual
