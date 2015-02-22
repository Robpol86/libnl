from libnl.cache_mngt import nl_cache_ops_associate_safe, nl_msgtype_lookup
from libnl.genl.family import genl_family_alloc, genl_family_set_name
from libnl.genl.genl import genlmsg_put
from libnl.handlers import nl_cb_overwrite_send, NL_STOP
from libnl.linux_private.genetlink import GENL_ID_CTRL, CTRL_CMD_GETFAMILY
from libnl.linux_private.netlink import NETLINK_GENERIC
from libnl.msg import nlmsg_hdr, nlmsg_alloc, NL_AUTO_PORT, NL_AUTO_SEQ, nlmsg_attrlen
from libnl.nl import nl_send_auto
from libnl.socket_ import nl_socket_alloc


def test_nl_cache_ops_associate_safe():
    """// gcc $(pkg-config --cflags --libs libnl-genl-3.0) a.c && ./a.out
    #include <netlink/genl/family.h>
    struct nl_sock {
        struct sockaddr_nl s_local; struct sockaddr_nl s_peer; int s_fd; int s_proto; unsigned int s_seq_next;
        unsigned int s_seq_expect; int s_flags; struct nl_cb *s_cb; size_t s_bufsize;
    };
    struct nl_cache_ops {
        char *co_name; int co_hdrsize; int co_protocol; int co_hash_size; unsigned int co_flags; unsigned int co_refcnt;
        struct nl_af_group *co_groups; int (*co_request_update)(struct nl_cache*, struct nl_sock*);
        int (*co_msg_parser)(struct nl_cache_ops*, struct sockaddr_nl*, struct nlmsghdr*, struct nl_parser_param*);
        int (*co_event_filter)(struct nl_cache*, struct nl_object *obj);
        int (*co_include_event)(struct nl_cache *cache, struct nl_object *obj, change_func_t change_cb, void *data);
        void (*reserved_1)(void); void (*reserved_2)(void); void (*reserved_3)(void); void (*reserved_4)(void);
        void (*reserved_5)(void); void (*reserved_6)(void); void (*reserved_7)(void); void (*reserved_8)(void);
        struct nl_object_ops *co_obj_ops;
    };
    struct nl_object_ops { char *oo_name; size_t oo_size; uint32_t oo_id_attrs; };
    struct nl_msgtype { int mt_id; int mt_act; char *mt_name; };
    static int callback(struct nl_sock *sk, struct nl_msg *msg) {
        struct nlmsghdr *nlh = nlmsg_hdr(msg);
        printf("%d == nlh.nlmsg_len\n", nlh->nlmsg_len);
        printf("%d == nlh.nlmsg_type\n", nlh->nlmsg_type);
        printf("%d == nlh.nlmsg_flags\n", nlh->nlmsg_flags);
        struct nl_cache_ops *ops = nl_cache_ops_associate_safe(NETLINK_GENERIC, nlh->nlmsg_type);
        printf("'%s' == ops.co_name\n", ops->co_name);
        printf("%d == ops.co_hdrsize\n", ops->co_hdrsize);
        printf("%d == ops.co_protocol\n", ops->co_protocol);
        printf("%d == ops.co_hash_size\n", ops->co_hash_size);
        printf("%d == ops.co_flags\n", ops->co_flags);
        printf("'%s' == ops.co_obj_ops.oo_name\n", ops->co_obj_ops->oo_name);
        printf("%d == ops.co_obj_ops.oo_size\n", ops->co_obj_ops->oo_size);
        printf("%d == ops.co_obj_ops.oo_id_attrs\n", ops->co_obj_ops->oo_id_attrs);
        printf("%d == nlmsg_attrlen(nlh, ops.co_hdrsize)\n", nlmsg_attrlen(nlh, ops->co_hdrsize));
        struct nl_msgtype *mt = nl_msgtype_lookup(ops, nlh->nlmsg_type);
        printf("%d == mt.mt_id\n", mt->mt_id);
        printf("%d == mt.mt_act\n", mt->mt_act);
        printf("'%s' == mt.mt_name\n", mt->mt_name);
        return NL_STOP;
    }
    int main() {
        struct nl_sock *sk = nl_socket_alloc();
        nl_cb_overwrite_send(sk->s_cb, callback);

        struct genl_family *ret = genl_family_alloc();
        genl_family_set_name(ret, "nl80211");
        struct nl_msg *msg = nlmsg_alloc();
        genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, GENL_ID_CTRL, 0, 0, CTRL_CMD_GETFAMILY, 1);
        printf("%d == nl_send_auto(sk, msg)\n", nl_send_auto(sk, msg));
        return 0;
    }
    // Expected output:
    // 20 == nlh.nlmsg_len
    // 16 == nlh.nlmsg_type
    // 5 == nlh.nlmsg_flags
    // 'genl/family' == ops.co_name
    // 4 == ops.co_hdrsize
    // 16 == ops.co_protocol
    // 0 == ops.co_hash_size
    // 0 == ops.co_flags
    // 'genl/family' == ops.co_obj_ops.oo_name
    // 80 == ops.co_obj_ops.oo_size
    // 1 == ops.co_obj_ops.oo_id_attrs
    // 0 == nlmsg_attrlen(nlh, ops.co_hdrsize)
    // 16 == mt.mt_id
    // 0 == mt.mt_act
    // 'nlctrl' == mt.mt_name
    // 2 == nl_send_auto(sk, msg)
    """
    called = list()

    def callback(_, msg_):
        nlh = nlmsg_hdr(msg_)
        assert 20 == nlh.nlmsg_len
        assert 16 == nlh.nlmsg_type
        assert 5 == nlh.nlmsg_flags
        ops = nl_cache_ops_associate_safe(NETLINK_GENERIC, nlh.nlmsg_type)
        assert 'genl/family' == ops.co_name
        assert 4 == ops.co_hdrsize
        assert 16 == ops.co_protocol
        assert 0 == ops.co_hash_size
        assert 0 == ops.co_flags
        assert 'genl/family' == ops.co_obj_ops.oo_name
        assert 80 == ops.co_obj_ops.oo_size
        assert 1 == ops.co_obj_ops.oo_id_attrs
        assert 0 == nlmsg_attrlen(nlh, ops.co_hdrsize)
        mt = nl_msgtype_lookup(ops, nlh.nlmsg_type)
        assert 16 == mt.mt_id
        assert 0 == mt.mt_act
        assert 'nlctrl' == mt.mt_name
        called.append(True)
        return NL_STOP

    sk = nl_socket_alloc()
    nl_cb_overwrite_send(sk.s_cb, callback)
    ret = genl_family_alloc()
    genl_family_set_name(ret, 'nl80211')
    msg = nlmsg_alloc()
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, GENL_ID_CTRL, 0, 0, CTRL_CMD_GETFAMILY, 1)
    assert 2 == nl_send_auto(sk, msg)
    assert [True] == called
