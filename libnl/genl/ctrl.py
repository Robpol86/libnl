"""Generic Netlink Controller (lib/genl/ctrl.c).

https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/genl.c

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from libnl.attr import (nla_for_each_nested, nla_get_string, nla_get_u16, nla_get_u32, NLA_NESTED, nla_parse_nested,
                        nla_policy, nla_put_string, NLA_STRING, NLA_U16, NLA_U32)
from libnl.cache import NL_ACT_UNSPEC
from libnl.errno_ import NLE_MISSING_ATTR, NLE_OBJ_NOTFOUND
from libnl.genl.family import (genl_family_add_grp, genl_family_alloc, genl_family_get_id, genl_family_ops,
                               genl_family_set_id, genl_family_set_name)
from libnl.genl.genl import genl_send_simple, genlmsg_parse, genlmsg_put
from libnl.genl.mngt import genl_cmd, genl_ops, genl_register
from libnl.handlers import nl_cb_clone, NL_CB_CUSTOM, nl_cb_set, NL_CB_VALID, NL_SKIP, NL_STOP
from libnl.linux_private.genetlink import (CTRL_ATTR_FAMILY_ID, CTRL_ATTR_FAMILY_NAME, CTRL_ATTR_HDRSIZE, CTRL_ATTR_MAX,
                                           CTRL_ATTR_MAXATTR, CTRL_ATTR_MCAST_GROUPS, CTRL_ATTR_MCAST_GRP_ID,
                                           CTRL_ATTR_MCAST_GRP_MAX, CTRL_ATTR_MCAST_GRP_NAME, CTRL_ATTR_OP_FLAGS,
                                           CTRL_ATTR_OP_ID, CTRL_ATTR_OP_MAX, CTRL_ATTR_OPS, CTRL_ATTR_VERSION,
                                           CTRL_CMD_DELFAMILY, CTRL_CMD_DELOPS, CTRL_CMD_GETFAMILY, CTRL_CMD_NEWFAMILY,
                                           CTRL_CMD_NEWOPS, GENL_HDRSIZE, GENL_ID_CTRL, GENL_NAMSIZ)
from libnl.linux_private.netlink import NETLINK_GENERIC, NLM_F_DUMP
from libnl.list_ import nl_list_for_each_entry
from libnl.misc import __init, c_int
from libnl.msg import NL_AUTO_PORT, NL_AUTO_SEQ, nlmsg_alloc, nlmsg_hdr
from libnl.netlink_private.cache_api import nl_cache_ops, nl_msgtype
from libnl.netlink_private.netlink import BUG
from libnl.netlink_private.types import genl_family_grp
from libnl.nl import nl_recvmsgs, nl_send_auto, wait_for_ack
from libnl.socket_ import nl_socket_get_cb

CTRL_VERSION = 0x0001


ctrl_policy = dict((i, None) for i in range(CTRL_ATTR_MAX + 1))
ctrl_policy.update({  # https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/ctrl.c#L43
    CTRL_ATTR_FAMILY_ID: nla_policy(type_=NLA_U16),
    CTRL_ATTR_FAMILY_NAME: nla_policy(type_=NLA_STRING, maxlen=GENL_NAMSIZ),
    CTRL_ATTR_VERSION: nla_policy(type_=NLA_U32),
    CTRL_ATTR_HDRSIZE: nla_policy(type_=NLA_U32),
    CTRL_ATTR_MAXATTR: nla_policy(type_=NLA_U32),
    CTRL_ATTR_OPS: nla_policy(type_=NLA_NESTED),
    CTRL_ATTR_MCAST_GROUPS: nla_policy(type_=NLA_NESTED),
})


family_op_policy = dict((i, None) for i in range(CTRL_ATTR_OP_MAX + 1))
family_op_policy.update({  # https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/ctrl.c#L54
    CTRL_ATTR_OP_ID: nla_policy(type_=NLA_U32),
    CTRL_ATTR_OP_FLAGS: nla_policy(type_=NLA_U32),
})


family_grp_policy = dict((i, None) for i in range(CTRL_ATTR_MCAST_GRP_MAX + 1))
family_grp_policy.update({  # https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/ctrl.c#L59
    CTRL_ATTR_MCAST_GRP_NAME: nla_policy(type_=NLA_STRING),
    CTRL_ATTR_MCAST_GRP_ID: nla_policy(type_=NLA_U32),
})


def ctrl_request_update(_, nl_sock_h):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/ctrl.c#L37.

    Positional arguments:
    nl_sock_h -- nl_sock class instance.

    Returns:
    Integer, genl_send_simple() output.
    """
    return int(genl_send_simple(nl_sock_h, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, CTRL_VERSION, NLM_F_DUMP))


def parse_mcast_grps(family, grp_attr):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/ctrl.c#L64.

    Positional arguments:
    family -- genl_family class instance.
    grp_attr -- nlattr class instance.

    Returns:
    0 on success or a negative error code.
    """
    remaining = c_int()
    if not grp_attr:
        raise BUG

    for nla in nla_for_each_nested(grp_attr, remaining):
        tb = dict()
        err = nla_parse_nested(tb, CTRL_ATTR_MCAST_GRP_MAX, nla, family_grp_policy)
        if err < 0:
            return err
        if not tb[CTRL_ATTR_MCAST_GRP_ID] or not tb[CTRL_ATTR_MCAST_GRP_NAME]:
            return -NLE_MISSING_ATTR

        id_ = nla_get_u32(tb[CTRL_ATTR_MCAST_GRP_ID])
        name = nla_get_string(tb[CTRL_ATTR_MCAST_GRP_NAME])

        err = genl_family_add_grp(family, id_, name)
        if err < 0:
            return err

    return 0


def ctrl_msg_parser(ops, cmd, info, arg):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/ctrl.c#L105.

    Positional arguments:
    ops -- nl_cache_ops class instance.
    cmd -- genl_cmd class instance.
    info -- genl_info class instance.
    arg -- nl_parser_param class instance, whose pp_cb attribute is called and passed itself.

    0 on success or a negative error code.
    """
    raise NotImplementedError


def probe_response(msg, arg):
    """Process responses from from the query sent by genl_ctrl_probe_by_name().

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/ctrl.c#L203

    Process returned messages, filling out the missing information in the genl_family structure.

    Positional arguments:
    msg -- returned message (nl_msg class instance).
    arg -- genl_family class instance to fill out.

    Returns:
    Indicator to keep processing frames or not (NL_SKIP or NL_STOP).
    """
    tb = dict((i, None) for i in range(CTRL_ATTR_MAX + 1))
    nlh = nlmsg_hdr(msg)
    ret = arg
    if genlmsg_parse(nlh, 0, tb, CTRL_ATTR_MAX, ctrl_policy):
        return NL_SKIP
    if tb[CTRL_ATTR_FAMILY_ID]:
        genl_family_set_id(ret, nla_get_u16(tb[CTRL_ATTR_FAMILY_ID]))
    if tb[CTRL_ATTR_MCAST_GROUPS] and parse_mcast_grps(ret, tb[CTRL_ATTR_MCAST_GROUPS]) < 0:
        return NL_SKIP
    return NL_STOP


def genl_ctrl_probe_by_name(sk, name):
    """Look up generic Netlink family by family name querying the kernel directly.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/ctrl.c#L237

    Directly query's the kernel for a given family name.

    Note: This API call differs from genl_ctrl_search_by_name in that it queries the kernel directly, allowing for
    module autoload to take place to resolve the family request. Using an nl_cache prevents that operation.

    Positional arguments:
    sk -- Generic Netlink socket (nl_sock class instance).
    name -- family name (bytes).

    Returns:
    Generic Netlink family `genl_family` class instance or None if no match was found.
    """
    ret = genl_family_alloc()
    if not ret:
        return None

    genl_family_set_name(ret, name)
    msg = nlmsg_alloc()
    orig = nl_socket_get_cb(sk)
    cb = nl_cb_clone(orig)
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, GENL_ID_CTRL, 0, 0, CTRL_CMD_GETFAMILY, 1)
    nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, name)
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, probe_response, ret)

    if nl_send_auto(sk, msg) < 0:
        return None
    if nl_recvmsgs(sk, cb) < 0:
        return None
    if wait_for_ack(sk) < 0:  # If search was successful, request may be ACKed after data.
        return None

    if genl_family_get_id(ret) != 0:
        return ret


def genl_ctrl_resolve(sk, name):
    """Resolve Generic Netlink family name to numeric identifier.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/ctrl.c#L429

    Resolves the Generic Netlink family name to the corresponding numeric family identifier. This function queries the
    kernel directly, use genl_ctrl_search_by_name() if you need to resolve multiple names.

    Positional arguments:
    sk -- Generic Netlink socket (nl_sock class instance).
    name -- name of Generic Netlink family (bytes).

    Returns:
    The numeric family identifier or a negative error code.
    """
    family = genl_ctrl_probe_by_name(sk, name)
    if family is None:
        return -NLE_OBJ_NOTFOUND

    return int(genl_family_get_id(family))


def genl_ctrl_grp_by_name(family, grp_name):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/ctrl.c#L446.

    Positional arguments:
    family -- genl_family class instance.
    grp_name -- bytes.

    Returns:
    group ID or negative error code.
    """
    for grp in nl_list_for_each_entry(genl_family_grp(), family.gf_mc_grps, 'list_'):
        if grp.name == grp_name:
            return grp.id_
    return -NLE_OBJ_NOTFOUND


def genl_ctrl_resolve_grp(sk, family_name, grp_name):
    """Resolve Generic Netlink family group name.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/ctrl.c#L471

    Looks up the family object and resolves the group name to the numeric group identifier.

    Positional arguments:
    sk -- Generic Netlink socket (nl_sock class instance).
    family_name -- name of Generic Netlink family (bytes).
    grp_name -- name of group to resolve (bytes).

    Returns:
    The numeric group identifier or a negative error code.
    """
    family = genl_ctrl_probe_by_name(sk, family_name)
    if family is None:
        return -NLE_OBJ_NOTFOUND
    return genl_ctrl_grp_by_name(family, grp_name)


genl_cmds = (  # https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/ctrl.c#L493
    genl_cmd(c_id=CTRL_CMD_NEWFAMILY, c_name='NEWFAMILY', c_maxattr=CTRL_ATTR_MAX, c_attr_policy=ctrl_policy,
             c_msg_parser=ctrl_msg_parser),
    genl_cmd(c_id=CTRL_CMD_DELFAMILY, c_name='DELFAMILY'),
    genl_cmd(c_id=CTRL_CMD_GETFAMILY, c_name='GETFAMILY'),
    genl_cmd(c_id=CTRL_CMD_NEWOPS, c_name='NEWOPS'),
    genl_cmd(c_id=CTRL_CMD_DELOPS, c_name='DELOPS'),
)


genl_ctrl_ops = nl_cache_ops(  # https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/ctrl.c#L526
    co_name='genl/family',
    co_hdrsize=GENL_HDRSIZE(0),
    co_msgtypes=(nl_msgtype(GENL_ID_CTRL, NL_ACT_UNSPEC, 'nlctrl'), nl_msgtype(-1, -1, None)),
    co_genl=genl_ops(o_cmds=genl_cmds, o_ncmds=len(genl_cmds)),
    co_protocol=NETLINK_GENERIC,
    co_request_update=ctrl_request_update,
    co_obj_ops=genl_family_ops,
)


@__init
def ctrl_init():
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/ctrl.c#L536."""
    genl_register(genl_ctrl_ops)
