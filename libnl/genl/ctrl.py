"""Generic Netlink Controller (lib/genl/ctrl.c).
https://github.com/thom311/libnl/blob/master/lib/genl/ctrl.c

Resolves Generic Netlink family names to numeric identifiers.

The controller is a component in the kernel that resolves Generic Netlink family names to their numeric identifiers.
This module provides functions to query the controller to access the resolving functionality.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from ctypes import cast, POINTER

from libnl.attr import NLA_U16, NLA_STRING, NLA_U32, NLA_NESTED
from libnl.errno_ import NLE_OBJ_NOTFOUND
from libnl.genl.family import genl_family_alloc
from libnl.genl.genl import genlmsg_parse
from libnl.handlers import NL_CB_CUSTOM, NL_CB_VALID, NL_SKIP, NL_STOP
from libnl.linux_private.genetlink import (
    CTRL_ATTR_FAMILY_NAME, CTRL_ATTR_FAMILY_ID, CTRL_ATTR_MAX, CTRL_ATTR_MCAST_GROUPS, CTRL_CMD_GETFAMILY, GENL_ID_CTRL,
    GENL_NAMSIZ, CTRL_ATTR_VERSION, CTRL_ATTR_HDRSIZE, CTRL_ATTR_MAXATTR, CTRL_ATTR_OPS
)
from libnl.linux_private.netlink import nlattr
from libnl.misc import define_struct
from libnl.msg import NL_AUTO_PORT, NL_AUTO_SEQ, nlmsg_alloc, nlmsg_hdr
from libnl.netlink_private.netlink import BUG
from libnl.nl import nl_send_auto_complete
from libnl.netlink_private.types import genl_family

#ctrl_policy = define_struct(nla_policy, CTRL_ATTR_MAX + 1, {
#    CTRL_ATTR_FAMILY_ID: nla_policy(type=NLA_U16),
#    CTRL_ATTR_FAMILY_NAME: nla_policy(type=NLA_STRING, maxlen=GENL_NAMSIZ),
#    CTRL_ATTR_VERSION: nla_policy(type=NLA_U32),
#    CTRL_ATTR_HDRSIZE: nla_policy(type=NLA_U32),
#    CTRL_ATTR_MAXATTR: nla_policy(type=NLA_U32),
#    CTRL_ATTR_OPS: nla_policy(type=NLA_NESTED),
#    CTRL_ATTR_MCAST_GROUPS: nla_policy(type=NLA_NESTED),
#})


def probe_response(msg, arg):
    """Process responses from from the query sent by genl_ctrl_probe_by_name.
    https://github.com/thom311/libnl/blob/master/lib/genl/ctrl.c#L203

    Process returned messages, filling out the missing information in the genl_family structure.

    Positional arguments:
    msg -- netlink message object.
    arg -- argument passed on through caller.

    Returns:
    Indicator to keep processing frames or not.
    """
    tb = POINTER(nlattr)
    nlh = nlmsg_hdr(msg)
    ret = cast(arg, POINTER(genl_family))
    if genlmsg_parse(nlh, 0, tb, CTRL_ATTR_MAX, ctrl_policy):
        return NL_SKIP
    if tb[CTRL_ATTR_FAMILY_ID]:
        genl_family_set_id(ret, nla_get_u16(tb[CTRL_ATTR_FAMILY_ID]))
    if tb[CTRL_ATTR_MCAST_GROUPS] and parse_mcast_grps(ret, tb[CTRL_ATTR_MCAST_GROUPS]) < 0:
        return NL_SKIP
    return NL_STOP


def genl_ctrl_probe_by_name(sk, name):
    """Look up generic netlink family by family name querying the kernel directly.
    https://github.com/thom311/libnl/blob/master/lib/genl/ctrl.c#L237

    Directly query's the kernel for a given family name. The caller will own a reference on the returned object which
    needs to be given back after usage using genl_family_put.

    Note: This API call differs from genl_ctrl_search_by_name in that it queries the kernel directly, allowing for
    module autoload to take place to resolve the family request. Using an nl_cache prevents that operation.

    Positional arguments:
    sk -- generic netlink socket.
    name -- family name.

    Returns:
    Generic netlink family object or None if no match was found.
    """
    ret = genl_family_alloc()
    if not ret:
        return None
    genl_family_set_name(ret, name)

    msg = nlmsg_alloc()
    if not msg:
        genl_family_put(ret)
        return None

    orig = nl_socket_get_cb(sk)
    if not orig:
        nlmsg_free(msg)
        genl_family_put(ret)
        return None

    cb = nl_cb_clone(orig)
    nl_cb_put(orig)
    if not cb:
        nlmsg_free(msg)
        genl_family_put(ret)
        return None

    if not genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, GENL_ID_CTRL, 0, 0, CTRL_CMD_GETFAMILY, 1):
        nl_cb_put(cb)
        nlmsg_free(msg)
        genl_family_put(ret)
        raise BUG

    if nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, name) < 0:
        nl_cb_put(cb)
        nlmsg_free(msg)
        genl_family_put(ret)
        return None

    if nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, probe_response, ret) < 0:
        nl_cb_put(cb)
        nlmsg_free(msg)
        genl_family_put(ret)
        return None

    if nl_send_auto_complete(sk, msg) < 0:
        nl_cb_put(cb)
        nlmsg_free(msg)
        genl_family_put(ret)
        return None

    if nl_recvmsgs(sk, cb) < 0:
        nl_cb_put(cb)
        nlmsg_free(msg)
        genl_family_put(ret)
        return None

    # If search was successful, request may be ACKed after data.
    if wait_for_ack(sk) < 0:
        nl_cb_put(cb)
        nlmsg_free(msg)
        genl_family_put(ret)
        return None

    if genl_family_get_id(ret) != 0:
        nlmsg_free(msg)
        nl_cb_put(cb)
        return ret

    nl_cb_put(cb)
    nlmsg_free(msg)
    genl_family_put(ret)
    return None


def genl_ctrl_resolve(sk, name):
    """Resolve Generic Netlink family name to numeric identifier.
    https://github.com/thom311/libnl/blob/master/lib/genl/ctrl.c#L429

    Resolves the Generic Netlink family name to the corresponding numeric family identifier. This function queries the
    kernel directly, use genl_ctrl_search_by_name() if you need to resolve multiple names.

    Positional arguments:
    sk -- generic netlink socket.
    name -- name of generic netlink family.

    Returns:
    The numeric family identifier or a negative error code.
    """
    family = genl_ctrl_probe_by_name(sk, name)
    if not family:
        return -NLE_OBJ_NOTFOUND
    err = genl_family_get_id(family)
    genl_family_put(family)
    return int(err)


def genl_ctrl_resolve_grp(sk, family_name, grp_name):
    """Resolve Generic Netlink family group name.
    https://github.com/thom311/libnl/blob/master/lib/genl/ctrl.c#L471

    Looks up the family object and resolves the group name to the numeric group identifier.

    Positional arguments:
    sk -- generic netlink socket.
    family_name -- name of generic netlink family.
    grp_name -- name of group to resolve.

    Returns:
    Numeric group identifier or a negative error code.
    """
    family = genl_ctrl_probe_by_name(sk, family_name)
    if not family:
        return -NLE_OBJ_NOTFOUND
    err = genl_ctrl_grp_by_name(family, grp_name)
    genl_family_put(family)
    return int(err)
