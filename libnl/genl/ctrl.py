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

from libnl.errno import NLE_OBJ_NOTFOUND
from libnl.genl.family import genl_family_alloc
from libnl.msg import nlmsg_alloc
from libnl.netlink_private.netlink import BUG
from libnl.nl import nl_send_auto_complete


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
