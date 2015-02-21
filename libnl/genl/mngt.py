"""Generic Netlink Management (netlink/genl/mngt.h).
https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink/genl/mngt.h
https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/mngt.c

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from libnl.errno_ import NLE_PROTO_MISMATCH, NLE_INVAL
from libnl.linux_private.genetlink import GENL_HDRSIZE, GENL_HDRLEN
from libnl.linux_private.netlink import NETLINK_GENERIC
from libnl.netlink_private.netlink import BUG


def cmd_msg_parser(who, nlh, ops, cache_ops, arg):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/mngt.c#L47

    Positional arguments:
    who -- sockaddr_nl class instance.
    nlh -- nlmsghdr class instance.
    ops -- genl_ops class instance.
    cache_ops -- nl_cache_ops class instance.
    arg -- to be passed along to .c_msg_parser().

    Returns:
    Integer
    """
    raise NotImplementedError


def genl_msg_parser(ops, who, nlh, pp):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/mngt.c#L85

    Positional arguments:
    ops:
    who:
    nlh:
    pp:

    Returns:
    Integer, cmd_msg_parser() output.
    """
    if not ops.co_genl:
        raise BUG
    return int(cmd_msg_parser(who, nlh, ops.co_genl, ops, pp))


class genl_cmd(object):
    """Definition of a Generic Netlink command.
    https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink/genl/mngt.h#L87

    This structure is used to define the list of available commands on the receiving side.

    Instance variables:
    c_id -- numeric command identifier (c_int).
    c_name -- human readable name (string).
    c_maxattr -- maximum attribute identifier that the command is prepared to handle (c_int).
    c_msg_parser -- function called whenever a message for this command is received.
    c_attr_policy -- attribute validation policy, enforced before the callback is called (nla_policy class instance).
    """

    def __init__(self, c_id=0, c_name='', c_maxattr=0, c_msg_parser=None, c_attr_policy=None):
        self.c_id = c_id
        self.c_name = c_name
        self.c_maxattr = c_maxattr
        self.c_msg_parser = c_msg_parser
        self.c_attr_policy = c_attr_policy


class genl_ops(object):
    """Definition of a Generic Netlink family.
    https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink/genl/mngt.h#L132

    Instance variables:
    o_hdrsize -- length of user header (c_uint).
    o_id -- numeric identifier, automatically filled in by genl_ops_resolve (c_int).
    o_name -- human readable name, used by genl_ops_resolve() to resolve numeric id (string).
    o_cache_ops -- if registered via genl_register(), will point to the related cache operations (nl_cache_ops class
        instance).
    o_cmds -- optional array defining the available Generic Netlink commands (genl_cmd class instance).
    o_list -- used internally to link together all registered operations (nl_list_head class instance).
    """

    def __init__(self, o_hdrsize=0, o_id=0, o_name='', o_cache_ops=None, o_cmds=None, o_list=None):
        self.o_hdrsize = o_hdrsize
        self.o_id = o_id
        self.o_name = o_name
        self.o_cache_ops = o_cache_ops
        self.o_cmds = o_cmds
        self.o_list = o_list


def genl_register(ops):
    """Register Generic Netlink family backed cache.
    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/mngt.c#L241

    Same as genl_register_family() but additionally registers the specified cache operations using
    nl_cache_mngt_register() and associates it with the Generic Netlink family.

    Positional arguments:
    ops -- cache operations definition (nl_cache_ops class instance).

    Returns:
    0 on success or a negative error code.
    """
    if ops.co_protocol != NETLINK_GENERIC:
        return -NLE_PROTO_MISMATCH
    if ops.co_hdrsize < GENL_HDRSIZE(0):
        return -NLE_INVAL
    if not ops.co_genl:
        return -NLE_INVAL

    ops.co_genl.o_cache_ops = ops
    ops.co_genl.o_hdrsize = ops.co_hdrsize - GENL_HDRLEN
    ops.co_genl.o_name = ops.co_msgtypes[0].mt_name
    ops.co_genl.o_id = ops.co_msgtypes[0].mt_id
    ops.co_msg_parser = genl_msg_parser

    err = genl_register_family(ops.co_genl)
    if err < 0:
        return err
    return nl_cache_mngt_register(ops)
