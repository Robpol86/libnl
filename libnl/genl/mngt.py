"""Generic Netlink Management (netlink/genl/mngt.h).

https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink/genl/mngt.h
https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/mngt.c

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from libnl.cache_mngt import nl_cache_mngt_register
from libnl.errno_ import NLE_EXIST, NLE_INVAL, NLE_MSGTYPE_NOSUPPORT, NLE_OPNOTSUPP, NLE_PROTO_MISMATCH
from libnl.genl.genl import genlmsg_hdr, genlmsg_user_hdr
from libnl.linux_private.genetlink import GENL_HDRLEN, GENL_HDRSIZE
from libnl.linux_private.netlink import NETLINK_GENERIC
from libnl.list_ import nl_list_add_tail, nl_list_for_each_entry, nl_list_head
from libnl.msg import nlmsg_parse
from libnl.netlink_private.netlink import BUG

genl_ops_list = nl_list_head()  # https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/mngt.c#L31
genl_ops_list.next_ = genl_ops_list.prev = genl_ops_list


def lookup_cmd(ops, cmd_id):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/mngt.c#L33.

    Positional arguments:
    ops -- genl_ops class instance.
    cmd_id -- integer.

    Returns:
    genl_cmd class instance or None.
    """
    for i in range(ops.o_ncmds):
        cmd = ops.o_cmds[i]
        if cmd.c_id == cmd_id:
            return cmd
    return None


class genl_info(object):
    """Informative class passed on to message parser callbacks.

    https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink/genl/mngt.h#L37

    This class is passed on to all message parser callbacks and contains information about the sender of the message as
    well as references to all relevant sections of the parsed message.

    Instance variables:
    who -- socket address of sender (sockaddr_nl class instance).
    nlh -- reference to Netlink message header (nlmsghdr class instance).
    genlhdr -- reference to Generic Netlink message header (genlmsghdr class instance).
    userhdr -- reference to user header (any type).
    attrs -- dictionary of parsed attributes.
    """

    def __init__(self, who=None, nlh=None, genlhdr=None, userhdr=None, attrs=None):
        """Constructor."""
        self.who = who
        self.nlh = nlh
        self.genlhdr = genlhdr
        self.userhdr = userhdr
        self.attrs = attrs


def cmd_msg_parser(who, nlh, ops, cache_ops, arg):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/mngt.c#L47.

    Positional arguments:
    who -- sockaddr_nl class instance.
    nlh -- nlmsghdr class instance.
    ops -- genl_ops class instance.
    cache_ops -- nl_cache_ops class instance.
    arg -- to be passed along to .c_msg_parser().

    Returns:
    Integer
    """
    ghdr = genlmsg_hdr(nlh)
    cmd = lookup_cmd(ops, ghdr.cmd)
    if not cmd:
        return -NLE_MSGTYPE_NOSUPPORT
    if cmd.c_msg_parser is None:
        return -NLE_OPNOTSUPP

    tb = dict((i, None) for i in range(cmd.c_maxattr + 1))
    info = genl_info(who=who, nlh=nlh, genlhdr=ghdr, userhdr=genlmsg_user_hdr(ghdr), attrs=tb)
    err = nlmsg_parse(nlh, GENL_HDRSIZE(ops.o_hdrsize), tb, cmd.c_maxattr, cmd.c_attr_policy)
    if err < 0:
        return err
    return cmd.c_msg_parser(cache_ops, cmd, info, arg)


def genl_msg_parser(ops, who, nlh, pp):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/mngt.c#L85.

    Positional arguments:
    ops -- nl_cache_ops class instance.
    who -- sockaddr_nl class instance.
    nlh -- nlmsghdr class instance.
    pp -- nl_parser_param class instance.

    Returns:
    Integer, cmd_msg_parser() output.
    """
    if ops.co_genl is None:
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
        """Constructor."""
        self.c_id = c_id
        self.c_name = c_name
        self.c_maxattr = c_maxattr
        self.c_msg_parser = c_msg_parser
        self.c_attr_policy = c_attr_policy


def lookup_family(family):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/mngt.c#L94.

    Positional arguments:
    family -- integer.

    Returns:
    genl_ops class instance or None.
    """
    for ops in nl_list_for_each_entry(genl_ops(), genl_ops_list, 'o_list'):
        if ops.o_id == family:
            return ops
    return None


def lookup_family_by_name(name):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/mngt.c#L106.

    Positional arguments:
    name -- string.

    Returns:
    genl_ops class instance or None.
    """
    for ops in nl_list_for_each_entry(genl_ops(), genl_ops_list, 'o_list'):
        if ops.o_name == name:
            return ops
    return None


class genl_ops(object):
    """Definition of a Generic Netlink family.

    https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink/genl/mngt.h#L132

    Instance variables:
    o_hdrsize -- length of user header (c_uint).
    o_id -- numeric identifier, automatically filled in by genl_ops_resolve() (c_int).
    o_name -- human readable name, used by genl_ops_resolve() to resolve numeric id (string).
    o_cache_ops -- if registered via genl_register(), will point to the related cache operations (nl_cache_ops class
        instance).
    o_cmds -- optional array defining the available Generic Netlink commands (genl_cmd class instance).
    o_ncmds -- number of elements in `o_cmds` array.
    o_list -- used internally to link together all registered operations (nl_list_head class instance).
    """

    def __init__(self, o_hdrsize=0, o_id=0, o_name='', o_cache_ops=None, o_cmds=None, o_ncmds=0, o_list=None):
        """Constructor."""
        self.o_hdrsize = o_hdrsize
        self.o_id = o_id
        self.o_name = o_name
        self.o_cache_ops = o_cache_ops
        self.o_cmds = o_cmds
        self.o_ncmds = o_ncmds
        self.o_list = o_list or nl_list_head()
        self.o_list.container_of = self

    def __repr__(self):
        """repr() handler."""
        answer_base = ("<{0}.{1} o_hdrsize={2} o_id={3} o_name='{4}' o_cache_ops={5} o_cmds='{6}' o_ncmds={7} "
                       "o_list='{8}'>")
        answer = answer_base.format(
            self.__class__.__module__,
            self.__class__.__name__,
            self.o_hdrsize, self.o_id, self.o_name, 'yes' if self.o_cache_ops else 'no', self.o_cmds, self.o_ncmds,
            self.o_list,
        )
        return answer


def genl_register_family(ops):
    """Register Generic Netlink family and associated commands.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/mngt.c#L164

    Registers the specified Generic Netlink family definition together with all associated commands. After registration,
    received Generic Netlink messages can be passed to genl_handle_msg() which will validate the messages, look for a
    matching command and call the respective callback function automatically.

    Positional arguments:
    ops -- Generic Netlink family definition (genl_ops class instance).

    Returns:
    0 on success or a negative error code.
    """
    if not ops.o_name or (ops.o_cmds and ops.o_ncmds <= 0):
        return -NLE_INVAL

    if ops.o_id and lookup_family(ops.o_id):
        return -NLE_EXIST

    if lookup_family_by_name(ops.o_name):
        return -NLE_EXIST

    nl_list_add_tail(ops.o_list, genl_ops_list)

    return 0


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
    if ops.co_genl is None:
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
