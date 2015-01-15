"""Generic Netlink Management (netlink/genl/mngt.h).
https://github.com/thom311/libnl/blob/master/include/netlink/genl/mngt.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from ctypes import c_char_p, c_int, c_uint, POINTER, Structure

from wifipy.backends.netlink.attr import nla_policy
from wifipy.backends.netlink.cache_api import nl_cache_ops
from wifipy.backends.netlink.list import nl_list_head


class genl_cmd(Structure):
    """Definition of a Generic Netlink command.
    https://github.com/thom311/libnl/blob/master/include/netlink/genl/mngt.h#L87

    This structure is used to define the list of available commands on the receiving side.

    Fields:
    c_id -- Numeric command identifier (required).
    c_name -- Human readable name (required).
    c_maxattr -- Maximum attribute identifier that the command is prepared to handle.
    c_msg_parser -- Called whenever a message for this command is received.
    c_attr_policy -- Attribute validation policy, enforced before the callback is called.
    """
    _fields_ = [
        ('c_id', c_int),
        ('c_name', c_char_p),
        ('c_maxattr', c_int),
        ('c_msg_parser', c_int),
        ('c_attr_policy', POINTER(nla_policy)),
    ]


class genl_ops(Structure):
    """Definition of a Generic Netlink family.
    https://github.com/thom311/libnl/blob/master/include/netlink/genl/mngt.h#L132

    Fields:
    o_hdrsize -- Length of user header.
    o_id -- Numeric identifier, automatically filled in by genl_ops_resolve().
    o_name -- Human readable name, used by genl_ops_resolve() to resolve numeric id.
    o_cache_ops -- If registered via genl_register(), will point to the related cache operations.
    o_cmds -- Optional array defining the available Generic Netlink commands.
    o_ncmds -- Number of elements in \c o_cmds array.
    o_list -- Used internally to link together all registered operations.
    """
    _fields_ = [
        ('o_hdrsize', c_uint),
        ('o_id', c_int),
        ('o_name', c_char_p),
        ('o_cache_ops', POINTER(nl_cache_ops)),
        ('o_cmds', POINTER(genl_cmd)),
        ('o_ncmds', c_int),
        ('o_list', nl_list_head),
    ]
