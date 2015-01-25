"""Netlink Types (netlink-private/types.h).
https://github.com/thom311/libnl/blob/master/include/netlink-private/types.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from ctypes import c_char, c_int, c_uint, c_uint16, c_uint32, POINTER, Structure

from libnl.cache_api import nl_cache_ops
from libnl.hashtable import nl_hash_table
from libnl.list import nl_list_head
from libnl.object_api import NLHDR_COMMON


class nl_cache(Structure):
    """https://github.com/thom311/libnl/blob/master/include/netlink-private/types.h#L82"""
    _fields_ = [
        ('c_items', nl_list_head),
        ('c_nitems', c_int),
        ('c_iarg1', c_int),
        ('c_iarg2', c_int),
        ('c_refcnt', c_int),
        ('c_flags', c_uint),
        ('hashtable', POINTER(nl_hash_table)),
        ('c_ops', POINTER(nl_cache_ops)),
    ]


class nl_msg(object):
    """https://github.com/thom311/libnl/blob/master/include/netlink-private/types.h#L133"""

    def __init__(self):
        self.nm_protocol = None
        self.nm_flags = None
        self.nm_src = None
        self.nm_dst = None
        self.nm_creds = None
        self.nm_nlh = None
        self.nm_refcnt = None


class genl_family(Structure):
    """https://github.com/thom311/libnl/blob/master/include/netlink-private/types.h#L783"""
    _fields_ = NLHDR_COMMON + [
        ('gf_id', c_uint16),
        ('gf_name', c_char),
        ('gf_version', c_uint32),
        ('gf_hdrsize', c_uint32),
        ('gf_maxattr', c_uint32),
        ('gf_ops', nl_list_head),
        ('gf_mc_grps', nl_list_head),
    ]
