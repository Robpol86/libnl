"""Port of cache-api.h C library.
https://github.com/thom311/libnl/blob/master/include/netlink-private/cache-api.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from ctypes import c_char_p, c_int, c_uint, c_void_p, POINTER, Structure

from wifipy.backends.netlink.object_api import nl_object_ops
from wifipy.backends.netlink.types import nl_cache


class nl_msgtype(Structure):
    """https://github.com/thom311/libnl/blob/master/include/netlink-private/cache-api.h#L117"""
    _fields_ = [
        ('mt_id', c_int),
        ('mt_act', c_int),
        ('mt_name', c_char_p),
    ]


class nl_af_group(Structure):
    """https://github.com/thom311/libnl/blob/master/include/netlink-private/cache-api.h#L132"""
    _fields_ = [
        ('ag_family', c_int),
        ('ag_group', c_int),
    ]


class nl_cache_ops(Structure):
    """https://github.com/thom311/libnl/blob/master/include/netlink-private/cache-api.h#L165"""
    pass
nl_cache_ops._fields_ = [
    ('co_name', c_char_p),
    ('co_hdrsize', c_int),
    ('co_protocol', c_int),
    ('co_hash_size', c_int),
    ('co_flags', c_uint),
    ('co_refcnt', c_uint),
    ('co_groups', POINTER(nl_af_group)),
    ('co_request_update', c_int),
    ('co_msg_parser', c_int),
    ('co_event_filter', c_int),
    ('co_include_event', c_int),
    ('reserved_1', c_void_p),
    ('reserved_2', c_void_p),
    ('reserved_3', c_void_p),
    ('reserved_4', c_void_p),
    ('reserved_5', c_void_p),
    ('reserved_6', c_void_p),
    ('reserved_7', c_void_p),
    ('reserved_8', c_void_p),
    ('co_obj_ops', POINTER(nl_object_ops)),
    ('co_next', POINTER(nl_cache_ops)),
    ('co_major_cache', POINTER(nl_cache)),
    ('co_genl', POINTER()),  # POINTER(genl_ops): infinite python import recursion.
    ('co_msgtypes', nl_msgtype),
]
