"""Port of object-api.h C library.
https://github.com/thom311/libnl/blob/master/include/netlink-private/object-api.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from ctypes import c_char_p, c_int, c_size_t, c_uint32, c_void_p, POINTER, Structure

from wifipy.backends.netlink.list import nl_list_head
from wifipy.backends.netlink.types import nl_cache


class nl_object_ops(Structure):
    _fields_ = [
        ('oo_name', c_char_p),
        ('oo_size', c_size_t),
        ('oo_id_attrs', c_uint32),
        ('oo_constructor', c_void_p),
        ('oo_free_data', c_void_p),
        ('oo_clone', c_int),
        ('oo_dump', c_void_p),
        ('oo_compare', c_int),
        ('oo_update', c_int),
        ('oo_keygen', c_void_p),
        ('oo_attrs2str', POINTER(c_char_p)),
        ('oo_id_attrs_get', c_uint32),
    ]


NLHDR_COMMON = [
    ('ce_refcnt', c_int),
    ('ce_ops', POINTER(nl_object_ops)),
    ('ce_cache', POINTER(nl_cache)),
    ('ce_list', nl_list_head),
    ('ce_msgtype', c_int),
    ('ce_flags', c_int),
    ('ce_mask', c_uint32),
]


class nl_object(Structure):
    _fields_ = NLHDR_COMMON
