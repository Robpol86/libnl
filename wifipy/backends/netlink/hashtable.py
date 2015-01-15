"""Port of hashtable.h C library.
https://github.com/thom311/libnl/blob/master/include/netlink/hashtable.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from ctypes import c_int, c_uint32, POINTER, Structure

from wifipy.backends.netlink.object_api import nl_object


class nl_hash_node(Structure):
    """https://github.com/thom311/libnl/blob/master/include/netlink/hashtable.h#L19"""
    pass
nl_hash_node._fields_ = [
    ('key', c_uint32),
    ('key_size', c_uint32),
    ('obj', POINTER(nl_object)),
    ('next', POINTER(nl_hash_node)),
]
nl_hash_node_t = nl_hash_node


class nl_hash_table(Structure):
    """https://github.com/thom311/libnl/blob/master/include/netlink/hashtable.h#L26"""
    _fields_ = [
        ('size', c_int),
        ('nodes', POINTER(POINTER(nl_hash_node_t))),
    ]
nl_hash_table_t = nl_hash_table
