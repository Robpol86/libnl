"""Object API (netlink-private/object-api.c).
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
    """Object Operations
    https://github.com/thom311/libnl/blob/master/include/netlink-private/object-api.h#L269

    Fields:
    oo_name -- unique name of object type.
    oo_size -- size of object including its header.
    oo_id_attrs -- list of attributes needed to uniquely identify the object.
    oo_constructor -- constructor function. Will be called when a new object of this type is allocated. Can be used to
        initialize members such as lists etc.
    oo_free_data -- destructor function. Will be called when an object is freed. Must free all resources which may have
        been allocated as part of this object.
    oo_clone -- cloning function. Will be called when an object needs to be cloned. Please note that the generic object
        code will make an exact copy of the object first, therefore you only need to take care of members which require
        reference counting etc. May return a negative error code to abort cloning.
    oo_dump -- dumping functions. Will be called when an object is dumped. The implementations have to use nl_dump(),
        nl_dump_line(), and nl_new_line() to dump objects. The functions must return the number of lines printed.
    oo_compare -- comparison function. Will be called when two objects of the same type are compared. It takes the two
        objects in question, an object specific bitmask defining which attributes should be compared and flags to
        control the behaviour. The function must return a bitmask with the relevant bit set for each attribute that
        mismatches.
    oo_update -- update function. Will be called when the object given by first argument needs to be updated with the
        contents of the second object. The function must return 0 for success and error for failure to update. In case
        of failure its assumed that the original object is not touched.
    oo_keygen -- hash Key generator function. When called returns a hash key for the object being referenced. This key
        will be used by higher level hash functions to build association lists. Each object type gets to specify it's
        own key formulation.
    oo_attrs2str -- attrs to str.
    oo_id_attrs_get -- get key attributes by family function.
    """
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
    """https://github.com/thom311/libnl/blob/master/include/netlink-private/object-api.h#L194"""
    _fields_ = NLHDR_COMMON
