"""Object API (netlink-private/object-api.c).

https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink-private/object-api.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from libnl.list_ import nl_list_head


class NLHDR_COMMON(object):
    """Common Object Header.

    https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink-private/object-api.h#L185

    Must be used by every "object" definition to allow objects to be cached.

    Instance variables:
    ce_refcnt -- c_int.
    ce_ops -- nl_object_ops class instance.
    ce_cache -- nl_cache class instance.
    ce_list -- nl_list_head class instance.
    ce_msgtype -- c_int.
    ce_flags -- c_int.
    ce_mask -- c_uint32.
    """

    SIZEOF = 32

    def __init__(self):
        """Constructor."""
        self.ce_refcnt = 0
        self.ce_ops = None
        self.ce_cache = None
        self.ce_list = nl_list_head(container_of=self)
        self.ce_msgtype = 0
        self.ce_flags = 0
        self.ce_mask = 0


class nl_object(NLHDR_COMMON):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink-private/object-api.h#L194."""

    pass


class nl_object_ops(object):
    """Object operations.

    https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink-private/object-api.h#L269

    Instance variables:
    oo_name -- unique name of object type. Must be in the form family/name, e.g. "route/addr" (bytes()).
    oo_size -- size of object including its header (c_uint32).
    oo_id_attrs -- attributes needed to uniquely identify the object (c_uint32).
    oo_constructor -- constructor function, will be called when a new object of this type is allocated. Can be used to
        initialize members such as lists etc.
    oo_free_data -- destructor function, will be called when an object is freed. Must free all resources which may have
        been allocated as part of this object.
    oo_clone -- cloning function, will be called when an object needs to be cloned. Please note that the generic object
        code will make an exact copy of the object first, therefore you only need to take care of members which require
        reference counting etc. May return a negative error code to abort cloning.
    oo_dump -- dumping functions as values, NL_DUMP_* integer values as keys. Will be called when an object is dumped.
        The implementations have to use nl_dump(), nl_dump_line(), and nl_new_line() to dump objects. The functions must
        return the number of lines printed (dict(), keys are integers, values are functions).
    oo_compare -- comparison function, will be called when two objects of the same type are compared. It takes the two
        objects in question, an object specific bitmask defining which attributes should be compared and flags to
        control the behaviour. The function must return a bitmask with the relevant bit set for each attribute that
        mismatches.
    oo_update -- update function, will be called when the object given by first argument needs to be updated with the
        contents of the second object. The function must return 0 for success and error for failure to update. In case
        of failure its assumed that the original object is not touched.
    oo_keygen -- hash key generator function, when called returns a hash key for the object being referenced. This key
        will be used by higher level hash functions to build association lists. Each object type gets to specify it's
        own key formulation.
    oo_attrs2str -- function.
    oo_id_attrs_get -- function to get key attributes by family.
    """

    def __init__(self, oo_name, oo_size=None, oo_constructor=None, oo_free_data=None, oo_clone=None, oo_dump=None,
                 oo_compare=None, oo_id_attrs=None):
        """Constructor."""
        self.oo_name = oo_name
        self.oo_size = oo_size
        self.oo_id_attrs = oo_id_attrs
        self.oo_constructor = oo_constructor
        self.oo_free_data = oo_free_data
        self.oo_clone = oo_clone
        self.oo_dump = oo_dump
        self.oo_compare = oo_compare
        self.oo_update = None
        self.oo_keygen = None
        self.oo_attrs2str = None
        self.oo_id_attrs_get = None
