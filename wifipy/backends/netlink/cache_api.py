"""Caching API (netlink-private/cache-api.h).
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
    """Message type to cache action association.
    https://github.com/thom311/libnl/blob/master/include/netlink-private/cache-api.h#L117

    Fields:
    mt_id -- Netlink message type.
    mt_act -- Cache action to take.
    mt_name -- Name of operation for human-readable printing.
    """
    _fields_ = [
        ('mt_id', c_int),
        ('mt_act', c_int),
        ('mt_name', c_char_p),
    ]


class nl_af_group(Structure):
    """Address family to netlink group association.
    https://github.com/thom311/libnl/blob/master/include/netlink-private/cache-api.h#L132

    Fields:
    ag_family -- address family.
    ag_group -- netlink group identifier.
    """
    _fields_ = [
        ('ag_family', c_int),
        ('ag_group', c_int),
    ]


class nl_cache_ops(Structure):
    """Cache Operations.
    https://github.com/thom311/libnl/blob/master/include/netlink-private/cache-api.h#L165

    This structure defines the characteristics of a cache type. It contains pointers to functions which implement the
    specifics of the object type the cache can hold.

    Fields:
    co_name -- name of cache type (must be unique).
    co_hdrsize -- size of family specific netlink header.
    co_protocol -- netlink protocol.
    co_hash_size -- cache object hash size.
    co_flags -- cache flags.
    co_refcnt -- reference counter.
    co_groups -- group definition.
    co_request_update -- called whenever an update of the cache is required. Must send a request message to the kernel
        requesting a complete dump.
    co_msg_parser -- called whenever a message was received that needs to be parsed. Must parse the message and call the
        paser callback function (nl_parser_param) provided via the argument.
    co_event_filter -- the function registered under this callback is called after a netlink notification associated
        with this cache type has been parsed into an object and is being considered for inclusion into the specified
        cache. The purpose of this function is to filter out notifications which should be ignored when updating caches.
        The function must return NL_SKIP to prevent the object from being included, or NL_OK to include it.
    co_include_event -- the function registered under this callback is called when an object formed from a notification
        event needs to be included in a cache. For each modified object, the change callback \c change_cb must be called
        with the \c data argument provided. If no function is registered, the function nl_cache_include() will be used
        for this purpose.
    reserved_1 -- reserved.
    reserved_2 -- reserved.
    reserved_3 -- reserved.
    reserved_4 -- reserved.
    reserved_5 -- reserved.
    reserved_6 -- reserved.
    reserved_7 -- reserved.
    reserved_8 -- reserved.
    co_obj_ops -- object operations.
    co_next -- internal, do not touch!
    co_major_cache -- major cache.
    co_genl -- genl.
    co_msgtypes -- message type definition.
    """
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
