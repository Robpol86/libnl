"""Cache Management (lib/cache_mngt.c).

https://github.com/thom311/libnl/blob/libnl3_2_25/lib/cache_mngt.c

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

import logging
import threading

from libnl.errno_ import NLE_EXIST, NLE_INVAL
from libnl.netlink_private.cache_api import nl_cache_ops

_LOGGER = logging.getLogger(__name__)
cache_ops = nl_cache_ops()
cache_ops_lock = threading.Lock()


def _nl_cache_ops_lookup(name):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/cache_mngt.c#L41.

    Positional arguments:
    name -- string.

    Returns:
    nl_cache_ops instance or None.
    """
    ops = cache_ops
    while ops:  # Loop until `ops` is None.
        if ops.co_name == name:
            return ops
        ops = ops.co_next
    return None


def _cache_ops_associate(protocol, msgtype):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/cache_mngt.c#L111.

    Positional arguments:
    protocol -- Netlink protocol (integer).
    msgtype -- Netlink message type (integer).

    Returns:
    nl_cache_ops instance with matching protocol containing matching msgtype or None.
    """
    ops = cache_ops
    while ops:  # Loop until `ops` is None.
        if ops.co_protocol == protocol:
            for co_msgtype in ops.co_msgtypes:
                if co_msgtype.mt_id == msgtype:
                    return ops
        ops = ops.co_next
    return None


def nl_cache_ops_associate_safe(protocol, msgtype):
    """Associate protocol and message type to cache operations.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/cache_mngt.c#L164

    Searches the registered cache operations for a matching protocol and message type.

    Positional arguments:
    protocol -- Netlink protocol (integer).
    msgtype -- Netlink message type (integer).

    Returns:
    The cache operations or None if no no match was found.
    """
    with cache_ops_lock:
        return _cache_ops_associate(protocol, msgtype)


def nl_msgtype_lookup(ops, msgtype):
    """Lookup message type cache association.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/cache_mngt.c#L189

    Searches for a matching message type association ing the specified cache operations.

    Positional arguments:
    ops -- cache operations (nl_cache_ops class instance).
    msgtype -- Netlink message type (integer).

    Returns:
    A message type association or None.
    """
    for i in ops.co_msgtypes:
        if i.mt_id == msgtype:
            return i
    return None


def nl_cache_mngt_register(ops):
    """Register a set of cache operations.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/cache_mngt.c#L252

    Called by users of caches to announce the availability of a certain cache type.

    Positional arguments:
    ops -- cache operations (nl_cache_ops class instance).

    Returns:
    0 on success or a negative error code.
    """
    global cache_ops

    if not ops.co_name or not ops.co_obj_ops:
        return -NLE_INVAL

    with cache_ops_lock:
        if _nl_cache_ops_lookup(ops.co_name):
            return -NLE_EXIST
        ops.co_refcnt = 0
        ops.co_next = cache_ops
        cache_ops = ops

    _LOGGER.debug('Registered cache operations {0}'.format(ops.co_name))
    return 0
