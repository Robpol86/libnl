"""Generic Cacheable Object (lib/object.c).
https://github.com/thom311/libnl/blob/master/lib/object.c

Generic object data type, for inheritance purposes to implement cacheable data types.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from ctypes import POINTER, sizeof

from libnl.backends.netlink.object_api import nl_object


def nl_object_alloc(ops):
    """Allocate a new object of kind specified by the operations handle.
    https://github.com/thom311/libnl/blob/master/lib/object.c#L54

    Positional arguments:
    ops -- cache operations handle.

    Returns:
    The new object or None.
    """
    new = POINTER(nl_object())

    if ops.oo_size < sizeof(POINTER(new)):
        raise OSError('BUG: ops.oo_size < sizeof(POINTER(new)')
    # TODO