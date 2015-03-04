"""Generic Cacheable Object (lib/object.c).
https://github.com/thom311/libnl/blob/libnl3_2_25/lib/object.c

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

import logging

from libnl.netlink_private.object_api import nl_object

_LOGGER = logging.getLogger(__name__)


def nl_object_alloc(ops):  # TODO https://github.com/Robpol86/libnl/issues/15
    """Allocate a new object of kind specified by the operations handle.
    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/object.c#L54

    Positional arguments:
    ops -- cache operations handle (nl_object_ops class instance).

    Returns:
    New nl_object class instance or None.
    """
    new = nl_object()
    new.ce_ops = ops
    if ops.oo_constructor:
        ops.oo_constructor(new)
    _LOGGER.debug('Allocated new object 0x%x', id(new))
    return new
