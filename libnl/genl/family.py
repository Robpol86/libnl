"""Generic Netlink Family (lib/genl/family.c).
https://github.com/thom311/libnl/blob/master/lib/genl/family.c

Object representing a kernel side registered Generic Netlink family.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from libnl.types import genl_family


def genl_family_alloc():
    """Allocate new Generic Netlink family object.
    https://github.com/thom311/libnl/blob/master/lib/genl/family.c#L181

    Returns:
    Newly allocated Generic Netlink family object (Structure) or NULL.
    """
    return nl_object_alloc()  # TODO
