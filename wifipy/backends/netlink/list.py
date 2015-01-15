"""Netlink List Utilities (netlink/list.h).
https://github.com/thom311/libnl/blob/master/include/netlink/list.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from ctypes import POINTER, Structure


class nl_list_head(Structure):
    """https://github.com/thom311/libnl/blob/master/include/netlink/list.h#L15"""
    pass
nl_list_head._fields_ = [
    ('next', POINTER(nl_list_head)),
    ('prev', POINTER(nl_list_head)),
]
