"""Port of types.h C library.
https://github.com/thom311/libnl/blob/master/include/netlink-private/types.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from ctypes import c_int, c_size_t, Structure

from wifipy.misc import ucred
from wifipy.netlink.netlink import nlmsghdr, sockaddr_nl


class nl_msg(Structure):
    """https://github.com/thom311/libnl/blob/master/include/netlink-private/types.h#L133"""
    _fields_ = [
        ('nm_protocol', c_int),
        ('nm_flags', c_int),
        ('nm_src', sockaddr_nl),
        ('nm_dst', sockaddr_nl),
        ('nm_creds', ucred),
        ('nm_nlh', nlmsghdr),
        ('nm_size', c_size_t),
        ('nm_refcnt', c_int),
    ]
