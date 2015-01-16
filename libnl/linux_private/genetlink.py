"""genetlink.h.
https://github.com/thom311/libnl/blob/master/include/linux-private/linux/genetlink.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from ctypes import c_uint8, c_uint16, sizeof, Structure

from libnl.linux_private.netlink import NLMSG_ALIGN, NLMSG_MIN_TYPE


GENL_NAMSIZ = 16  # Length of family name.
GENL_MIN_ID = NLMSG_MIN_TYPE
GENL_MAX_ID = 1023
GENL_ADMIN_PERM = 0x01
GENL_CMD_CAP_DO = 0x02
GENL_CMD_CAP_DUMP = 0x04
GENL_CMD_CAP_HASPOL = 0x08
GENL_ID_GENERATE = 0
GENL_ID_CTRL = NLMSG_MIN_TYPE


class genlmsghdr(Structure):
    """https://github.com/thom311/libnl/blob/master/include/linux-private/linux/genetlink.h#L12"""
    _fields_ = [
        ('cmd', c_uint8),
        ('version', c_uint8),
        ('reserved', c_uint16),
    ]


GENL_HDRLEN = NLMSG_ALIGN(sizeof(genlmsghdr))
