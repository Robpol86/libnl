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


class genlmsghdr(Structure):
    """https://github.com/thom311/libnl/blob/master/include/linux-private/linux/genetlink.h#L12"""
    _fields_ = [
        ('cmd', c_uint8),
        ('version', c_uint8),
        ('reserved', c_uint16),
    ]


GENL_HDRLEN = NLMSG_ALIGN(sizeof(genlmsghdr))
GENL_ADMIN_PERM = 0x01
GENL_CMD_CAP_DO = 0x02
GENL_CMD_CAP_DUMP = 0x04
GENL_CMD_CAP_HASPOL = 0x08
GENL_ID_GENERATE = 0
GENL_ID_CTRL = NLMSG_MIN_TYPE


CTRL_CMD_UNSPEC = 0
CTRL_CMD_NEWFAMILY = 1
CTRL_CMD_DELFAMILY = 2
CTRL_CMD_GETFAMILY = 3
CTRL_CMD_NEWOPS = 4
CTRL_CMD_DELOPS = 5
CTRL_CMD_GETOPS = 6
CTRL_CMD_NEWMCAST_GRP = 7
CTRL_CMD_DELMCAST_GRP = 8
CTRL_CMD_GETMCAST_GRP = 9  # Unused.
CTRL_CMD_MAX = CTRL_CMD_GETMCAST_GRP


CTRL_ATTR_UNSPEC = 0
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2
CTRL_ATTR_VERSION = 3
CTRL_ATTR_HDRSIZE = 4
CTRL_ATTR_MAXATTR = 5
CTRL_ATTR_OPS = 6
CTRL_ATTR_MCAST_GROUPS = 7
CTRL_ATTR_MAX = CTRL_ATTR_MCAST_GROUPS


CTRL_ATTR_OP_UNSPEC = 0
CTRL_ATTR_OP_ID = 1
CTRL_ATTR_OP_FLAGS = 2
CTRL_ATTR_OP_MAX = CTRL_ATTR_OP_FLAGS


CTRL_ATTR_MCAST_GRP_UNSPEC = 0
CTRL_ATTR_MCAST_GRP_NAME = 1
CTRL_ATTR_MCAST_GRP_ID = 2
CTRL_ATTR_MCAST_GRP_MAX = CTRL_ATTR_MCAST_GRP_ID
