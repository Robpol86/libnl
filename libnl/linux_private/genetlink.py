"""genetlink.h.
https://github.com/thom311/libnl/blob/libnl3_2_25/include/linux-private/linux/genetlink.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

import ctypes

from libnl.linux_private.netlink import NLMSG_MIN_TYPE, NLMSG_ALIGN
from libnl.misc import split_bytearray


GENL_NAMSIZ = 16  # Length of family name.
GENL_MIN_ID = NLMSG_MIN_TYPE
GENL_MAX_ID = 1023


class genlmsghdr(object):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/include/linux-private/linux/genetlink.h#L12

    Instance variables:
    cmd -- c_uint8
    version -- c_uint8
    reserved -- c_uint16
    """
    SIZEOF = (ctypes.sizeof(ctypes.c_uint8) * 2) + ctypes.sizeof(ctypes.c_uint16)

    def __init__(self, cmd=None, version=None, reserved=None):
        self._cmd = None
        self._version = None
        self._reserved = None

        self.cmd = cmd
        self.version = version
        self.reserved = reserved

    def __bytes__(self):
        """Returns a bytes object formatted for the kernel."""
        padding = b'\0' * (GENL_HDRLEN - self.SIZEOF)
        segments = (
            bytes(self._cmd),
            bytes(self._version),
            bytes(self._reserved),
            padding,
        )
        return b''.join(segments)

    def __repr__(self):
        answer = '<{0}.{1} cmd={2} version={3} reserved={4}>'.format(
            self.__class__.__module__,
            self.__class__.__name__,
            self.cmd, self.version, self.reserved,
        )
        return answer

    @classmethod
    def from_buffer(cls, buf):
        """Creates and returns a class instance based on data from a bytearray()."""
        cmd, version, reserved, _ = split_bytearray(buf, ctypes.c_uint8, ctypes.c_uint8, ctypes.c_uint16)
        return cls(cmd=cmd, version=version, reserved=reserved)

    @property
    def cmd(self):
        return self._cmd.value

    @cmd.setter
    def cmd(self, value):
        if value is None:
            self._cmd = ctypes.c_uint8()
            return
        self._cmd = value if isinstance(value, ctypes.c_uint8) else ctypes.c_uint8(value)

    @property
    def version(self):
        return self._version.value

    @version.setter
    def version(self, value):
        if value is None:
            self._version = ctypes.c_uint8()
            return
        self._version = value if isinstance(value, ctypes.c_uint8) else ctypes.c_uint8(value)

    @property
    def reserved(self):
        return self._reserved.value

    @reserved.setter
    def reserved(self, value):
        if value is None:
            self._reserved = ctypes.c_uint16()
            return
        self._reserved = value if isinstance(value, ctypes.c_uint16) else ctypes.c_uint16(value)


GENL_HDRLEN = NLMSG_ALIGN(genlmsghdr.SIZEOF)
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
