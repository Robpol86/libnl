"""genetlink.h.

https://github.com/thom311/libnl/blob/libnl3_2_25/include/linux/genetlink.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from libnl.linux_private.netlink import NLMSG_ALIGN, NLMSG_MIN_TYPE
from libnl.misc import bytearray_ptr, c_uint16, c_uint8, SIZEOF_U16, SIZEOF_U8, Struct

GENL_NAMSIZ = 16  # Length of family name.
GENL_MIN_ID = NLMSG_MIN_TYPE
GENL_MAX_ID = 1023


class genlmsghdr(Struct):
    """Generic Netlink message header (holds payload data).

    https://github.com/thom311/libnl/blob/libnl3_2_25/include/linux/genetlink.h#L12

    Instance variables:
    cmd -- c_uint8
    version -- c_uint8
    reserved -- c_uint16
    payload -- payload and padding at the end (bytearay).
    """

    _REPR = '<{0}.{1} cmd={2[cmd]} version={2[version]} reserved={2[reserved]} payload={2[payload]}>'
    SIGNATURE = (SIZEOF_U8, SIZEOF_U8, SIZEOF_U16)
    SIZEOF = sum(SIGNATURE)

    def __init__(self, ba=None, cmd=None, version=None, reserved=None):
        """Constructor."""
        super(genlmsghdr, self).__init__(ba)
        if cmd is not None:
            self.cmd = cmd
        if version is not None:
            self.version = version
        if reserved is not None:
            self.reserved = reserved

    @property
    def cmd(self):
        """Return command integer."""
        return c_uint8.from_buffer(self.bytearray[self._get_slicers(0)]).value

    @cmd.setter
    def cmd(self, value):
        """Command setter."""
        self.bytearray[self._get_slicers(0)] = bytearray(c_uint8(value or 0))

    @property
    def version(self):
        """Return version integer."""
        return c_uint8.from_buffer(self.bytearray[self._get_slicers(1)]).value

    @version.setter
    def version(self, value):
        """Version setter."""
        self.bytearray[self._get_slicers(1)] = bytearray(c_uint8(value or 0))

    @property
    def reserved(self):
        """Return reserved integer."""
        return c_uint16.from_buffer(self.bytearray[self._get_slicers(2)]).value

    @reserved.setter
    def reserved(self, value):
        """Reserved setter."""
        self.bytearray[self._get_slicers(2)] = bytearray(c_uint16(value or 0))

    @property
    def payload(self):
        """Payload and padding at the end (bytearray_ptr)."""
        return bytearray_ptr(self.bytearray, self._get_slicers(2).stop)


GENL_HDRLEN = NLMSG_ALIGN(genlmsghdr.SIZEOF)
GENL_ADMIN_PERM = 0x01
GENL_CMD_CAP_DO = 0x02
GENL_CMD_CAP_DUMP = 0x04
GENL_CMD_CAP_HASPOL = 0x08
GENL_ID_GENERATE = 0
GENL_ID_CTRL = NLMSG_MIN_TYPE
GENL_HDRSIZE = lambda hdrlen: GENL_HDRLEN + hdrlen  # /thom311/libnl/blob/libnl3_2_25/include/netlink-private/genl.h#L18


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
