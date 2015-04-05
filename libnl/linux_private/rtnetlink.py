"""rtnetlink.h.

https://github.com/thom311/libnl/blob/libnl3_2_25/include/linux/rtnetlink.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from libnl.misc import (bytearray_ptr, c_int, c_ubyte, c_uint, c_ushort, SIZEOF_INT, SIZEOF_UBYTE, SIZEOF_UINT,
                        SIZEOF_USHORT, Struct)

RTNL_FAMILY_IPMR = 128
RTNL_FAMILY_IP6MR = 129
RTNL_FAMILY_MAX = 129

RTM_BASE = 16
RTM_NEWLINK = 16
RTM_DELLINK = 17
RTM_GETLINK = 18
RTM_SETLINK = 19
RTM_NEWADDR = 20
RTM_DELADDR = 21
RTM_GETADDR = 22
RTM_NEWROUTE = 24
RTM_DELROUTE = 25
RTM_GETROUTE = 26
RTM_NEWNEIGH = 28
RTM_DELNEIGH = 29
RTM_GETNEIGH = 30
RTM_NEWRULE = 32
RTM_DELRULE = 33
RTM_GETRULE = 34
RTM_NEWQDISC = 36
RTM_DELQDISC = 37
RTM_GETQDISC = 38
RTM_NEWTCLASS = 40
RTM_DELTCLASS = 41
RTM_GETTCLASS = 42
RTM_NEWTFILTER = 44
RTM_DELTFILTER = 45
RTM_GETTFILTER = 46
RTM_NEWACTION = 48
RTM_DELACTION = 49
RTM_GETACTION = 50
RTM_NEWPREFIX = 52
RTM_GETMULTICAST = 58
RTM_GETANYCAST = 62
RTM_NEWNEIGHTBL = 64
RTM_GETNEIGHTBL = 66
RTM_SETNEIGHTBL = 67
RTM_NEWNDUSEROPT = 68
RTM_NEWADDRLABEL = 72
RTM_DELADDRLABEL = 73
RTM_GETADDRLABEL = 74
RTM_GETDCB = 78
RTM_SETDCB = 79
RTM_MAX = RTM_SETDCB

RTM_NR_MSGTYPES = RTM_MAX + 1 - RTM_BASE
RTM_NR_FAMILIES = RTM_NR_MSGTYPES >> 2
RTM_FAM = lambda cmd: (cmd - RTM_BASE) >> 2


class rtattr(Struct):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/include/linux/rtnetlink.h#L137.

    Generic structure for encapsulation of optional route information. It is reminiscent of sockaddr, but with sa_family
    replaced with attribute type.

    Instance variables:
    rta_len -- c_ushort.
    rta_type -- attribute type (c_ushort).
    payload -- payload and padding at the end (bytearay).
    """

    _REPR = '<{0}.{1} rta_len={2[rta_len]} rta_type={2[rta_type]} payload={2[payload]}>'
    SIGNATURE = (SIZEOF_USHORT, SIZEOF_USHORT)
    SIZEOF = sum(SIGNATURE)

    def __init__(self, ba, rta_len=None, rta_type=None):
        """Constructor."""
        super(rtattr, self).__init__(ba)
        if rta_len is not None:
            self.rta_len = rta_len
        if rta_type is not None:
            self.rta_type = rta_type

    @property
    def rta_len(self):
        """Attribute length."""
        return c_ushort.from_buffer(self.bytearray[self._get_slicers(0)]).value

    @rta_len.setter
    def rta_len(self, value):
        """Length setter."""
        self.bytearray[self._get_slicers(0)] = bytearray(c_ushort(value or 0))

    @property
    def rta_type(self):
        """Attribute type."""
        return c_ushort.from_buffer(self.bytearray[self._get_slicers(1)]).value

    @rta_type.setter
    def rta_type(self, value):
        """Type setter."""
        self.bytearray[self._get_slicers(1)] = bytearray(c_ushort(value or 0))

    @property
    def payload(self):
        """Payload and padding at the end."""
        return self.bytearray[self._get_slicers(1).stop:]


RTA_ALIGNTO = 4
RTA_ALIGN = lambda len_: (len_ + RTA_ALIGNTO - 1) & ~(RTA_ALIGNTO - 1)
RTA_OK = lambda rta, len_: len_.value >= rtattr.SIZEOF and rtattr.SIZEOF <= rta.rta_len <= len_.value
RTA_NEXT = lambda rta, attrlen: (setattr(attrlen, 'value', attrlen.value - RTA_ALIGN(rta.rta_len)),
                                 rtattr(bytearray_ptr(rta.bytearray, RTA_ALIGN(rta.rta_len))))[1]
RTA_LENGTH = lambda len_: RTA_ALIGN(rtattr.SIZEOF) + len_
RTA_SPACE = lambda len_: RTA_ALIGN(RTA_LENGTH(len_))
RTA_DATA = lambda rta: rta.payload.rstrip(b'\0')
RTA_PAYLOAD = lambda rta: rta.rta_len - RTA_LENGTH(0)


class rtgenmsg(Struct):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/include/linux/rtnetlink.h#L410.

    Instance variables:
    rtgen_family -- rtgen family (c_ubyte).
    """

    _REPR = '<{0}.{1} rtgen_family={2[rtgen_family]}>'
    SIGNATURE = (SIZEOF_UBYTE, )
    SIZEOF = sum(SIGNATURE)

    def __init__(self, rtgen_family=None):
        """Constructor."""
        super(rtgenmsg, self).__init__()
        if rtgen_family is not None:
            self.rtgen_family = rtgen_family

    @property
    def rtgen_family(self):
        """rtgen family."""
        return c_ubyte.from_buffer(self.bytearray[self._get_slicers(0)]).value

    @rtgen_family.setter
    def rtgen_family(self, value):
        """Family setter."""
        self.bytearray[self._get_slicers(0)] = bytearray(c_ubyte(value or 0))


class ifinfomsg(Struct):
    """Pass link level specific information, not dependent on network protocol.

    https://github.com/thom311/libnl/blob/libnl3_2_25/include/linux/rtnetlink.h#L423

    Instance variables:
    ifi_family -- c_ubyte.
    _ifi_pad -- c_ubyte.
    ifi_type -- ARPHRD_* (c_ushort).
    ifi_index -- link index (c_int).
    ifi_flags -- IFF_* flags (c_uint).
    ifi_change -- IFF_* change mask (c_uint).
    payload -- payload and padding at the end (bytearay).
    """

    _REPR = ('<{0}.{1} ifi_family={2[ifi_family]} ifi_type={2[ifi_type]} ifi_index={2[ifi_index]} '
             'ifi_flags={2[ifi_flags]} ifi_change={2[ifi_change]} payload={2[payload]}>')
    SIGNATURE = (SIZEOF_UBYTE, SIZEOF_UBYTE, SIZEOF_USHORT, SIZEOF_INT, SIZEOF_UINT, SIZEOF_UINT)
    SIZEOF = sum(SIGNATURE)

    def __init__(self, ba, ifi_family=None, ifi_type=None, ifi_index=None, ifi_flags=None, ifi_change=None):
        """Constructor."""
        super(ifinfomsg, self).__init__(ba)
        if ifi_family is not None:
            self.ifi_family = ifi_family
        if ifi_type is not None:
            self.ifi_type = ifi_type
        if ifi_index is not None:
            self.ifi_index = ifi_index
        if ifi_flags is not None:
            self.ifi_flags = ifi_flags
        if ifi_change is not None:
            self.ifi_change = ifi_change

    @property
    def ifi_family(self):
        """Message family."""
        return c_ubyte.from_buffer(self.bytearray[self._get_slicers(0)]).value

    @ifi_family.setter
    def ifi_family(self, value):
        """Family setter."""
        self.bytearray[self._get_slicers(0)] = bytearray(c_ubyte(value or 0))

    @property
    def ifi_type(self):
        """Message type."""
        return c_ushort.from_buffer(self.bytearray[self._get_slicers(2)]).value

    @ifi_type.setter
    def ifi_type(self, value):
        """Type setter."""
        self.bytearray[self._get_slicers(2)] = bytearray(c_ushort(value or 0))

    @property
    def ifi_index(self):
        """Message index."""
        return c_int.from_buffer(self.bytearray[self._get_slicers(3)]).value

    @ifi_index.setter
    def ifi_index(self, value):
        """Index setter."""
        self.bytearray[self._get_slicers(3)] = bytearray(c_int(value or 0))

    @property
    def ifi_flags(self):
        """Message flags."""
        return c_uint.from_buffer(self.bytearray[self._get_slicers(4)]).value

    @ifi_flags.setter
    def ifi_flags(self, value):
        """Message flags setter."""
        self.bytearray[self._get_slicers(4)] = bytearray(c_uint(value or 0))

    @property
    def ifi_change(self):
        """Message change."""
        return c_uint.from_buffer(self.bytearray[self._get_slicers(5)]).value

    @ifi_change.setter
    def ifi_change(self, value):
        """Change setter."""
        self.bytearray[self._get_slicers(5)] = bytearray(c_uint(value or 0))

    @property
    def payload(self):
        """Payload and padding at the end (bytearray_ptr)."""
        return bytearray_ptr(self.bytearray, self._get_slicers(5).stop)
