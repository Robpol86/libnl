"""rtnetlink.h.
https://github.com/thom311/libnl/blob/libnl3_2_25/include/linux/rtnetlink.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

import ctypes
from libnl.misc import split_bytearray

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


class rtattr(object):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/include/linux/rtnetlink.h#L137

    Generic structure for encapsulation of optional route information. It is reminiscent of sockaddr, but with sa_family
    replaced with attribute type.

    Instance variables:
    rta_type -- c_ushort attribute type.
    payload -- data of any type for this attribute. None means 0 byte payload.
    """
    SIZEOF = ctypes.sizeof(ctypes.c_ushort) * 2

    def __init__(self, rta_type=None, payload=None):
        self._rta_type = None
        self.rta_type = rta_type
        self.payload = payload

    def __bytes__(self):
        """Returns a bytes object formatted for the kernel."""
        rta_len = self.rta_len
        payload = b'' if self.payload is None else bytes(self.payload)
        padding = (b'\0' * (RTA_ALIGN(rtattr.SIZEOF) - self.SIZEOF), b'\0' * (RTA_ALIGN(rta_len) - rta_len))
        segments = (bytes(ctypes.c_uint16(rta_len)), bytes(self._rta_type), padding[0], payload, padding[1])
        return b''.join(segments)

    def __repr__(self):
        answer = '<{0}.{1} rta_len={2} rta_type={3} payload={4}>'.format(
            self.__class__.__module__,
            self.__class__.__name__,
            self.rta_len, self.rta_type,
            'yes' if self.payload else 'no',
        )
        return answer

    @property
    def rta_len(self):
        """c_ushort attribute length including payload, returns integer."""
        return RTA_ALIGN(rtattr.SIZEOF) + (0 if self.payload is None else ctypes.sizeof(self.payload))

    @property
    def rta_type(self):
        """c_ushort attribute type."""
        return self._rta_type.value

    @rta_type.setter
    def rta_type(self, value):
        if value is None:
            self._rta_type = ctypes.c_ushort()
            return
        self._rta_type = value if isinstance(value, ctypes.c_ushort) else ctypes.c_ushort(value)


RTA_ALIGNTO = 4
RTA_ALIGN = lambda len_: (len_ + RTA_ALIGNTO - 1) & ~(RTA_ALIGNTO - 1)
RTA_LENGTH = lambda len_: RTA_ALIGN(rtattr.SIZEOF) + len_
RTA_SPACE = lambda len_: RTA_ALIGN(RTA_LENGTH(len_))
RTA_PAYLOAD = lambda rta: rta.rta_len - RTA_LENGTH(0)


class rtgenmsg(object):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/include/linux/rtnetlink.h#L410

    Instance variables:
    rtgen_family -- c_ubyte rtgen family.
    """
    SIZEOF = ctypes.sizeof(ctypes.c_ubyte)

    def __init__(self, rtgen_family=None):
        self._rtgen_family = None
        self.rtgen_family = rtgen_family

    def __bytes__(self):
        return bytes(self._rtgen_family)

    def __repr__(self):
        answer = '<{0}.{1} rtgen_family={2}>'.format(
            self.__class__.__module__,
            self.__class__.__name__,
            self.rtgen_family,
        )
        return answer

    @property
    def rtgen_family(self):
        """c_ubyte rtgen family, returns integer."""
        return self._rtgen_family.value

    @rtgen_family.setter
    def rtgen_family(self, value):
        if value is None:
            self._rtgen_family = ctypes.c_ubyte()
            return
        self._rtgen_family = value if isinstance(value, ctypes.c_ubyte) else ctypes.c_ubyte(value)


class ifinfomsg(object):
    """Passes link level specific information, not dependent on network protocol.
    https://github.com/thom311/libnl/blob/libnl3_2_25/include/linux/rtnetlink.h#L423

    Instance variables:
    ifi_family -- c_ubyte.
    ifi_type -- ARPHRD_*, c_ushort.
    ifi_index -- link index, c_int.
    ifi_flags -- IFF_* flags, c_uint.
    ifi_change -- IFF_* change mask, c_uint.
    payload -- data of any type for this attribute. None means 0 byte payload.
    """
    SIZEOF = sum([ctypes.sizeof(ctypes.c_ubyte) * 2, ctypes.sizeof(ctypes.c_ushort), ctypes.sizeof(ctypes.c_int),
                  ctypes.sizeof(ctypes.c_uint) * 2])

    def __init__(self, ifi_family=None, ifi_type=None, ifi_index=None, ifi_flags=None, ifi_change=None, payload=None):
        self._ifi_family = None
        self._ifi_type = None
        self._ifi_index = None
        self._ifi_flags = None
        self._ifi_change = None

        self.payload = payload
        self.ifi_family = ifi_family
        self.ifi_type = ifi_type
        self.ifi_index = ifi_index
        self.ifi_flags = ifi_flags
        self.ifi_change = ifi_change

    def __repr__(self):
        answer_base = '<{0}.{1} ifi_family={2} ifi_type={3} ifi_index={4} ifi_flags={5} ifi_change={6} payload={7}>'
        answer = answer_base.format(
            self.__class__.__module__,
            self.__class__.__name__,
            self.ifi_family, self.ifi_type, self.ifi_index, self.ifi_flags, self.ifi_change,
            'yes' if self.payload else 'no',
        )
        return answer

    @classmethod
    def from_buffer(cls, buf):
        """Creates and returns a class instance based on data from a bytearray()."""
        types = (ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ushort, ctypes.c_int, ctypes.c_uint, ctypes.c_uint)
        ifi_family, __ifi_pad, ifi_type, ifi_index, ifi_flags, ifi_change, buf_remaining = split_bytearray(buf, *types)
        nlh = cls(ifi_family=ifi_family, ifi_type=ifi_type, ifi_index=ifi_index, ifi_flags=ifi_flags,
                  ifi_change=ifi_change, payload=buf_remaining)
        return nlh

    @property
    def ifi_family(self):
        return self._ifi_family.value

    @ifi_family.setter
    def ifi_family(self, value):
        if value is None:
            self._ifi_family = ctypes.c_ubyte()
            return
        self._ifi_family = value if isinstance(value, ctypes.c_ubyte) else ctypes.c_ubyte(value)

    @property
    def ifi_type(self):
        return self._ifi_type.value

    @ifi_type.setter
    def ifi_type(self, value):
        if value is None:
            self._ifi_type = ctypes.c_ushort()
            return
        self._ifi_type = value if isinstance(value, ctypes.c_ushort) else ctypes.c_ushort(value)

    @property
    def ifi_index(self):
        return self._ifi_index.value

    @ifi_index.setter
    def ifi_index(self, value):
        if value is None:
            self._ifi_index = ctypes.c_int()
            return
        self._ifi_index = value if isinstance(value, ctypes.c_int) else ctypes.c_int(value)

    @property
    def ifi_flags(self):
        return self._ifi_flags.value

    @ifi_flags.setter
    def ifi_flags(self, value):
        if value is None:
            self._ifi_flags = ctypes.c_uint()
            return
        self._ifi_flags = value if isinstance(value, ctypes.c_uint) else ctypes.c_uint(value)

    @property
    def ifi_change(self):
        return self._ifi_change.value

    @ifi_change.setter
    def ifi_change(self, value):
        if value is None:
            self._ifi_change = ctypes.c_uint()
            return
        self._ifi_change = value if isinstance(value, ctypes.c_uint) else ctypes.c_uint(value)
