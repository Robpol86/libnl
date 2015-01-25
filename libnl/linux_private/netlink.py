"""netlink.h.
https://github.com/thom311/libnl/blob/master/include/linux-private/linux/netlink.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from ctypes import c_int, c_uint, c_uint16, c_uint32, c_ushort, c_void_p, cast, pointer, resize, sizeof, Structure


def _increase(ptr, offset):
    """Calls resize() on a sizeof(pointer) then returns that same pointer. Used for ported C macros (to lambdas) below.

    Positional arguments:
    ptr -- pointer() return value.
    offset -- integer value to increase size of pointer.
    """
    resize(ptr, sizeof(ptr) + offset)
    return ptr


NLM_F_REQUEST = 1  # It is request message.
NLM_F_MULTI = 2  # Multipart message, terminated by NLMSG_DONE
NLM_F_ACK = 4  # Reply with ack, with zero or error code
NLM_F_ECHO = 8  # Echo this request
NLM_F_DUMP_INTR = 16  # Dump was inconsistent due to sequence change


# Modifiers to GET request.
NLM_F_ROOT = 0x100  # Specify tree root.
NLM_F_MATCH = 0x200  # Return all matching.
NLM_F_ATOMIC = 0x400  # Atomic GET.
NLM_F_DUMP = NLM_F_ROOT | NLM_F_MATCH


# Modifiers to NEW request.
NLM_F_REPLACE = 0x100  # Override existing.
NLM_F_EXCL = 0x200  # Do not touch, if it exists.
NLM_F_CREATE = 0x400  # Create, if it does not exist.
NLM_F_APPEND = 0x800  # Add to end of list.


class sockaddr_nl(object):
    """https://github.com/thom311/libnl/blob/master/include/linux-private/linux/netlink.h#L31

    Fields:
    nl_family -- AF_NETLINK.
    nl_pad -- zero.
    nl_pid -- port ID.
    nl_groups -- multicast groups mask.
    """

    def __init__(self):
        self._nl_pid = None
        self._nl_groups = None
        self.nl_family = None

    @property
    def nl_pid(self):
        return self._nl_pid

    @nl_pid.setter
    def nl_pid(self, value):
        if value is None:
            self._nl_pid = None
            return
        self._nl_pid = value if isinstance(value, c_uint32) else c_uint32(value)

    @property
    def nl_groups(self):
        return self._nl_groups

    @nl_groups.setter
    def nl_groups(self, value):
        if value is None:
            self._nl_groups = None
            return
        self._nl_groups = value if isinstance(value, c_uint32) else c_uint32(value)


class nlmsghdr(object):
    """https://github.com/thom311/libnl/blob/master/include/linux-private/linux/netlink.h#L38"""

    def __init__(self, nlmsg_type=None, nlmsg_flags=None, nlmsg_pid=None):
        self._nlmsg_type = None
        self._nlmsg_flags = None
        self._nlmsg_pid = None

        self.attrs = list()
        self.nlmsg_type = nlmsg_type
        self.nlmsg_flags = nlmsg_flags
        self.nlmsg_pid = nlmsg_pid

    @property
    def nlmsg_type(self):
        """message content."""
        return self._nlmsg_type

    @nlmsg_type.setter
    def nlmsg_type(self, value):
        if value is None:
            self._nlmsg_type = None
            return
        self._nlmsg_type = value if isinstance(value, c_uint16) else c_uint16(value)

    @property
    def nlmsg_flags(self):
        """additional flags."""
        return self._nlmsg_flags

    @nlmsg_flags.setter
    def nlmsg_flags(self, value):
        if value is None:
            self._nlmsg_flags = None
            return
        self._nlmsg_flags = value if isinstance(value, c_uint16) else c_uint16(value)

    @property
    def nlmsg_pid(self):
        """sending process port ID."""
        return self._nlmsg_pid

    @nlmsg_pid.setter
    def nlmsg_pid(self, value):
        if value is None:
            self._nlmsg_pid = None
            return
        self._nlmsg_pid = value if isinstance(value, c_uint32) else c_uint32(value)


NLMSG_ALIGNTO = c_uint(4)
NLMSG_ALIGN = lambda len_: (len_ + NLMSG_ALIGNTO.value - 1) & ~(NLMSG_ALIGNTO.value - 1)
#NLMSG_HDRLEN = NLMSG_ALIGN(sizeof(nlmsghdr))
#NLMSG_LENGTH = lambda len_: len_ + NLMSG_ALIGN(NLMSG_HDRLEN)
#NLMSG_SPACE = lambda len_: NLMSG_ALIGN(NLMSG_LENGTH(len_))
#NLMSG_DATA = lambda nlh: cast(_increase(pointer(nlh), NLMSG_LENGTH(0)), c_void_p)
#define NLMSG_NEXT(nlh,len)	 ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), (struct nlmsghdr*)(((char*)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))
NLMSG_OK = lambda nlh, len_: len_ >= sizeof(nlmsghdr) and sizeof(nlmsghdr) <= nlh.contents.nlmsg_len <= len_
#NLMSG_PAYLOAD = lambda nlh, len_: nlh.contents.nlmsg_len - NLMSG_SPACE(len_)
NLMSG_NOOP = 0x1  # Nothing.
NLMSG_ERROR = 0x2  # Error.
NLMSG_DONE = 0x3  # End of a dump.
NLMSG_OVERRUN = 0x4  # Data lost.
NLMSG_MIN_TYPE = 0x10  # < 0x10: reserved control messages.


#class nlmsgerr(Structure):
#    """https://github.com/thom311/libnl/blob/master/include/linux-private/linux/netlink.h#L95"""
#    _fields_ = [
#        ('error', c_int),
#        ('msg', nlmsghdr),
#    ]


NETLINK_ADD_MEMBERSHIP = 1
NETLINK_DROP_MEMBERSHIP = 2
NETLINK_PKTINFO = 3
NETLINK_BROADCAST_ERROR = 4
NETLINK_NO_ENOBUFS = 5


class nlattr(object):
    """https://github.com/thom311/libnl/blob/master/include/linux-private/linux/netlink.h#L126

    Holds a netlink attribute along with a payload/data (such as a c_uint32 instance).

    Instance variables:
    nla_type -- c_uint16 attribute type (e.g. NL80211_ATTR_SCAN_SSIDS).
    payload -- data of any type for this attribute.
    """

    def __init__(self, nla_type=None, payload=None):
        self._nla_type = None
        self.nla_type = nla_type
        self.payload = payload

    @property
    def nla_type(self):
        """c_uint16 attribute type (e.g. NL80211_ATTR_SCAN_SSIDS)."""
        return self._nla_type

    @nla_type.setter
    def nla_type(self, value):
        if value is None:
            self._nla_type = None
            return
        self._nla_type = value if isinstance(value, c_uint16) else c_uint16(value)


NLA_F_NESTED = 1 << 15
NLA_F_NET_BYTEORDER = 1 << 14
NLA_TYPE_MASK = ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)


NLA_ALIGNTO = 4
NLA_ALIGN = lambda len_: (len_ + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1)
#NLA_HDRLEN = int(NLA_ALIGN(sizeof(nlattr)))
