"""netlink.h.
https://github.com/thom311/libnl/blob/master/include/linux-private/linux/netlink.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from ctypes import c_uint, c_uint16, c_uint32, sizeof
from io import BytesIO

NETLINK_ROUTE = 0  # Routing/device hook.
NETLINK_GENERIC = 16

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
    """Netlink sockaddr class (C struct equivalent).
    https://github.com/thom311/libnl/blob/master/include/linux-private/linux/netlink.h#L31

    Instance variables:
    nl_family -- AF_NETLINK.
    nl_pid -- port ID integer.
    nl_groups -- multicast groups mask integer.
    """

    def __init__(self):
        self.nl_family = 0
        self.nl_pid = 0
        self.nl_groups = 0

    def __iter__(self):
        return iter((self.nl_pid, self.nl_groups))


class nlmsghdr(object):
    """Netlink message header (holds actual payload of netlink message).
    https://github.com/thom311/libnl/blob/master/include/linux-private/linux/netlink.h#L38

    Instance variables:
    nlmsg_type -- message content.
    nlmsg_flags -- additional flags.
    nlmsg_seq -- sequence number.
    nlmsg_pid -- sending process port ID.
    """

    def __init__(self, nlmsg_type=None, nlmsg_flags=None, nlmsg_seq=None, nlmsg_pid=None):
        self._nlmsg_type = None
        self._nlmsg_flags = None
        self._nlmsg_seq = None
        self._nlmsg_pid = None

        self.payload = list()
        self.nlmsg_type = nlmsg_type
        self.nlmsg_flags = nlmsg_flags
        self.nlmsg_seq = nlmsg_seq
        self.nlmsg_pid = nlmsg_pid

    def __iter__(self):
        """Converts all these Python data types into bytes() so the kernel can understand the data.

         <------- NLMSG_ALIGN(hlen) ------> <---- NLMSG_ALIGN(len) --->
        +----------------------------+- - -+- - - - - - - - - - -+- - -+
        |           Header           | Pad |       Payload       | Pad |
        |      struct nlmsghdr       |     |                     |     |
        +----------------------------+- - -+- - - - - - - - - - -+- - -+
        """
        buffer = BytesIO()
        buffer.write(self._nlmsg_type)
        buffer.write(self._nlmsg_flags)
        buffer.write(self._nlmsg_seq)
        buffer.write(self._nlmsg_pid)
        for p in self.payload:
            buffer.write(bytes(p))
        return iter(buffer.getvalue())

    @property
    def nlmsg_type(self):
        """message content."""
        return self._nlmsg_type.value

    @nlmsg_type.setter
    def nlmsg_type(self, value):
        if value is None:
            self._nlmsg_type = c_uint16()
            return
        self._nlmsg_type = value if isinstance(value, c_uint16) else c_uint16(value)

    @property
    def nlmsg_flags(self):
        """additional flags."""
        return self._nlmsg_flags.value

    @nlmsg_flags.setter
    def nlmsg_flags(self, value):
        if value is None:
            self._nlmsg_flags = c_uint16()
            return
        self._nlmsg_flags = value if isinstance(value, c_uint16) else c_uint16(value)

    @property
    def nlmsg_seq(self):
        """sequence number."""
        return self._nlmsg_seq.value

    @nlmsg_seq.setter
    def nlmsg_seq(self, value):
        if value is None:
            self._nlmsg_seq = c_uint32()
            return
        self._nlmsg_seq = value if isinstance(value, c_uint32) else c_uint32(value)

    @property
    def nlmsg_pid(self):
        """sending process port ID."""
        return self._nlmsg_pid.value

    @nlmsg_pid.setter
    def nlmsg_pid(self, value):
        if value is None:
            self._nlmsg_pid = c_uint32()
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
    SIZEOF = sizeof(c_uint16) * 2

    def __init__(self, nla_type=None, payload=None):
        self._nla_type = None
        self.nla_type = nla_type
        self.payload = payload

    @property
    def nla_len(self):
        """c_uint16 attribute length including payload, returns integer."""
        return NLA_HDRLEN + sizeof(self.payload)

    @property
    def nla_type(self):
        """c_uint16 attribute type (e.g. NL80211_ATTR_SCAN_SSIDS)."""
        return self._nla_type.value

    @nla_type.setter
    def nla_type(self, value):
        if value is None:
            self._nla_type = c_uint16()
            return
        self._nla_type = value if isinstance(value, c_uint16) else c_uint16(value)

    def __bytes__(self):
        """Returns a bytes object formatted for the kernel.

        To be fed into nl_sendmsg() and sent to the kernel in a format it understands.

         <------- NLA_HDRLEN ------> <-- NLA_ALIGN(payload)-->
        +---------------------+- - -+- - - - - - - - - -+- - -+
        |        Header       | Pad |     Payload       | Pad |
        |   (struct nlattr)   | ing |                   | ing |
        +---------------------+- - -+- - - - - - - - - -+- - -+
         <-------------- nlattr->nla_len -------------->

         <-------- nla_attr_size(payload) --------->
        +------------------+- - -+- - - - - - - - - +- - -+
        | Attribute Header | Pad |     Payload      | Pad |
        +------------------+- - -+- - - - - - - - - +- - -+
         <----------- nla_total_size(payload) ----------->
        """
        nla_len = self.nla_len
        padding = (b'\0' * (NLA_HDRLEN - self.SIZEOF), b'\0' * (NLA_ALIGN(nla_len) - nla_len))
        segments = (bytes(c_uint16(nla_len)), bytes(self._nla_type), padding[0], bytes(self.payload), padding[1])
        return b''.join(segments)


NLA_F_NESTED = 1 << 15
NLA_F_NET_BYTEORDER = 1 << 14
NLA_TYPE_MASK = ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)


NLA_ALIGNTO = 4
NLA_ALIGN = lambda len_: (len_ + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1)
NLA_HDRLEN = int(NLA_ALIGN(nlattr.SIZEOF))
