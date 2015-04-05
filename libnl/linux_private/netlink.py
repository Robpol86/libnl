"""netlink.h.

https://github.com/thom311/libnl/blob/libnl3_2_25/include/linux/netlink.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from libnl.misc import (bytearray_ptr, c_int, c_uint, c_uint16, c_uint32, c_ushort, SIZEOF_INT, SIZEOF_U16, SIZEOF_U32,
                        SIZEOF_UINT, SIZEOF_USHORT, Struct)

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


class sockaddr_nl(Struct):
    """Netlink sockaddr class (C struct equivalent).

    https://github.com/thom311/libnl/blob/libnl3_2_25/include/linux/netlink.h#L31

    Instance variables:
    nl_family -- AF_NETLINK (c_uint).
    nl_pad -- zero (c_ushort).
    nl_pid -- port ID (c_uint32).
    nl_groups -- multicast groups mask (c_uint32).
    """

    _REPR = '<{0}.{1} nl_family={2[nl_family]} nl_pad={2[nl_pad]} nl_pid={2[nl_pid]} nl_groups={2[nl_groups]}>'
    SIGNATURE = (SIZEOF_UINT, SIZEOF_USHORT, SIZEOF_U32, SIZEOF_U32)
    SIZEOF = sum(SIGNATURE)

    def __init__(self, nl_family=0, nl_pad=0, nl_pid=0, nl_groups=0):
        """Constructor."""
        super(sockaddr_nl, self).__init__()
        self.nl_family = nl_family
        self.nl_pad = nl_pad
        self.nl_pid = nl_pid
        self.nl_groups = nl_groups

    def __iter__(self):
        """Yield pid and groups."""
        yield self.nl_pid
        yield self.nl_groups

    @property
    def nl_family(self):
        """AF_NETLINK."""
        return c_uint.from_buffer(self.bytearray[self._get_slicers(0)]).value

    @nl_family.setter
    def nl_family(self, value):
        """Family setter."""
        self.bytearray[self._get_slicers(0)] = bytearray(c_uint(value or 0))

    @property
    def nl_pad(self):
        """Zero."""
        return c_ushort.from_buffer(self.bytearray[self._get_slicers(1)]).value

    @nl_pad.setter
    def nl_pad(self, value):
        """Pad setter."""
        self.bytearray[self._get_slicers(1)] = bytearray(c_ushort(value or 0))

    @property
    def nl_pid(self):
        """Port ID."""
        return c_uint32.from_buffer(self.bytearray[self._get_slicers(2)]).value

    @nl_pid.setter
    def nl_pid(self, value):
        """Port ID setter."""
        self.bytearray[self._get_slicers(2)] = bytearray(c_uint32(value or 0))

    @property
    def nl_groups(self):
        """Port ID."""
        return c_uint32.from_buffer(self.bytearray[self._get_slicers(3)]).value

    @nl_groups.setter
    def nl_groups(self, value):
        """Group setter."""
        self.bytearray[self._get_slicers(3)] = bytearray(c_uint32(value or 0))


class nlmsghdr(Struct):
    """Netlink message header (holds actual payload of Netlink message).

    https://github.com/thom311/libnl/blob/libnl3_2_25/include/linux/netlink.h#L38

     <------- NLMSG_ALIGN(hlen) ------> <---- NLMSG_ALIGN(len) --->
    +----------------------------+- - -+- - - - - - - - - - -+- - -+
    |           Header           | Pad |       Payload       | Pad |
    |      struct nlmsghdr       |     |                     |     |
    +----------------------------+- - -+- - - - - - - - - - -+- - -+
     <-------------- nlmsghdr->nlmsg_len ------------------->

    Instance variables:
    nlmsg_len -- length of message including header (c_uint32).
    nlmsg_type -- message content (c_uint16).
    nlmsg_flags -- additional flags (c_uint16).
    nlmsg_seq -- sequence number (c_uint32).
    nlmsg_pid -- sending process port ID (c_uint32).
    payload -- payload and padding at the end (bytearay).
    """

    _REPR = ('<{0}.{1} nlmsg_len={2[nlmsg_len]} nlmsg_type={2[nlmsg_type]} nlmsg_flags={2[nlmsg_flags]} '
             'nlmsg_seq={2[nlmsg_seq]} nlmsg_pid={2[nlmsg_pid]} payload={2[payload]}>')
    SIGNATURE = (SIZEOF_U32, SIZEOF_U16, SIZEOF_U16, SIZEOF_U32, SIZEOF_U32)
    SIZEOF = sum(SIGNATURE)

    def __init__(self, ba=None, nlmsg_len=None, nlmsg_type=None, nlmsg_flags=None, nlmsg_seq=None, nlmsg_pid=None):
        """Constructor."""
        super(nlmsghdr, self).__init__(ba)
        if nlmsg_len is not None:
            self.nlmsg_len = nlmsg_len
        if nlmsg_type is not None:
            self.nlmsg_type = nlmsg_type
        if nlmsg_flags is not None:
            self.nlmsg_flags = nlmsg_flags
        if nlmsg_seq is not None:
            self.nlmsg_seq = nlmsg_seq
        if nlmsg_pid is not None:
            self.nlmsg_pid = nlmsg_pid

    @property
    def nlmsg_len(self):
        """Length of message including header."""
        return c_uint32.from_buffer(self.bytearray[self._get_slicers(0)]).value

    @nlmsg_len.setter
    def nlmsg_len(self, value):
        """Length setter."""
        self.bytearray[self._get_slicers(0)] = bytearray(c_uint32(value or 0))

    @property
    def nlmsg_type(self):
        """Message content."""
        return c_uint16.from_buffer(self.bytearray[self._get_slicers(1)]).value

    @nlmsg_type.setter
    def nlmsg_type(self, value):
        """Message content setter."""
        self.bytearray[self._get_slicers(1)] = bytearray(c_uint16(value or 0))

    @property
    def nlmsg_flags(self):
        """Additional flags."""
        return c_uint16.from_buffer(self.bytearray[self._get_slicers(2)]).value

    @nlmsg_flags.setter
    def nlmsg_flags(self, value):
        """Message flags setter."""
        self.bytearray[self._get_slicers(2)] = bytearray(c_uint16(value or 0))

    @property
    def nlmsg_seq(self):
        """Sequence number."""
        return c_uint32.from_buffer(self.bytearray[self._get_slicers(3)]).value

    @nlmsg_seq.setter
    def nlmsg_seq(self, value):
        """Sequence setter."""
        self.bytearray[self._get_slicers(3)] = bytearray(c_uint32(value or 0))

    @property
    def nlmsg_pid(self):
        """Sending process port ID."""
        return c_uint32.from_buffer(self.bytearray[self._get_slicers(4)]).value

    @nlmsg_pid.setter
    def nlmsg_pid(self, value):
        """Port ID setter."""
        self.bytearray[self._get_slicers(4)] = bytearray(c_uint32(value or 0))

    @property
    def payload(self):
        """Payload and padding at the end (bytearray_ptr)."""
        return bytearray_ptr(self.bytearray, self._get_slicers(4).stop)


NLMSG_ALIGNTO = c_uint(4).value
NLMSG_ALIGN = lambda len_: (len_ + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1)
NLMSG_HDRLEN = NLMSG_ALIGN(nlmsghdr.SIZEOF)
NLMSG_LENGTH = lambda len_: len_ + NLMSG_ALIGN(NLMSG_HDRLEN)
NLMSG_SPACE = lambda len_: NLMSG_ALIGN(NLMSG_LENGTH(len_))
NLMSG_NOOP = 0x1  # Nothing.
NLMSG_ERROR = 0x2  # Error.
NLMSG_DONE = 0x3  # End of a dump.
NLMSG_OVERRUN = 0x4  # Data lost.
NLMSG_MIN_TYPE = 0x10  # < 0x10: reserved control messages.


class nlmsgerr(Struct):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/include/linux/netlink.h#L95.

    Instance variables:
    error -- c_int.
    msg -- nlmsghdr class instance.
    """

    _REPR = '<{0}.{1} error={2[error]} msg={2[msg]}>'
    SIGNATURE = (SIZEOF_INT, nlmsghdr.SIZEOF)
    SIZEOF = sum(SIGNATURE)

    @property
    def error(self):
        """Error integer value."""
        return c_int.from_buffer(self.bytearray[self._get_slicers(0)]).value

    @property
    def msg(self):
        """Payload and padding at the end (nlmsghdr class instance)."""
        return nlmsghdr(self.bytearray[self._get_slicers(1).start:])


NETLINK_ADD_MEMBERSHIP = 1
NETLINK_DROP_MEMBERSHIP = 2
NETLINK_PKTINFO = 3
NETLINK_BROADCAST_ERROR = 4
NETLINK_NO_ENOBUFS = 5


class nlattr(Struct):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/include/linux/netlink.h#L126.

    Holds a Netlink attribute along with a payload/data (such as a c_uint32 instance).

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

    Instance variables:
    nla_len -- length of attribute including payload (c_uint16).
    nla_type -- attribute type (e.g. NL80211_ATTR_SCAN_SSIDS) (c_uint16).
    payload -- payload and padding at the end (bytearay_ptr).
    """

    _REPR = '<{0}.{1} nla_len={2[nla_len]} nla_type={2[nla_type]} payload={2[payload]}>'
    SIGNATURE = (SIZEOF_U16, SIZEOF_U16)
    SIZEOF = sum(SIGNATURE)

    def __init__(self, ba, nla_len=None, nla_type=None):
        """Constructor."""
        super(nlattr, self).__init__(ba)
        if nla_len is not None:
            self.nla_len = nla_len
        if nla_type is not None:
            self.nla_type = nla_type

    @property
    def nla_len(self):
        """Attribute length."""
        return c_uint16.from_buffer(self.bytearray[self._get_slicers(0)]).value

    @nla_len.setter
    def nla_len(self, value):
        """Length setter."""
        self.bytearray[self._get_slicers(0)] = bytearray(c_uint16(value or 0))

    @property
    def nla_type(self):
        """Attribute type."""
        return c_uint16.from_buffer(self.bytearray[self._get_slicers(1)]).value

    @nla_type.setter
    def nla_type(self, value):
        """Type setter."""
        self.bytearray[self._get_slicers(1)] = bytearray(c_uint16(value or 0))

    @property
    def payload(self):
        """Payload and padding at the end."""
        return self.bytearray[self._get_slicers(1).stop:]


NLA_F_NESTED = 1 << 15
NLA_F_NET_BYTEORDER = 1 << 14
NLA_TYPE_MASK = ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)


NLA_ALIGNTO = 4
NLA_ALIGN = lambda len_: (len_ + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1)
NLA_HDRLEN = int(NLA_ALIGN(nlattr.SIZEOF))
