"""netlink.h.
https://github.com/thom311/libnl/blob/libnl3_2_25/include/linux-private/linux/netlink.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

import ctypes

from libnl.misc import split_bytearray

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
    https://github.com/thom311/libnl/blob/libnl3_2_25/include/linux-private/linux/netlink.h#L31

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
        yield self.nl_pid
        yield self.nl_groups

    def __repr__(self):
        answer = '<{0}.{1} nl_family={2} nl_pid={3} nl_groups={4}>'.format(
            self.__class__.__module__,
            self.__class__.__name__,
            self.nl_family, self.nl_pid, self.nl_groups,
        )
        return answer


class nlmsghdr(object):
    """Netlink message header (holds actual payload of netlink message).
    https://github.com/thom311/libnl/blob/libnl3_2_25/include/linux-private/linux/netlink.h#L38

    Instance variables:
    nlmsg_type -- message content.
    nlmsg_flags -- additional flags.
    nlmsg_seq -- sequence number.
    nlmsg_pid -- sending process port ID.
    payload -- list of data of any type.
    """
    SIZEOF = sum([ctypes.sizeof(ctypes.c_uint16) * 2, ctypes.sizeof(ctypes.c_uint32) * 3])

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

    def __bytes__(self):
        """Returns a bytes object formatted for the kernel.

         <------- NLMSG_ALIGN(hlen) ------> <---- NLMSG_ALIGN(len) --->
        +----------------------------+- - -+- - - - - - - - - - -+- - -+
        |           Header           | Pad |       Payload       | Pad |
        |      struct nlmsghdr       |     |                     |     |
        +----------------------------+- - -+- - - - - - - - - - -+- - -+
         <-------------- nlmsghdr->nlmsg_len ------------------->
        """
        nlmsg_len = self.nlmsg_len
        payload = b''
        for pl in self.payload:
            pl_bytes = bytes(pl)
            payload += pl_bytes.ljust(self._tlen(pl_bytes), b'\0')
        padding = (b'\0' * (NLMSG_ALIGN(self.SIZEOF) - self.SIZEOF), b'\0' * (NLMSG_ALIGN(nlmsg_len) - nlmsg_len))
        segments = (
            bytes(ctypes.c_uint32(nlmsg_len)),
            bytes(self._nlmsg_type),
            bytes(self._nlmsg_flags),
            bytes(self._nlmsg_seq),
            bytes(self._nlmsg_pid),
            padding[0],
            payload,
            padding[1]
        )
        return b''.join(segments)

    def __repr__(self):
        answer_base = '<{0}.{1} nlmsg_len={2} nlmsg_type={3} nlmsg_flags={4} nlmsg_seq={5} nlmsg_pid={6} payload={7}>'
        answer = answer_base.format(
            self.__class__.__module__,
            self.__class__.__name__,
            self.nlmsg_len, self.nlmsg_type, self.nlmsg_flags, self.nlmsg_seq, self.nlmsg_pid,
            'yes' if self.payload else 'no',
        )
        return answer

    @staticmethod
    def _tlen(pl_bytes):
        """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L413"""
        return (len(pl_bytes) + (NLMSG_ALIGNTO - 1)) & ~(NLMSG_ALIGNTO - 1)

    @classmethod
    def from_buffer(cls, buf):
        """Creates and returns a class instance based on data from a bytearray()."""
        types = (ctypes.c_uint32, ctypes.c_uint16, ctypes.c_uint16, ctypes.c_uint32, ctypes.c_uint32)
        nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid, buf_remaining = split_bytearray(buf, *types)
        nlh = cls(nlmsg_type=nlmsg_type, nlmsg_flags=nlmsg_flags, nlmsg_seq=nlmsg_seq, nlmsg_pid=nlmsg_pid)
        buf_remaining = buf_remaining[:NLMSG_ALIGN(nlmsg_len.value) - cls.SIZEOF]
        if buf_remaining:
            nlh.payload.append(buf_remaining)
        return nlh

    @property
    def nlmsg_len(self):
        """c_uint32 length of message including header, returns integer."""
        return NLMSG_ALIGN(self.SIZEOF) + sum(self._tlen(bytes(pl)) for pl in self.payload)

    @property
    def nlmsg_type(self):
        """message content."""
        return self._nlmsg_type.value

    @nlmsg_type.setter
    def nlmsg_type(self, value):
        if value is None:
            self._nlmsg_type = ctypes.c_uint16()
            return
        self._nlmsg_type = value if isinstance(value, ctypes.c_uint16) else ctypes.c_uint16(value)

    @property
    def nlmsg_flags(self):
        """additional flags."""
        return self._nlmsg_flags.value

    @nlmsg_flags.setter
    def nlmsg_flags(self, value):
        if value is None:
            self._nlmsg_flags = ctypes.c_uint16()
            return
        self._nlmsg_flags = value if isinstance(value, ctypes.c_uint16) else ctypes.c_uint16(value)

    @property
    def nlmsg_seq(self):
        """sequence number."""
        return self._nlmsg_seq.value

    @nlmsg_seq.setter
    def nlmsg_seq(self, value):
        if value is None:
            self._nlmsg_seq = ctypes.c_uint32()
            return
        self._nlmsg_seq = value if isinstance(value, ctypes.c_uint32) else ctypes.c_uint32(value)

    @property
    def nlmsg_pid(self):
        """sending process port ID."""
        return self._nlmsg_pid.value

    @nlmsg_pid.setter
    def nlmsg_pid(self, value):
        if value is None:
            self._nlmsg_pid = ctypes.c_uint32()
            return
        self._nlmsg_pid = value if isinstance(value, ctypes.c_uint32) else ctypes.c_uint32(value)


NLMSG_ALIGNTO = ctypes.c_uint(4).value
NLMSG_ALIGN = lambda len_: (len_ + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1)
NLMSG_HDRLEN = NLMSG_ALIGN(nlmsghdr.SIZEOF)
NLMSG_LENGTH = lambda len_: len_ + NLMSG_ALIGN(NLMSG_HDRLEN)
NLMSG_SPACE = lambda len_: NLMSG_ALIGN(NLMSG_LENGTH(len_))
NLMSG_NOOP = 0x1  # Nothing.
NLMSG_ERROR = 0x2  # Error.
NLMSG_DONE = 0x3  # End of a dump.
NLMSG_OVERRUN = 0x4  # Data lost.
NLMSG_MIN_TYPE = 0x10  # < 0x10: reserved control messages.


class nlmsgerr(object):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/include/linux-private/linux/netlink.h#L95

    Instance variables:
    error -- c_int.
    msg -- nlmsghdr class instance.
    """
    SIZEOF = ctypes.sizeof(ctypes.c_int) + nlmsghdr.SIZEOF

    def __init__(self, error=None, msg=None):
        self._error = None
        self.error = error
        self.msg = msg

    def __repr__(self):
        answer = "<{0}.{1} error={2} msg='{3}'>".format(
            self.__class__.__module__,
            self.__class__.__name__,
            self.error, self.msg,
        )
        return answer

    @classmethod
    def from_buffer(cls, buf):
        """Creates and returns a class instance based on data from a bytearray()."""
        error, buf_remaining = split_bytearray(buf, ctypes.c_int)
        nlh = nlmsghdr.from_buffer(buf_remaining)
        return cls(error=error, msg=nlh)

    @property
    def error(self):
        return self._error.value

    @error.setter
    def error(self, value):
        if value is None:
            self._error = ctypes.c_int()
            return
        self._error = value if isinstance(value, ctypes.c_int) else ctypes.c_int(value)


NETLINK_ADD_MEMBERSHIP = 1
NETLINK_DROP_MEMBERSHIP = 2
NETLINK_PKTINFO = 3
NETLINK_BROADCAST_ERROR = 4
NETLINK_NO_ENOBUFS = 5


class nlattr(object):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/include/linux-private/linux/netlink.h#L126

    Holds a netlink attribute along with a payload/data (such as a c_uint32 instance).

    Instance variables:
    nla_type -- c_uint16 attribute type (e.g. NL80211_ATTR_SCAN_SSIDS).
    payload -- data of any type for this attribute. None means 0 byte payload.
    """
    SIZEOF = ctypes.sizeof(ctypes.c_uint16) * 2

    def __init__(self, nla_type=None, payload=None):
        self._nla_type = None
        self.nla_type = nla_type
        self.payload = payload

    def __bytes__(self):
        """Returns a bytes object formatted for the kernel.

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
        payload = b'' if self.payload is None else bytes(self.payload)
        padding = (b'\0' * (NLA_HDRLEN - self.SIZEOF), b'\0' * (NLA_ALIGN(nla_len) - nla_len))
        segments = (bytes(ctypes.c_uint16(nla_len)), bytes(self._nla_type), padding[0], payload, padding[1])
        return b''.join(segments)

    def __repr__(self):
        answer = '<{0}.{1} nla_len={2} nla_type={3} payload={4}>'.format(
            self.__class__.__module__,
            self.__class__.__name__,
            self.nla_len, self.nla_type,
            'yes' if self.payload else 'no',
        )
        return answer

    @classmethod
    def from_buffer(cls, buf):
        """Creates and returns a class instance based on data from a bytearray()."""
        nla_len, nla_type, _ = split_bytearray(buf, ctypes.c_uint16, ctypes.c_uint16)
        nla = cls(nla_type=nla_type)
        payload_size = nla_len.value - NLA_HDRLEN
        if payload_size > 0:
            buf_remaining = buf[NLA_HDRLEN:nla_len.value]
            nla.payload = buf_remaining
        return nla

    @property
    def nla_len(self):
        """c_uint16 attribute length including payload, returns integer."""
        return NLA_HDRLEN + (0 if self.payload is None else ctypes.sizeof(self.payload))

    @property
    def nla_type(self):
        """c_uint16 attribute type (e.g. NL80211_ATTR_SCAN_SSIDS)."""
        return self._nla_type.value

    @nla_type.setter
    def nla_type(self, value):
        if value is None:
            self._nla_type = ctypes.c_uint16()
            return
        self._nla_type = value if isinstance(value, ctypes.c_uint16) else ctypes.c_uint16(value)


NLA_F_NESTED = 1 << 15
NLA_F_NET_BYTEORDER = 1 << 14
NLA_TYPE_MASK = ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)


NLA_ALIGNTO = 4
NLA_ALIGN = lambda len_: (len_ + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1)
NLA_HDRLEN = int(NLA_ALIGN(nlattr.SIZEOF))
