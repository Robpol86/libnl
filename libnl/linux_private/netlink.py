"""netlink.h.
https://github.com/thom311/libnl/blob/master/include/linux-private/linux/netlink.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from ctypes import byref, c_int, c_uint, c_uint16, c_uint32, c_ushort, c_void_p, cast, sizeof, Structure


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


class sockaddr_nl(Structure):
    """https://github.com/thom311/libnl/blob/master/include/linux-private/linux/netlink.h#L31

    Fields:
    nl_family -- AF_NETLINK.
    nl_pad -- zero.
    nl_pid -- port ID.
    nl_groups -- multicast groups mask.
    """
    _fields_ = [
        ('nl_family', c_ushort),
        ('nl_pad', c_ushort),
        ('nl_pid', c_uint32),
        ('nl_groups', c_uint32),
    ]


class nlmsghdr(Structure):
    """https://github.com/thom311/libnl/blob/master/include/linux-private/linux/netlink.h#L38

    Fields:
    nlmsg_len -- length of message including header.
    nlmsg_type -- message content.
    nlmsg_flags -- additional flags.
    nlmsg_seq -- sequence number.
    nlmsg_pid -- sending process port ID.
    """
    _fields_ = [
        ('nlmsg_len', c_uint32),
        ('nlmsg_type', c_uint16),
        ('nlmsg_flags', c_uint16),
        ('nlmsg_seq', c_uint32),
        ('nlmsg_pid', c_uint32),
    ]


NLMSG_ALIGNTO = c_uint(4)
NLMSG_ALIGN = lambda len_: (len_ + NLMSG_ALIGNTO.value - 1) & ~(NLMSG_ALIGNTO.value - 1)
NLMSG_HDRLEN = NLMSG_ALIGN(sizeof(nlmsghdr))
NLMSG_LENGTH = lambda len_: len_ + NLMSG_ALIGN(NLMSG_HDRLEN)
NLMSG_SPACE = lambda len_: NLMSG_ALIGN(NLMSG_LENGTH(len_))
NLMSG_DATA = lambda nlh: cast(byref(nlh, NLMSG_LENGTH(0)), c_void_p)
#define NLMSG_NEXT(nlh,len)	 ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), (struct nlmsghdr*)(((char*)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))
NLMSG_OK = lambda nlh, len_: len_ >= sizeof(nlmsghdr) and sizeof(nlmsghdr) <= nlh.contents.nlmsg_len <= len_
NLMSG_PAYLOAD = lambda nlh, len_: nlh.nlmsg_len - NLMSG_SPACE(len_)
NLMSG_NOOP = 0x1  # Nothing.
NLMSG_ERROR = 0x2  # Error.
NLMSG_DONE = 0x3  # End of a dump.
NLMSG_OVERRUN = 0x4  # Data lost.
NLMSG_MIN_TYPE = 0x10  # < 0x10: reserved control messages.


class nlmsgerr(Structure):
    """https://github.com/thom311/libnl/blob/master/include/linux-private/linux/netlink.h#L95"""
    _fields_ = [
        ('error', c_int),
        ('msg', nlmsghdr),
    ]


NETLINK_ADD_MEMBERSHIP = 1
NETLINK_DROP_MEMBERSHIP = 2
NETLINK_PKTINFO = 3
NETLINK_BROADCAST_ERROR = 4
NETLINK_NO_ENOBUFS = 5
