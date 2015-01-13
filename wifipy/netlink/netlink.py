"""Port of netlink.h C library.
https://github.com/thom311/libnl/blob/master/include/linux-private/linux/netlink.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from ctypes import c_uint16, c_uint32, c_ushort, Structure

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

NETLINK_ADD_MEMBERSHIP = 1
NETLINK_DROP_MEMBERSHIP = 2


class sockaddr_nl(Structure):
    _fields_ = [
        ('nl_family', c_ushort),  # AF_NETLINK (sa_family_t = typedef c_ushort).
        ('nl_pad', c_ushort),  # Zero.
        ('nl_pid', c_uint32),  # Port ID.
        ('nl_groups', c_uint32),  # Multicast groups mask.
    ]


class nlmsghdr(Structure):
    _fields_ = [
        ('nlmsg_len', c_uint32),  # Length of message including header.
        ('nlmsg_type', c_uint16),  # Message content.
        ('nlmsg_flags', c_uint16),  # Additional flags.
        ('nlmsg_seq', c_uint32),  # Sequence number.
        ('nlmsg_pid', c_uint32),  # Sending process port ID.
    ]
