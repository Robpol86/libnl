"""Netlink Attributes (netlink/attr.h).
https://github.com/thom311/libnl/blob/master/include/netlink/attr.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from ctypes import c_uint16, Structure

NLA_UNSPEC = 0  # Unspecified type, binary data chunk.
NLA_U8 = 1  # 8 bit integer.
NLA_U16 = 2  # 16 bit integer.
NLA_U32 = 3  # 32 bit integer.
NLA_U64 = 4  # 64 bit integer.
NLA_STRING = 5  # NUL terminated character string.
NLA_FLAG = 6  # Flag.
NLA_MSECS = 7  # Micro seconds (64bit).
NLA_NESTED = 8  # Nested attributes.


class nla_policy(Structure):
    """Attribute validation policy.
    https://github.com/thom311/libnl/blob/master/include/netlink/attr.h#L60

    Fields:
    type -- type of attribute or NLA_UNSPEC.
    minlen -- minimal length of payload required.
    maxlen -- maximal length of payload allowed.
    """
    _fields_ = [
        ('type', c_uint16),
        ('minlen', c_uint16),
        ('maxlen', c_uint16),
    ]
