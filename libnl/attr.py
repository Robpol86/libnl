"""Netlink Attributes (netlink/attr.h) (lib/attr.c).
https://github.com/thom311/libnl/blob/master/include/netlink/attr.h
https://github.com/thom311/libnl/blob/master/lib/attr.c

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from ctypes import byref, c_uint16, cast, memset, POINTER, sizeof, Structure

from libnl.linux_private.netlink import nlattr, NLA_ALIGN

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


def nla_ok(nla, remaining):
    """Check if the attribute header and payload can be accessed safely.
    https://github.com/thom311/libnl/blob/master/lib/attr.c#L148

    Verifies that the header and payload do not exceed the number of bytes left in the attribute stream. This function
    must be called before access the attribute header or payload when iterating over the attribute stream using
    nla_next().

    Positional arguments:
    nla -- attribute of any kind.
    remaining -- number of bytes remaining in attribute stream.

    Returns:
    True if the attribute can be accessed safely, False otherwise.
    """
    return remaining >= sizeof(*nla) and sizeof(*nla) <= nla.nla_len <= remaining


def nla_next(nla, remaining):
    """Return next attribute in a stream of attributes.
    https://github.com/thom311/libnl/blob/master/lib/attr.c#L171

    Calculates the offset to the next attribute based on the attribute given. The attribute provided is assumed to be
    accessible, the caller is responsible to use nla_ok() beforehand. The offset (length of specified attribute
    including padding) is then subtracted from the remaining bytes variable and a pointer to the next attribute is
    returned.

    nla_next() can be called as long as remaining is >0.

    Returns:
    Pointer to next attribute.
    """
    totlen = int(NLA_ALIGN(nla.nla_len))
    remaining.value -= totlen
    return cast(byref(nla, totlen), POINTER(nlattr))


def nla_parse(tb, maxtype, head, len_, policy):
    """Create attribute index based on a stream of attributes.
    https://github.com/thom311/libnl/blob/master/lib/attr.c#L242

    Iterates over the stream of attributes and stores a pointer to each attribute in the index array using the attribute
    type as index to the array. Attribute with a type greater than the maximum type specified will be silently ignored
    in order to maintain backwards compatibility. If \a policy is not NULL, the attribute will be validated using the
    specified policy.

    tb -- index array to be filled (maxtype+1 elements).
    maxtype -- maximum attribute type expected and accepted.
    head -- head of attribute stream.
    len_ -- length of attribute stream.
    policy -- attribute validation policy.

    Returns:
    0 on success or a negative error code.
    """
    memset(tb, 0, sizeof(nlattr) * (maxtype + 1))
    # for (pos = head, rem = len_, nla_ok(pos, rem), pos = nla_next(pos, &rem))
