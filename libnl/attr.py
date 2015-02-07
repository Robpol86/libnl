"""Netlink Attributes (netlink/attr.h) (lib/attr.c).
https://github.com/thom311/libnl/blob/master/include/netlink/attr.h
https://github.com/thom311/libnl/blob/master/lib/attr.c

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from ctypes import (byref, c_int, c_uint32, cast, memset, POINTER, sizeof, c_uint8, c_uint16, c_uint64, c_ulong,
                    create_string_buffer)

from libnl.errno_ import NLE_INVAL, NLE_RANGE
from libnl.linux_private.netlink import nlattr, NLA_ALIGN, NLA_TYPE_MASK
from libnl.netlink_private.netlink import BUG

NLA_UNSPEC = 0  # Unspecified type, binary data chunk.
NLA_U8 = 1  # 8 bit integer.
NLA_U16 = 2  # 16 bit integer.
NLA_U32 = 3  # 32 bit integer.
NLA_U64 = 4  # 64 bit integer.
NLA_STRING = 5  # NUL terminated character string.
NLA_FLAG = 6  # Flag.
NLA_MSECS = 7  # Micro seconds (64bit).
NLA_NESTED = 8  # Nested attributes.
NLA_TYPE_MAX = NLA_NESTED


def nla_type(nla):
    """Return type of the attribute.
    https://github.com/thom311/libnl/blob/master/lib/attr.c#L109

    Positional arguments:
    nla -- attribute.

    Returns:
    Type of attribute.
    """
    return nla.nla_type & NLA_TYPE_MASK


def nla_data(nla):
    """Return payload section.
    https://github.com/thom311/libnl/blob/master/lib/attr.c#L120

    Positional arguments:
    nla -- attribute.

    Returns:
    Pointer to start of payload section.
    """
    return nla.payload


def nla_len(nla):
    """Return length of the payload.
    https://github.com/thom311/libnl/blob/master/lib/attr.c#L131

    Positional arguments:
    nla -- attribute.

    Returns:
    Length of payload in bytes.
    """
    return int(nla.nla_len - NLA_HDRLEN)


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


def validate_nla(nla, maxtype, policy):
    """https://github.com/thom311/libnl/blob/master/lib/attr.c#L188

    Positional arguments:
    nla -- attribute.
    maxtype -- maximum attribute type expected and accepted.
    policy -- attribute validation policy.

    Returns:
    Integer.
    """
    minlen = 0
    type_ = nla_type(nla)
    if type_ < 0 or type_ > maxtype:
        return 0
    pt = POINTER(policy[type_])
    if pt.contents.type > NLA_TYPE_MAX:
        raise BUG

    if pt.contents.minlen:
        minlen = pt.contents.minlen
    elif pt.contents.type != NLA_UNSPEC:
        minlen = nla_attr_minlen[pt.contents.type]

    if nla_len(nla) < minlen:
        return -NLE_RANGE
    if pt.contents.maxlen and nla_len(nla) > pt.contents.maxlen:
        return -NLE_RANGE

    if pt.contents.type == NLA_STRING:
        data = byref(nla_data(nla))
        if data[nla_len(nla) - 1] != '\0':
            return -NLE_INVAL

    return 0


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
    nla = nlattr()
    rem = c_int()
    memset(tb, 0, sizeof(nlattr) * (maxtype + 1))
    while nla_for_each_attr(nla, head, len_, rem):
        type_ = nla_type(nla)
        if type_ > maxtype:
            continue
        if policy:
            err = validate_nla(nla, maxtype, policy)
            if err < 0:
                return int(err)
        tb[type_] = nla
    return 0


def nla_for_each_attr(head):
    """Iterate over a list of attributes.
    https://github.com/thom311/libnl/blob/master/include/netlink/attr.h#L262

    Positional arguments:
    head -- list of attributes.

    Returns:
    Generator yielding nl_attr instances.
    """
    return (a for a in head if isinstance(a, nlattr))


def nla_find(attrs, attrtype):
    """Find a single attribute in a list of attributes.
    https://github.com/thom311/libnl/blob/master/lib/attr.c#L323

    Iterates over the stream of attributes and compares each type with the type specified. Returns the first attribute
    which matches the type.

    Positional arguments:
    attrs -- list of attributes or payload containing attributes.
    attrtype -- attribute type to look for.

    Returns:
    Attribute found or None.
    """
    for nla in nla_for_each_attr(attrs):
        if nla_type(nla) == attrtype:
            return nla
    return None


def nla_put(msg, attrtype, data):
    """Add a unspecific attribute to netlink message.
    https://github.com/thom311/libnl/blob/master/lib/attr.c#L497

    Copies the provided data into the message as payload of the attribute.

    Positional arguments:
    msg -- netlink message.
    attrtype -- attribute type.
    data -- data to be used as attribute payload.

    Returns:
    0 on success or a negative error code.
    """
    nla = nlattr(nla_type=attrtype, payload=data)
    msg.nm_nlh.payload.append(nla)
    return 0


def nla_put_u8(msg, attrtype, value):
    """Add 8 bit integer attribute to netlink message.
    https://github.com/thom311/libnl/blob/master/lib/attr.c#L563

    Positional arguments:
    msg -- netlink message (nl_msg class instance).
    attrtype -- attribute type.
    value -- numeric value to store as payload (int() or c_uint8()).

    Returns:
    0 on success or a negative error code.
    """
    return int(nla_put(msg, attrtype, value if isinstance(value, c_uint8) else c_uint8(value)))


def nla_get_u8(nla):
    """Return value of 8 bit integer attribute as an int().
    https://github.com/thom311/libnl/blob/master/lib/attr.c#L574

    Positional arguments:
    nla -- 8 bit integer attribute.

    Returns:
    Payload as an int().
    """
    return int(nla.payload.value if isinstance(nla.payload, c_uint8) else c_uint8(nla.payload.value).value)


def nla_put_u16(msg, attrtype, value):
    """Add 16 bit integer attribute to netlink message.
    https://github.com/thom311/libnl/blob/master/lib/attr.c#L588

    Positional arguments:
    msg -- netlink message (nl_msg class instance).
    attrtype -- attribute type.
    value -- numeric value to store as payload (int() or c_uint16()).

    Returns:
    0 on success or a negative error code.
    """
    return int(nla_put(msg, attrtype, value if isinstance(value, c_uint16) else c_uint16(value)))


def nla_get_u16(nla):
    """Return value of 16 bit integer attribute as an int().
    https://github.com/thom311/libnl/blob/master/lib/attr.c#L599

    Positional arguments:
    nla -- 16 bit integer attribute.

    Returns:
    Payload as an int().
    """
    return int(nla.payload.value if isinstance(nla.payload, c_uint16) else c_uint16(nla.payload.value).value)


def nla_put_u32(msg, attrtype, value):
    """Add 32 bit integer attribute to netlink message.
    https://github.com/thom311/libnl/blob/master/lib/attr.c#L613

    Positional arguments:
    msg -- netlink message (nl_msg class instance).
    attrtype -- attribute type.
    value -- numeric value to store as payload (int() or c_uint32()).

    Returns:
    0 on success or a negative error code.
    """
    return int(nla_put(msg, attrtype, value if isinstance(value, c_uint32) else c_uint32(value)))


def nla_get_u32(nla):
    """Return value of 32 bit integer attribute as an int().
    https://github.com/thom311/libnl/blob/master/lib/attr.c#L624

    Returns:
    Payload as an int().
    """
    return int(nla.payload.value if isinstance(nla.payload, c_uint32) else c_uint32(nla.payload.value).value)


def nla_put_u64(msg, attrtype, value):
    """Add 64 bit integer attribute to netlink message.
    https://github.com/thom311/libnl/blob/master/lib/attr.c#L638

    Positional arguments:
    msg -- netlink message (nl_msg class instance).
    attrtype -- attribute type.
    value -- numeric value to store as payload (int() or c_uint64()).

    Returns:
    0 on success or a negative error code.
    """
    return int(nla_put(msg, attrtype, value if isinstance(value, c_uint64) else c_uint64(value)))


def nla_get_u64(nla):
    """Return value of 64 bit integer attribute as an int().
    https://github.com/thom311/libnl/blob/master/lib/attr.c#L649

    Returns:
    Payload as an int().
    """
    return int(nla.payload.value if isinstance(nla.payload, c_uint64) else c_uint64(nla.payload.value).value)


def nla_put_string(msg, attrtype, value):
    """Add string attribute to netlink message.
    https://github.com/thom311/libnl/blob/master/lib/attr.c#L674

    Positional arguments:
    msg -- netlink message (nl_msg class instance).
    attrtype -- attribute type.
    value -- bytes() string value (e.g. bytes('Test'.encode('ascii'))).

    Returns:
    0 on success or a negative error code.
    """
    return int(nla_put(msg, attrtype, create_string_buffer(value)))


def nla_get_string(nla):
    """Return string attribute.
    https://github.com/thom311/libnl/blob/master/lib/attr.c#L685

    Returns:
    bytes() string value.
    """
    return nla.payload.value


def nla_put_flag(msg, attrtype):
    """Add flag netlink attribute to netlink message.
    https://github.com/thom311/libnl/blob/master/lib/attr.c#L709

    Positional arguments:
    msg -- netlink message (nl_msg class instance).
    attrtype -- attribute type.

    Returns:
    0 on success or a negative error code.
    """
    return int(nla_put(msg, attrtype, None))


def nla_get_flag(nla):
    """Return True if flag attribute is set.
    https://github.com/thom311/libnl/blob/master/lib/attr.c#L720

    Returns:
    True if flag is set, otherwise False.
    """
    return bool(nla)


def nla_put_msecs(msg, attrtype, value):
    """Add msecs attribute to netlink message.
    https://github.com/thom311/libnl/blob/master/lib/attr.c#L737

    Positional arguments:
    msg -- netlink message (nl_msg class instance).
    attrtype -- attribute type.
    value -- numeric msecs (int(), c_uint64(), or c_ulong()).

    Returns:
    0 on success or a negative error code.
    """
    if isinstance(value, c_uint64):
        pass
    elif isinstance(value, c_ulong):
        value = c_uint64(value.value)
    else:
        value = c_uint64(value)
    return int(nla_put_u64(msg, attrtype, value))


def nla_get_msecs(nla):
    """Return value of msecs attribute as an int().
    https://github.com/thom311/libnl/blob/master/lib/attr.c#L748

    Returns:
    Payload as an int().
    """
    return nla_get_u64(nla)
