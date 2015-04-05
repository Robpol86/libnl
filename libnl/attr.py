"""Netlink Attributes (netlink/attr.h) (lib/attr.c).

https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink/attr.h
https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

import logging

from libnl.errno_ import NLE_INVAL, NLE_NOMEM, NLE_RANGE
from libnl.linux_private.netlink import NLA_ALIGN, NLA_F_NESTED, NLA_HDRLEN, NLA_TYPE_MASK, nlattr, NLMSG_ALIGN
from libnl.misc import (bytearray_ptr, c_int, c_uint16, c_uint32, c_uint64, c_uint8, c_ulong, get_string, sizeof,
                        SIZEOF_U16, SIZEOF_U32, SIZEOF_U64, SIZEOF_U8)
from libnl.msg_ import nlmsg_data, nlmsg_datalen, nlmsg_tail
from libnl.netlink_private.netlink import BUG

_LOGGER = logging.getLogger(__name__)
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


def nla_attr_size(payload):
    """Return size of attribute without padding.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L55

     <-------- nla_attr_size(payload) --------->
    +------------------+- - -+- - - - - - - - - +- - -+
    | Attribute Header | Pad |     Payload      | Pad |
    +------------------+- - -+- - - - - - - - - +- - -+

    Positional arguments:
    payload -- payload length of attribute (integer).

    Returns:
    Size of attribute in bytes without padding (integer).
    """
    return int(NLA_HDRLEN + payload)


class nla_policy(object):
    """Attribute validation policy.

    https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink/attr.h#L60

    Instance variables:
    type_ -- type of attribute or NLA_UNSPEC (c_uint16).
    minlen -- minimal length of payload required (c_uint16).
    maxlen -- maximal length of payload allowed (c_uint16).
    """

    def __init__(self, type_=0, minlen=0, maxlen=0):
        """Constructor."""
        self.type_ = type_
        self.minlen = minlen
        self.maxlen = maxlen

    def __repr__(self):
        """repr() handler."""
        answer = '<{0}.{1} type_={2} minlen={3} maxlen={4}>'.format(
            self.__class__.__module__,
            self.__class__.__name__,
            self.type_, self.minlen, self.maxlen,
        )
        return answer


def nla_total_size(payload):
    """Return size of attribute including padding.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L73

     <----------- nla_total_size(payload) ----------->
    +------------------+- - -+- - - - - - - - - +- - -+
    | Attribute Header | Pad |     Payload      | Pad |
    +------------------+- - -+- - - - - - - - - +- - -+

    Positional arguments:
    payload -- payload length of attribute (integer).

    Returns:
    Size of attribute in bytes (integer).
    """
    return int(NLA_ALIGN(nla_attr_size(payload)))


def nla_padlen(payload):
    """Return length of padding at the tail of the attribute.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L91

    +------------------+- - -+- - - - - - - - - +- - -+
    | Attribute Header | Pad |     Payload      | Pad |
    +------------------+- - -+- - - - - - - - - +- - -+
                                                 <--->

    Positional arguments:
    payload -- payload length of attribute (integer).

    Returns:
    Length of padding in bytes (integer).
    """
    return int(nla_total_size(payload) - nla_attr_size(payload))


def nla_type(nla):
    """Return type of the attribute.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L109

    Positional arguments:
    nla -- attribute (nlattr class instance).

    Returns:
    Type of attribute.
    """
    return int(nla.nla_type & NLA_TYPE_MASK)


def nla_data(nla):
    """Return bytearray_ptr of the payload data.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L120

    Positional arguments:
    nla -- attribute (nlattr class instance).

    Returns:
    Bytearray payload data.
    """
    return bytearray_ptr(nla.bytearray, NLA_HDRLEN)


def nla_len(nla):
    """Return length of the payload.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L131

    Positional arguments:
    nla -- attribute (nlattr class instance).

    Returns:
    Length of payload in bytes.
    """
    return int(nla.nla_len - NLA_HDRLEN)


def nla_ok(nla, remaining):
    """Check if the attribute header and payload can be accessed safely.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L148

    Verifies that the header and payload do not exceed the number of bytes left in the attribute stream. This function
    must be called before access the attribute header or payload when iterating over the attribute stream using
    nla_next().

    Positional arguments:
    nla -- attribute of any kind (nlattr class instance).
    remaining -- number of bytes remaining in attribute stream (c_int).

    Returns:
    True if the attribute can be accessed safely, False otherwise.
    """
    return remaining.value >= nla.SIZEOF and nla.SIZEOF <= nla.nla_len <= remaining.value


def nla_next(nla, remaining):
    """Return next attribute in a stream of attributes.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L171

    Calculates the offset to the next attribute based on the attribute given. The attribute provided is assumed to be
    accessible, the caller is responsible to use nla_ok() beforehand. The offset (length of specified attribute
    including padding) is then subtracted from the remaining bytes variable and a pointer to the next attribute is
    returned.

    nla_next() can be called as long as remaining is >0.

    Positional arguments:
    nla -- attribute of any kind (nlattr class instance).
    remaining -- number of bytes remaining in attribute stream (c_int).

    Returns:
    Next nlattr class instance.
    """
    totlen = int(NLA_ALIGN(nla.nla_len))
    remaining.value -= totlen
    return nlattr(bytearray_ptr(nla.bytearray, totlen))


nla_attr_minlen = dict((i, 0) for i in range(NLA_TYPE_MAX + 1))
nla_attr_minlen.update({  # https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L179
    NLA_U8: SIZEOF_U8,
    NLA_U16: SIZEOF_U16,
    NLA_U32: SIZEOF_U32,
    NLA_U64: SIZEOF_U64,
    NLA_STRING: 1,
    NLA_FLAG: 0,
})


def validate_nla(nla, maxtype, policy):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L188.

    Positional arguments:
    nla -- nlattr class instance.
    maxtype -- integer.
    policy -- dictionary of nla_policy class instances as values, with nla types as keys.

    Returns:
    0 on success or a negative error code.
    """
    minlen = 0
    type_ = nla_type(nla)
    if type_ < 0 or type_ > maxtype:
        return 0

    pt = policy[type_]
    if pt.type_ > NLA_TYPE_MAX:
        raise BUG

    if pt.minlen:
        minlen = pt.minlen
    elif pt.type_ != NLA_UNSPEC:
        minlen = nla_attr_minlen[pt.type_]

    if nla_len(nla) < minlen:
        return -NLE_RANGE

    if pt.maxlen and nla_len(nla) > pt.maxlen:
        return -NLE_RANGE

    if pt.type_ == NLA_STRING:
        data = nla_data(nla)
        if data[nla_len(nla) - 1] != 0:
            return -NLE_INVAL

    return 0


def nla_parse(tb, maxtype, head, len_, policy):
    """Create attribute index based on a stream of attributes.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L242

    Iterates over the stream of attributes and stores a pointer to each attribute in the index array using the attribute
    type as index to the array. Attribute with a type greater than the maximum type specified will be silently ignored
    in order to maintain backwards compatibility. If `policy` is not None, the attribute will be validated using the
    specified policy.

    Positional arguments:
    tb -- dictionary to be filled (maxtype+1 elements).
    maxtype -- maximum attribute type expected and accepted (integer).
    head -- first nlattr with more in its bytearray payload (nlattr class instance).
    len_ -- length of attribute stream (integer).
    policy -- dictionary of nla_policy class instances as values, with nla types as keys.

    Returns:
    0 on success or a negative error code.
    """
    rem = c_int()
    for nla in nla_for_each_attr(head, len_, rem):
        type_ = nla_type(nla)
        if type_ > maxtype:
            continue

        if policy:
            err = validate_nla(nla, maxtype, policy)
            if err < 0:
                return err

        if type_ in tb and tb[type_]:
            _LOGGER.debug('Attribute of type %d found multiple times in message, previous attribute is being ignored.',
                          type_)
        tb[type_] = nla

    if rem.value > 0:
        _LOGGER.debug('netlink: %d bytes leftover after parsing attributes.', rem.value)

    return 0


def nla_for_each_attr(head, len_, rem):
    """Iterate over a stream of attributes.

    https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink/attr.h#L262

    Positional arguments:
    head -- first nlattr with more in its bytearray payload (nlattr class instance).
    len_ -- length of attribute stream (integer).
    rem -- initialized to len, holds bytes currently remaining in stream (c_int).

    Returns:
    Generator yielding nlattr instances.
    """
    pos = head
    rem.value = len_
    while nla_ok(pos, rem):
        yield pos
        pos = nla_next(pos, rem)


def nla_for_each_nested(nla, rem):
    """Iterate over a stream of nested attributes.

    https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink/attr.h#L274

    Positional arguments:
    nla -- attribute containing the nested attributes (nlattr class instance).
    rem -- initialized to len, holds bytes currently remaining in stream (c_int).

    Returns:
    Generator yielding nlattr instances.
    """
    pos = nlattr(nla_data(nla))
    rem.value = nla_len(nla)
    while nla_ok(pos, rem):
        yield pos
        pos = nla_next(pos, rem)


def nla_find(head, len_, attrtype):
    """Find a single attribute in a stream of attributes.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L323

    Iterates over the stream of attributes and compares each type with the type specified. Returns the first attribute
    which matches the type.

    Positional arguments:
    head -- first nlattr with more in its bytearray payload (nlattr class instance).
    len_ -- length of attributes stream (integer).
    attrtype -- attribute type to look for (integer).

    Returns:
    Attribute found (nlattr class instance) or None.
    """
    rem = c_int()
    for nla in nla_for_each_attr(head, len_, rem):
        if nla_type(nla) == attrtype:
            return nla
    return None


def nla_reserve(msg, attrtype, attrlen):
    """Reserve space for an attribute.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L456

    Reserves room for an attribute in the specified Netlink message and fills in the attribute header (type, length).
    Returns None if there is insufficient space for the attribute.

    Any padding between payload and the start of the next attribute is zeroed out.

    Positional arguments:
    msg -- Netlink message (nl_msg class instance).
    attrtype -- attribute type (integer).
    attrlen -- length of payload (integer).

    Returns:
    nlattr class instance allocated to the new space or None on failure.
    """
    tlen = NLMSG_ALIGN(msg.nm_nlh.nlmsg_len) + nla_total_size(attrlen)
    if tlen > msg.nm_size:
        return None

    nla = nlattr(nlmsg_tail(msg.nm_nlh))
    nla.nla_type = attrtype
    nla.nla_len = nla_attr_size(attrlen)

    if attrlen:
        padlen = nla_padlen(attrlen)
        nla.bytearray[nla.nla_len:nla.nla_len + padlen] = bytearray(b'\0') * padlen
    msg.nm_nlh.nlmsg_len = tlen

    _LOGGER.debug('msg 0x%x: attr <0x%x> %d: Reserved %d (%d) bytes at offset +%d nlmsg_len=%d', id(msg), id(nla),
                  nla.nla_type, nla_total_size(attrlen), attrlen,
                  nla.bytearray.slice.start - nlmsg_data(msg.nm_nlh).slice.start, msg.nm_nlh.nlmsg_len)

    return nla


def nla_put(msg, attrtype, datalen, data):
    """Add a unspecific attribute to Netlink message.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L497

    Reserves room for an unspecific attribute and copies the provided data into the message as payload of the attribute.
    Returns an error if there is insufficient space for the attribute.

    Positional arguments:
    msg -- Netlink message (nl_msg class instance).
    attrtype -- attribute type (integer).
    datalen -- length of data to be used as payload (integer).
    data -- data to be used as attribute payload (bytearray).

    Returns:
    0 on success or a negative error code.
    """
    nla = nla_reserve(msg, attrtype, datalen)
    if not nla:
        return -NLE_NOMEM
    if datalen <= 0:
        return 0

    nla_data(nla)[:datalen] = data[:datalen]
    _LOGGER.debug('msg 0x%x: attr <0x%x> %d: Wrote %d bytes at offset +%d', id(msg), id(nla), nla.nla_type, datalen,
                  nla.bytearray.slice.start - nlmsg_data(msg.nm_nlh).slice.start)
    return 0


def nla_put_data(msg, attrtype, data):
    """Add abstract data as unspecific attribute to Netlink message.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L527

    Equivalent to nla_put() except that the length of the payload is derived from the bytearray data object.

    Positional arguments:
    msg -- Netlink message (nl_msg class instance).
    attrtype -- attribute type (integer).
    data -- data to be used as attribute payload (bytearray).

    Returns:
    0 on success or a negative error code.
    """
    return nla_put(msg, attrtype, len(data), data)


def nla_put_u8(msg, attrtype, value):
    """Add 8 bit integer attribute to Netlink message.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L563

    Positional arguments:
    msg -- Netlink message (nl_msg class instance).
    attrtype -- attribute type (integer).
    value -- numeric value to store as payload (int() or c_uint8()).

    Returns:
    0 on success or a negative error code.
    """
    data = bytearray(value if isinstance(value, c_uint8) else c_uint8(value))
    return nla_put(msg, attrtype, SIZEOF_U8, data)


def nla_get_u8(nla):
    """Return value of 8 bit integer attribute as an int().

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L574

    Positional arguments:
    nla -- 8 bit integer attribute (nlattr class instance).

    Returns:
    Payload as an int().
    """
    return int(c_uint8.from_buffer(nla_data(nla)[:SIZEOF_U8]).value)


def nla_put_u16(msg, attrtype, value):
    """Add 16 bit integer attribute to Netlink message.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L588

    Positional arguments:
    msg -- Netlink message (nl_msg class instance).
    attrtype -- attribute type (integer).
    value -- numeric value to store as payload (int() or c_uint16()).

    Returns:
    0 on success or a negative error code.
    """
    data = bytearray(value if isinstance(value, c_uint16) else c_uint16(value))
    return nla_put(msg, attrtype, SIZEOF_U16, data)


def nla_get_u16(nla):
    """Return value of 16 bit integer attribute as an int().

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L599

    Positional arguments:
    nla -- 16 bit integer attribute (nlattr class instance).

    Returns:
    Payload as an int().
    """
    return int(c_uint16.from_buffer(nla_data(nla)[:SIZEOF_U16]).value)


def nla_put_u32(msg, attrtype, value):
    """Add 32 bit integer attribute to Netlink message.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L613

    Positional arguments:
    msg -- Netlink message (nl_msg class instance).
    attrtype -- attribute type (integer).
    value -- numeric value to store as payload (int() or c_uint32()).

    Returns:
    0 on success or a negative error code.
    """
    data = bytearray(value if isinstance(value, c_uint32) else c_uint32(value))
    return nla_put(msg, attrtype, SIZEOF_U32, data)


def nla_get_u32(nla):
    """Return value of 32 bit integer attribute as an int().

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L624

    Positional arguments:
    nla -- 32 bit integer attribute (nlattr class instance).

    Returns:
    Payload as an int().
    """
    return int(c_uint32.from_buffer(nla_data(nla)[:SIZEOF_U32]).value)


def nla_put_u64(msg, attrtype, value):
    """Add 64 bit integer attribute to Netlink message.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L638

    Positional arguments:
    msg -- Netlink message (nl_msg class instance).
    attrtype -- attribute type (integer).
    value -- numeric value to store as payload (int() or c_uint64()).

    Returns:
    0 on success or a negative error code.
    """
    data = bytearray(value if isinstance(value, c_uint64) else c_uint64(value))
    return nla_put(msg, attrtype, SIZEOF_U64, data)


def nla_get_u64(nla):
    """Return value of 64 bit integer attribute as an int().

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L649

    Positional arguments:
    nla -- 64 bit integer attribute (nlattr class instance).

    Returns:
    Payload as an int().
    """
    tmp = c_uint64(0)
    if nla and nla_len(nla) >= sizeof(tmp):
        tmp = c_uint64.from_buffer(nla_data(nla)[:SIZEOF_U64])
    return int(tmp.value)


def nla_put_string(msg, attrtype, value):
    """Add string attribute to Netlink message.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L674

    Positional arguments:
    msg -- Netlink message (nl_msg class instance).
    attrtype -- attribute type (integer).
    value -- bytes() or bytearray() value (e.g. 'Test'.encode('ascii')).

    Returns:
    0 on success or a negative error code.
    """
    data = bytearray(value) + bytearray(b'\0')
    return nla_put(msg, attrtype, len(data), data)


def nla_get_string(nla):
    """Return string attribute.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L685

    Positional arguments:
    nla -- string attribute (nlattr class instance).

    Returns:
    bytes() value.
    """
    return get_string(nla_data(nla))


def nla_put_flag(msg, attrtype):
    """Add flag Netlink attribute to Netlink message.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L709

    Positional arguments:
    msg -- Netlink message (nl_msg class instance).
    attrtype -- attribute type (integer).

    Returns:
    0 on success or a negative error code.
    """
    return nla_put(msg, attrtype, 0, None)


def nla_get_flag(nla):
    """Return True if flag attribute is set.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L720

    Positional arguments:
    nla -- flag Netlink attribute (nlattr class instance).

    Returns:
    True if flag is set, otherwise False.
    """
    return not not nla


def nla_put_msecs(msg, attrtype, msecs):
    """Add msecs Netlink attribute to Netlink message.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L737

    Positional arguments:
    msg -- Netlink message (nl_msg class instance).
    attrtype -- attribute type (integer).
    msecs -- number of msecs (int(), c_uint64(), or c_ulong()).

    Returns:
    0 on success or a negative error code.
    """
    if isinstance(msecs, c_uint64):
        pass
    elif isinstance(msecs, c_ulong):
        msecs = c_uint64(msecs.value)
    else:
        msecs = c_uint64(msecs)
    return nla_put_u64(msg, attrtype, msecs)


def nla_get_msecs(nla):
    """Return payload of msecs attribute as an int().

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L748

    Positional arguments:
    nla -- msecs Netlink attribute (nlattr class instance).

    Returns:
    The number of milliseconds (integer).
    """
    return nla_get_u64(nla)


def nla_put_nested(msg, attrtype, nested):
    """Add nested attributes to Netlink message.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L772

    Takes the attributes found in the `nested` message and appends them to the message `msg` nested in a container of
    the type `attrtype`. The `nested` message may not have a family specific header.

    Positional arguments:
    msg -- Netlink message (nl_msg class instance).
    attrtype -- attribute type (integer).
    nested -- message containing attributes to be nested (nl_msg class instance).

    Returns:
    0 on success or a negative error code.
    """
    _LOGGER.debug('msg 0x%x: attr <> %d: adding msg 0x%x as nested attribute', id(msg), attrtype, id(nested))
    return nla_put(msg, attrtype, nlmsg_datalen(nested.nm_nlh), nlmsg_data(nested.nm_nlh))


def nla_parse_nested(tb, maxtype, nla, policy):
    """Create attribute index based on nested attribute.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L885

    Feeds the stream of attributes nested into the specified attribute to nla_parse().

    Positional arguments:
    tb -- dictionary to be filled (maxtype+1 elements).
    maxtype -- maximum attribute type expected and accepted (integer).
    nla -- nested attribute (nlattr class instance).
    policy -- attribute validation policy.

    Returns:
    0 on success or a negative error code.
    """
    return nla_parse(tb, maxtype, nlattr(nla_data(nla)), nla_len(nla), policy)


def nla_is_nested(attr):
    """Return True if attribute has NLA_F_NESTED flag set.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/attr.c#L897

    Positional arguments:
    attr -- Netlink attribute (nlattr class instance).

    Returns:
    True if attribute has NLA_F_NESTED flag set, otherwise False.
    """
    return not not attr.nla_type & NLA_F_NESTED
