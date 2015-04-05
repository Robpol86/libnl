"""Netlink Messages Interface (lib/msg.c).

https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c
https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink/msg.h

Netlink message construction/parsing interface.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

import logging
import os
import resource
import string

import libnl.linux_private.netlink
from libnl.attr import nla_data, nla_find, nla_for_each_attr, nla_is_nested, nla_len, nla_padlen, nla_parse
from libnl.cache_mngt import nl_cache_ops_associate_safe, nl_msgtype_lookup
from libnl.errno_ import NLE_MSG_TOOSHORT, NLE_NOMEM
from libnl.linux_private.genetlink import GENL_HDRLEN, genlmsghdr
from libnl.misc import bytearray_ptr, c_int
from libnl.msg_ import nlmsg_data, nlmsg_len
from libnl.netlink_private.netlink import BUG
from libnl.netlink_private.types import nl_msg, NL_MSG_CRED_PRESENT
from libnl.utils import __type2str

_LOGGER = logging.getLogger(__name__)
default_msg_size = resource.getpagesize()
NL_AUTO_PORT = 0
NL_AUTO_PID = NL_AUTO_PORT
NL_AUTO_SEQ = 0


def nlmsg_size(payload):
    """Calculate size of Netlink message based on payload length.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L54

    Positional arguments:
    payload -- length of payload (integer).

    Returns:
    Size of Netlink message without padding (integer).
    """
    return int(libnl.linux_private.netlink.NLMSG_HDRLEN + payload)


nlmsg_msg_size = nlmsg_size  # Alias. https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L59


def nlmsg_total_size(payload):
    """Calculate size of Netlink message including padding based on payload length.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L72

    This function is identical to nlmsg_size() + nlmsg_padlen().

    Positional arguments:
    payload -- length of payload (integer).

    Returns:
    Size of Netlink message including padding (integer).
    """
    return int(libnl.linux_private.netlink.NLMSG_ALIGN(nlmsg_msg_size(payload)))


def nlmsg_for_each_attr(nlh, hdrlen, rem):
    """Iterate over a stream of attributes in a message.

    https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink/msg.h#L123

    Positional arguments:
    nlh -- Netlink message header (nlmsghdr class instance).
    hdrlen -- length of family header (integer).
    rem -- initialized to len, holds bytes currently remaining in stream (c_int).

    Returns:
    Generator yielding nl_attr instances.
    """
    return nla_for_each_attr(nlmsg_attrdata(nlh, hdrlen), nlmsg_attrlen(nlh, hdrlen), rem)


def nlmsg_attrdata(nlh, hdrlen):
    """Head of attributes data.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L143

    Positional arguments:
    nlh -- Netlink message header (nlmsghdr class instance).
    hdrlen -- length of family specific header (integer).

    Returns:
    First attribute (nlattr class instance with others in its payload).
    """
    data = nlmsg_data(nlh)
    return libnl.linux_private.netlink.nlattr(bytearray_ptr(data, libnl.linux_private.netlink.NLMSG_ALIGN(hdrlen)))


def nlmsg_attrlen(nlh, hdrlen):
    """Length of attributes data.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L154

    nlh -- Netlink message header (nlmsghdr class instance).
    hdrlen -- length of family specific header (integer).

    Returns:
    Integer.
    """
    return max(nlmsg_len(nlh) - libnl.linux_private.netlink.NLMSG_ALIGN(hdrlen), 0)


def nlmsg_valid_hdr(nlh, hdrlen):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L166.

    Positional arguments:
    nlh -- Netlink message header (nlmsghdr class instance).
    hdrlen -- integer.

    Returns True if valid, False otherwise.
    """
    return not nlh.nlmsg_len < nlmsg_msg_size(hdrlen)


def nlmsg_ok(nlh, remaining):
    """Check if the Netlink message fits into the remaining bytes.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L179

    Positional arguments:
    nlh -- Netlink message header (nlmsghdr class instance).
    remaining -- number of bytes remaining in message stream (c_int).

    Returns:
    Boolean.
    """
    sizeof = libnl.linux_private.netlink.nlmsghdr.SIZEOF
    return remaining.value >= sizeof and sizeof <= nlh.nlmsg_len <= remaining.value


def nlmsg_next(nlh, remaining):
    """Next Netlink message in message stream.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L194

    Positional arguments:
    nlh -- Netlink message header (nlmsghdr class instance).
    remaining -- number of bytes remaining in message stream (c_int).

    Returns:
    The next Netlink message in the message stream and decrements remaining by the size of the current message.
    """
    totlen = libnl.linux_private.netlink.NLMSG_ALIGN(nlh.nlmsg_len)
    remaining.value -= totlen
    return libnl.linux_private.netlink.nlmsghdr(bytearray_ptr(nlh.bytearray, totlen))


def nlmsg_parse(nlh, hdrlen, tb, maxtype, policy):
    """Parse attributes of a Netlink message.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L213

    Positional arguments:
    nlh -- Netlink message header (nlmsghdr class instance).
    hdrlen -- length of family specific header (integer).
    tb -- dictionary of nlattr instances (length of maxtype+1).
    maxtype -- maximum attribute type to be expected (integer).
    policy -- validation policy (nla_policy class instance).

    Returns:
    0 on success or a negative error code.
    """
    if not nlmsg_valid_hdr(nlh, hdrlen):
        return -NLE_MSG_TOOSHORT
    return nla_parse(tb, maxtype, nlmsg_attrdata(nlh, hdrlen), nlmsg_attrlen(nlh, hdrlen), policy)


def nlmsg_find_attr(nlh, hdrlen, attrtype):
    """Find a specific attribute in a Netlink message.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L231

    Positional arguments:
    nlh -- Netlink message header (nlmsghdr class instance).
    hdrlen -- length of family specific header (integer).
    attrtype -- type of attribute to look for (integer).

    Returns:
    The first attribute which matches the specified type (nlattr class instance).
    """
    return nla_find(nlmsg_attrdata(nlh, hdrlen), nlmsg_attrlen(nlh, hdrlen), attrtype)


def nlmsg_alloc(len_=default_msg_size):
    """Allocate a new Netlink message with maximum payload size specified.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L299

    Allocates a new Netlink message without any further payload. The maximum payload size defaults to
    resource.getpagesize() or as otherwise specified with nlmsg_set_default_size().

    Returns:
    Newly allocated Netlink message (nl_msg class instance).
    """
    len_ = max(libnl.linux_private.netlink.nlmsghdr.SIZEOF, len_)
    nm = nl_msg()
    nm.nm_refcnt = 1
    nm.nm_nlh = libnl.linux_private.netlink.nlmsghdr(bytearray(b'\0') * len_)
    nm.nm_protocol = -1
    nm.nm_size = len_
    nm.nm_nlh.nlmsg_len = nlmsg_total_size(0)
    _LOGGER.debug('msg 0x%x: Allocated new message, maxlen=%d', id(nm), len_)
    return nm


nlmsg_alloc_size = nlmsg_alloc  # Alias. https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L307


def nlmsg_inherit(hdr=None):
    """Allocate a new Netlink message and inherit Netlink message header.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L322

    Allocates a new Netlink message and inherits the original message header. If `hdr` is not None it will be used as a
    template for the Netlink message header, otherwise the header is left blank.

    Keyword arguments:
    hdr -- Netlink message header template (nlmsghdr class instance).

    Returns:
    Newly allocated Netlink message (nl_msg class instance).
    """
    nm = nlmsg_alloc()
    if hdr:
        new = nm.nm_nlh
        new.nlmsg_type = hdr.nlmsg_type
        new.nlmsg_flags = hdr.nlmsg_flags
        new.nlmsg_seq = hdr.nlmsg_seq
        new.nlmsg_pid = hdr.nlmsg_pid
    return nm


def nlmsg_alloc_simple(nlmsgtype, flags):
    """Allocate a new Netlink message.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L346

    Positional arguments:
    nlmsgtype -- Netlink message type (integer).
    flags -- message flags (integer).

    Returns:
    Newly allocated Netlink message (nl_msg class instance) or None.
    """
    nlh = libnl.linux_private.netlink.nlmsghdr(nlmsg_type=nlmsgtype, nlmsg_flags=flags)
    msg = nlmsg_inherit(nlh)
    _LOGGER.debug('msg 0x%x: Allocated new simple message', id(msg))
    return msg


def nlmsg_set_default_size(max_):
    """Set the default maximum message payload size for allocated messages.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L365

    Positional arguments:
    max_ -- size of payload in bytes (integer).
    """
    global default_msg_size
    default_msg_size = max(nlmsg_total_size(0), max_)


def nlmsg_convert(hdr):
    """Convert a Netlink message received from a Netlink socket to an nl_msg.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L382

    Allocates a new Netlink message and copies all of the data in `hdr` into the new message object.

    Positional arguments:
    hdr -- Netlink message received from netlink socket (nlmsghdr class instance).

    Returns:
    Newly allocated Netlink message (nl_msg class instance) or None.
    """
    nm = nlmsg_alloc(hdr.nlmsg_len)
    if not nm:
        return None
    nm.nm_nlh.bytearray = hdr.bytearray.copy()[:hdr.nlmsg_len]
    return nm


def nlmsg_reserve(n, len_, pad):
    """Reserve room for additional data in a Netlink message.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L407

    Reserves room for additional data at the tail of the an existing netlink message. Eventual padding required will be
    zeroed out.

    bytearray_ptr() at the start of additional data or None.
    """
    nlmsg_len_ = n.nm_nlh.nlmsg_len
    tlen = len_ if not pad else ((len_ + (pad - 1)) & ~(pad - 1))

    if tlen + nlmsg_len_ > n.nm_size:
        return None

    buf = bytearray_ptr(n.nm_nlh.bytearray, nlmsg_len_)
    n.nm_nlh.nlmsg_len += tlen
    if tlen > len_:
        bytearray_ptr(buf, len_, tlen)[:] = bytearray(b'\0') * (tlen - len_)

    _LOGGER.debug('msg 0x%x: Reserved %d (%d) bytes, pad=%d, nlmsg_len=%d', id(n), tlen, len_, pad, n.nm_nlh.nlmsg_len)
    return buf


def nlmsg_append(n, data, len_, pad):
    """Append data to tail of a Netlink message.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L442

    Extends the Netlink message as needed and appends the data of given length to the message.

    Positional arguments:
    n -- Netlink message (nl_msg class instance).
    data -- data to add.
    len_ -- length of data (integer).
    pad -- number of bytes to align data to (integer).

    Returns:
    0 on success or a negative error code.
    """
    tmp = nlmsg_reserve(n, len_, pad)
    if tmp is None:
        return -NLE_NOMEM
    tmp[:len_] = data.bytearray[:len_]
    _LOGGER.debug('msg 0x%x: Appended %d bytes with padding %d', id(n), len_, pad)
    return 0


def nlmsg_put(n, pid, seq, type_, payload, flags):
    """Add a Netlink message header to a Netlink message.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L503

    Adds or overwrites the Netlink message header in an existing message object.

    Positional arguments:
    n -- Netlink message (nl_msg class instance).
    pid -- Netlink process id or NL_AUTO_PID (c_uint32).
    seq -- sequence number of message or NL_AUTO_SEQ (c_uint32).
    type_ -- message type (integer).
    payload -- length of message payload (integer).
    flags -- message flags (integer).

    Returns:
    nlmsghdr class instance or None.
    """
    if n.nm_nlh.nlmsg_len < libnl.linux_private.netlink.NLMSG_HDRLEN:
        raise BUG

    nlh = n.nm_nlh
    nlh.nlmsg_type = type_
    nlh.nlmsg_flags = flags
    nlh.nlmsg_pid = pid
    nlh.nlmsg_seq = seq

    _LOGGER.debug('msg 0x%x: Added netlink header type=%d, flags=%d, pid=%d, seq=%d', id(n), type_, flags, pid, seq)

    if payload > 0 and nlmsg_reserve(n, payload, libnl.linux_private.netlink.NLMSG_ALIGNTO) is None:
        return None

    return nlh


def nlmsg_hdr(msg):
    """Return actual Netlink message.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L536

    Returns the actual Netlink message casted to a nlmsghdr class instance.

    Positional arguments:
    msg -- Netlink message (nl_msg class instance).

    Returns:
    nlmsghdr class instance.
    """
    return msg.nm_nlh


def nlmsg_set_proto(msg, protocol):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L584.

    Positional arguments:
    msg -- Netlink message (nl_msg class instance).
    protocol -- integer.
    """
    msg.nm_protocol = protocol


def nlmsg_set_src(msg, addr):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L599."""
    msg.nm_src = addr


def nlmsg_get_dst(msg):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L614."""
    return msg.nm_dst


def nlmsg_get_creds(msg):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L625."""
    if msg.nm_flags & NL_MSG_CRED_PRESENT:
        return msg.nm_creds
    return None


nl_msgtypes = {
    libnl.linux_private.netlink.NLMSG_NOOP: 'NOOP',
    libnl.linux_private.netlink.NLMSG_ERROR: 'ERROR',
    libnl.linux_private.netlink.NLMSG_DONE: 'DONE',
    libnl.linux_private.netlink.NLMSG_OVERRUN: 'OVERRUN',
}


def nl_nlmsgtype2str(type_, buf, size):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L646.

    Positional arguments:
    type_ -- integer (e.g. nlh.nlmsg_type).
    buf -- bytearray().
    size -- integer.

    Returns:
    Reference to `buf`.
    """
    return __type2str(type_, buf, size, nl_msgtypes)


def nl_nlmsg_flags2str(flags, buf, _=None):
    """Netlink Message Flags Translations.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L664

    Positional arguments:
    flags -- integer.
    buf -- bytearray().

    Keyword arguments:
    _ -- unused.

    Returns:
    Reference to `buf`.
    """
    del buf[:]
    all_flags = (
        ('REQUEST', libnl.linux_private.netlink.NLM_F_REQUEST),
        ('MULTI', libnl.linux_private.netlink.NLM_F_MULTI),
        ('ACK', libnl.linux_private.netlink.NLM_F_ACK),
        ('ECHO', libnl.linux_private.netlink.NLM_F_ECHO),
        ('ROOT', libnl.linux_private.netlink.NLM_F_ROOT),
        ('MATCH', libnl.linux_private.netlink.NLM_F_MATCH),
        ('ATOMIC', libnl.linux_private.netlink.NLM_F_ATOMIC),
        ('REPLACE', libnl.linux_private.netlink.NLM_F_REPLACE),
        ('EXCL', libnl.linux_private.netlink.NLM_F_EXCL),
        ('CREATE', libnl.linux_private.netlink.NLM_F_CREATE),
        ('APPEND', libnl.linux_private.netlink.NLM_F_APPEND),
    )
    print_flags = []
    for k, v in all_flags:
        if not flags & v:
            continue
        flags &= ~v
        print_flags.append(k)
    if flags:
        print_flags.append('0x{0:x}'.format(flags))
    buf.extend(','.join(print_flags).encode('ascii'))
    return buf


def dump_hex(ofd, start, len_, prefix=0):
    """Convert `start` to hex and logs it, 16 bytes per log statement.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L760

    Positional arguments:
    ofd -- function to call with arguments similar to `logging.debug`.
    start -- bytearray() or bytearray_ptr() instance.
    len_ -- size of `start` (integer).

    Keyword arguments:
    prefix -- additional number of whitespace pairs to prefix each log statement with.
    """
    prefix_whitespaces = '  ' * prefix
    limit = 16 - (prefix * 2)
    start_ = start[:len_]
    for line in (start_[i:i + limit] for i in range(0, len(start_), limit)):  # stackoverflow.com/a/9475354/1198943
        hex_lines, ascii_lines = list(), list()
        for c in line:
            hex_lines.append('{0:02x}'.format(c if hasattr(c, 'real') else ord(c)))
            c2 = chr(c) if hasattr(c, 'real') else c
            ascii_lines.append(c2 if c2 in string.printable[:95] else '.')
        hex_line = ' '.join(hex_lines).ljust(limit * 3)
        ascii_line = ''.join(ascii_lines)
        ofd('    %s%s%s', prefix_whitespaces, hex_line, ascii_line)


def print_hdr(ofd, msg):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L793.

    Positional arguments:
    ofd -- function to call with arguments similar to `logging.debug`.
    msg -- message to print (nl_msg class instance).
    """
    nlh = nlmsg_hdr(msg)
    buf = bytearray()

    ofd('    .nlmsg_len = %d', nlh.nlmsg_len)

    ops = nl_cache_ops_associate_safe(msg.nm_protocol, nlh.nlmsg_type)
    if ops:
        mt = nl_msgtype_lookup(ops, nlh.nlmsg_type)
        if not mt:
            raise BUG
        buf.extend('{0}::{1}'.format(ops.co_name, mt.mt_name).encode('ascii'))
    else:
        nl_nlmsgtype2str(nlh.nlmsg_type, buf, 128)

    ofd('    .type = %d <%s>', nlh.nlmsg_type, buf.decode('ascii'))
    ofd('    .flags = %d <%s>', nlh.nlmsg_flags, nl_nlmsg_flags2str(nlh.nlmsg_flags, buf, 128).decode('ascii'))
    ofd('    .seq = %d', nlh.nlmsg_seq)
    ofd('    .port = %d', nlh.nlmsg_pid)


def print_genl_hdr(ofd, start):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L821.

    Positional arguments:
    ofd -- function to call with arguments similar to `logging.debug`.
    start -- bytearray() or bytearray_ptr() instance.
    """
    ghdr = genlmsghdr(start)
    ofd('  [GENERIC NETLINK HEADER] %d octets', GENL_HDRLEN)
    ofd('    .cmd = %d', ghdr.cmd)
    ofd('    .version = %d', ghdr.version)
    ofd('    .unused = %#d', ghdr.reserved)


def print_genl_msg(_, ofd, hdr, ops, payloadlen):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L831.

    Positional arguments:
    _ -- unused.
    ofd -- function to call with arguments similar to `logging.debug`.
    hdr -- Netlink message header (nlmsghdr class instance).
    ops -- cache operations (nl_cache_ops class instance).
    payloadlen -- length of payload in message (ctypes.c_int instance).

    Returns:
    data (bytearray_ptr).
    """
    data = nlmsg_data(hdr)
    if payloadlen.value < GENL_HDRLEN:
        return data

    print_genl_hdr(ofd, data)
    payloadlen.value -= GENL_HDRLEN
    data = bytearray_ptr(data, GENL_HDRLEN)

    if ops:
        hdrsize = ops.co_hdrsize - GENL_HDRLEN
        if hdrsize > 0:
            if payloadlen.value < hdrsize:
                return data
            ofd('  [HEADER] %d octets', hdrsize)
            dump_hex(ofd, data, hdrsize, 0)
            payloadlen.value -= hdrsize
            data = bytearray_ptr(data, hdrsize)

    return data


def dump_attr(ofd, attr, prefix=0):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L862.

    Positional arguments:
    ofd -- function to call with arguments similar to `logging.debug`.
    attr -- nlattr class instance.

    Keyword arguments:
    prefix -- additional number of whitespace pairs to prefix each log statement with.
    """
    dump_hex(ofd, nla_data(attr), nla_len(attr), prefix)


def dump_attrs(ofd, attrs, attrlen, prefix=0):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L869.

    Positional arguments:
    ofd -- function to call with arguments similar to `logging.debug`.
    attrs -- nlattr class instance.
    attrlen -- length of payload (integer).

    Keyword arguments:
    prefix -- additional number of whitespace pairs to prefix each log statement with.
    """
    prefix_whitespaces = '  ' * prefix
    rem = c_int()
    for nla in nla_for_each_attr(attrs, attrlen, rem):
        alen = nla_len(nla)
        if nla.nla_type == 0:
            ofd('%s  [ATTR PADDING] %d octets', prefix_whitespaces, alen)
        else:
            is_nested = ' NESTED' if nla_is_nested(nla) else ''
            ofd('%s  [ATTR %02d%s] %d octets', prefix_whitespaces, nla.nla_type, is_nested, alen)

        if nla_is_nested(nla):
            dump_attrs(ofd, nla_data(nla), alen, prefix + 1)
        else:
            dump_attr(ofd, nla, prefix)

        padlen = nla_padlen(alen)
        if padlen > 0:
            ofd('%s  [PADDING] %d octets', prefix_whitespaces, padlen)
            dump_hex(ofd, bytearray_ptr(nla_data(nla), alen), padlen, prefix)

    if rem.value:
        ofd('%s  [LEFTOVER] %d octets', prefix_whitespaces, rem)


def dump_error_msg(msg, ofd=_LOGGER.debug):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L908.

    Positional arguments:
    msg -- message to print (nl_msg class instance).

    Keyword arguments:
    ofd -- function to call with arguments similar to `logging.debug`.
    """
    hdr = nlmsg_hdr(msg)
    err = libnl.linux_private.netlink.nlmsgerr(nlmsg_data(hdr))

    ofd('  [ERRORMSG] %d octets', err.SIZEOF)

    if nlmsg_len(hdr) >= err.SIZEOF:
        ofd('    .error = %d "%s"', err.error, os.strerror(-err.error))
        ofd('  [ORIGINAL MESSAGE] %d octets', hdr.SIZEOF)
        errmsg = nlmsg_inherit(err.msg)
        print_hdr(ofd, errmsg)


def print_msg(msg, ofd, hdr):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L929.

    Positional arguments:
    msg -- Netlink message (nl_msg class instance).
    ofd -- function to call with arguments similar to `logging.debug`.
    hdr -- Netlink message header (nlmsghdr class instance).
    """
    payloadlen = c_int(nlmsg_len(hdr))
    attrlen = 0
    data = nlmsg_data(hdr)
    ops = nl_cache_ops_associate_safe(msg.nm_protocol, hdr.nlmsg_type)
    if ops:
        attrlen = nlmsg_attrlen(hdr, ops.co_hdrsize)
        payloadlen.value -= attrlen
    if msg.nm_protocol == libnl.linux_private.netlink.NETLINK_GENERIC:
        data = print_genl_msg(msg, ofd, hdr, ops, payloadlen)
    if payloadlen.value:
        ofd('  [PAYLOAD] %d octets', payloadlen.value)
        dump_hex(ofd, data, payloadlen.value, 0)
    if attrlen:
        attrs = nlmsg_attrdata(hdr, ops.co_hdrsize)
        attrlen = nlmsg_attrlen(hdr, ops.co_hdrsize)
        dump_attrs(ofd, attrs, attrlen, 0)


def nl_msg_dump(msg, ofd=_LOGGER.debug):
    """Dump message in human readable format to callable.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L970

    Positional arguments:
    msg -- message to print (nl_msg class instance).

    Keyword arguments:
    ofd -- function to call with arguments similar to `logging.debug`.
    """
    hdr = nlmsg_hdr(msg)

    ofd('--------------------------   BEGIN NETLINK MESSAGE ---------------------------')

    ofd('  [NETLINK HEADER] %d octets', hdr.SIZEOF)
    print_hdr(ofd, msg)

    if hdr.nlmsg_type == libnl.linux_private.netlink.NLMSG_ERROR:
        dump_error_msg(msg, ofd)
    elif nlmsg_len(hdr) > 0:
        print_msg(msg, ofd, hdr)

    ofd('---------------------------  END NETLINK MESSAGE   ---------------------------')
