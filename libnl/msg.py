"""Netlink Messages Interface (lib/msg.c).
https://github.com/thom311/libnl/blob/master/lib/msg.c
https://github.com/thom311/libnl/blob/master/include/netlink/msg.h

Netlink message construction/parsing interface.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

import ctypes
import logging
import os

from libnl.attr import nla_for_each_attr, nla_find
from libnl.linux_private.genetlink import GENL_HDRLEN, genlmsghdr
from libnl.linux_private.netlink import (nlmsghdr, NLMSG_ERROR, NLMSG_HDRLEN, NETLINK_GENERIC, NLMSG_NOOP, NLMSG_DONE,
                                         NLMSG_OVERRUN, NLM_F_REQUEST, NLM_F_MULTI, NLM_F_ACK, NLM_F_ECHO, NLM_F_ROOT,
                                         NLM_F_MATCH, NLM_F_ATOMIC, NLM_F_REPLACE, NLM_F_EXCL, NLM_F_CREATE,
                                         NLM_F_APPEND, nlmsgerr)
from libnl.netlink_private.types import nl_msg, NL_MSG_CRED_PRESENT
from libnl.utils import __type2str

_LOGGER = logging.getLogger(__name__)
NL_AUTO_PORT = 0
NL_AUTO_PID = NL_AUTO_PORT
NL_AUTO_SEQ = 0


def nlmsg_size(payload):
    """Calculates size of netlink message based on payload length.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L54

    Positional arguments:
    payload -- length of payload (integer).

    Returns:
    Size of netlink message without padding.
    """
    return NLMSG_HDRLEN + payload


nlmsg_msg_size = nlmsg_size  # Alias. https://github.com/thom311/libnl/blob/master/lib/msg.c#L59


def nlmsg_data(nlh):
    """Return the message payload.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L105

    Positional arguments:
    nlh -- netlink message header (nlmsghdr class instance).

    Returns:
    Message payload (list of objects).
    """
    if len(nlh.payload) == 1 and isinstance(nlh.payload[0], bytearray):
        return nlh.payload[0]
    return nlh.payload


def nlmsg_for_each_attr(nlh):
    """Iterate over a stream of attributes in a message.
    https://github.com/thom311/libnl/blob/master/include/netlink/msg.h#L123

    Positional arguments:
    nlh -- netlink message header (nlmsghdr class instance).

    Returns:
    Generator yielding nl_attr instances.
    """
    return nla_for_each_attr(nlh.payload)


def nlmsg_datalen(nlh):
    """Return length of message payload.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L121

    Positional arguments:
    nlh -- netlink message header (nlmsghdr class instance).

    Returns:
    Length of message payload in bytes.
    """
    return nlh.nlmsg_len - NLMSG_HDRLEN


nlmsg_len = nlmsg_datalen  # Alias. https://github.com/thom311/libnl/blob/master/lib/msg.c#L126


def nlmsg_attrdata(nlh):
    """Returns list of attributes/payload from netlink message header.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L143

    Positional arguments:
    nlh -- netlink message header (nlmsghdr class instance).

    Returns:
    List of attributes.
    """
    return nlh.payload


def nlmsg_find_attr(nlh, attrtype):
    """Find a specific attribute in a netlink message.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L231

    Positional arguments:
    nlh -- netlink message header (nlmsghdr class instance).
    attrtype -- type of attribute to look for.

    Returns:
    The first attribute which matches the specified type (nlattr class instance).
    """
    return nla_find(nlmsg_attrdata(nlh), attrtype)


def nlmsg_alloc():
    """Instantiate a new netlink message.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L299

    Instantiates a new netlink message without any further payload.

    Returns:
    Newly allocated netlink message (nl_msg class instance).
    """
    nm = nl_msg()
    nm.nm_nlh = nlmsghdr()
    nm.nm_refcnt = 1
    nm.nm_protocol = -1
    _LOGGER.debug('msg 0x%x: Allocated new message', id(nm))
    return nm


def nlmsg_inherit(hdr=None):
    """Allocate a new netlink message and inherit netlink message header.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L322

    Allocates a new netlink message and inherits the original message header. If `hdr` is not None it will be used as a
    template for the netlink message header, otherwise the header is left blank.

    Keyword arguments:
    hdr -- netlink message header template (nlmsghdr class instance).

    Returns:
    Newly allocated netlink message (nl_msg class instance).
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
    """Allocate a new netlink message.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L346

    Positional arguments:
    nlmsgtype -- netlink message type (integer).
    flags -- message flags (integer).

    Returns:
    Newly allocated netlink message (nl_msg class instance).
    """
    nlh = nlmsghdr(nlmsg_type=nlmsgtype, nlmsg_flags=flags)
    msg = nlmsg_inherit(nlh)
    _LOGGER.debug('msg 0x%x: Allocated new simple message', id(msg))
    return msg


def nlmsg_convert(hdr):
    """Convert a netlink message received from a netlink socket to a nl_msg.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L382

    Allocates a new netlink message and copies all of the data pointed to by `hdr` into the new message object.

    Positional arguments:
    hdr -- nlmsghdr class instance.

    Returns:
    New nl_msg class instance derived,
    """
    nm = nlmsg_alloc()
    nm.nm_nlh = hdr
    return nm


def nlmsg_append(msg, data):
    """Append data to tail of a netlink message.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L442

    Positional arguments:
    msg -- netlink message (nl_msg class instance).
    data -- data to add.

    Returns:
    0 on success or a negative error code.
    """
    msg.nm_nlh.payload.append(data)
    _LOGGER.debug('msg 0x%x: Appended %s', id(msg), type(data).__name__)
    return 0


def nlmsg_hdr(msg):
    """Return actual netlink message.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L536

    Returns the actual netlink message.

    Positional arguments:
    msg -- netlink message (nl_msg class instance).

    Returns:
    The netlink message object.
    """
    return msg.nm_nlh


def nlmsg_set_proto(msg, protocol):
    """https://github.com/thom311/libnl/blob/master/lib/msg.c#L584

    Positional arguments:
    msg -- netlink message (nl_msg class instance).
    protocol -- integer.
    """
    msg.nm_protocol = protocol


def nlmsg_set_src(msg, addr):
    """https://github.com/thom311/libnl/blob/master/lib/msg.c#L599"""
    msg.nm_src = addr


def nlmsg_get_dst(msg):
    """https://github.com/thom311/libnl/blob/master/lib/msg.c#L614"""
    return msg.nm_dst


def nlmsg_get_creds(msg):
    """https://github.com/thom311/libnl/blob/master/lib/msg.c#L625"""
    if msg.nm_flags & NL_MSG_CRED_PRESENT:
        return msg.nm_creds
    return None


nl_msgtypes = {
    NLMSG_NOOP: 'NOOP',
    NLMSG_ERROR: 'ERROR',
    NLMSG_DONE: 'DONE',
    NLMSG_OVERRUN: 'OVERRUN',
}


def nl_nlmsgtype2str(type_):
    """https://github.com/thom311/libnl/blob/master/lib/msg.c#L646

    Positional arguments:
    type_ -- integer (e.g. nlh.nlmsg_type).

    Returns:
    String.
    """
    return str(__type2str(type_, nl_msgtypes))


def nl_nlmsg_flags2str(flags):
    """Netlink Message Flags Translations.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L664

    Positional arguments:
    flags -- integer.

    Returns:
    String.
    """
    all_flags = (
        ('REQUEST', NLM_F_REQUEST),
        ('MULTI', NLM_F_MULTI),
        ('ACK', NLM_F_ACK),
        ('ECHO', NLM_F_ECHO),
        ('ROOT', NLM_F_ROOT),
        ('MATCH', NLM_F_MATCH),
        ('ATOMIC', NLM_F_ATOMIC),
        ('REPLACE', NLM_F_REPLACE),
        ('EXCL', NLM_F_EXCL),
        ('CREATE', NLM_F_CREATE),
        ('APPEND', NLM_F_APPEND),
    )
    matching_flags = [(k, v) for k, v in all_flags if flags & v]

    # Modify `flags`.
    for _, v in matching_flags:
        flags &= ~v

    keys = ([i[0] for i in matching_flags] + ['0x{0:x}'.format(flags)]) if flags else [i[0] for i in matching_flags]
    return ','.join(keys)


def dump_hex(start, len_, prefix):
    """https://github.com/thom311/libnl/blob/master/lib/msg.c#L760"""
    pass  # TODO https://github.com/Robpol86/libnl/issues/7


def print_hdr(msg):
    """https://github.com/thom311/libnl/blob/master/lib/msg.c#L793

    Positional arguments:
    msg -- message to print (nl_msg class instance).
    """
    nlh = nlmsg_hdr(msg)

    _LOGGER.debug('    .nlmsg_len = %d', nlh.nlmsg_len)

    ops = None  # ops = nl_cache_ops_associate_safe(nlmsg_get_proto(msg), nlh.nlmsg_type) # TODO issues/8
    if ops:
        raise NotImplementedError
    else:
        buf = nl_nlmsgtype2str(nlh.nlmsg_type)

    _LOGGER.debug('    .type = %d <%s>', nlh.nlmsg_type, buf)
    _LOGGER.debug('    .flags = %d <%s>', nlh.nlmsg_flags, nl_nlmsg_flags2str(nlh.nlmsg_flags))
    _LOGGER.debug('    .seq = %d', nlh.nlmsg_seq)
    _LOGGER.debug('    .port = %d', nlh.nlmsg_pid)


def print_genl_hdr(start):
    """https://github.com/thom311/libnl/blob/master/lib/msg.c#L831

    Positional arguments:
    start -- bytearray() instance.
    """
    ghdr = genlmsghdr.from_buffer(start)
    _LOGGER.debug('  [GENERIC NETLINK HEADER] %d octets', GENL_HDRLEN)
    _LOGGER.debug('    .cmd = %d', ghdr.cmd)
    _LOGGER.debug('    .version = %d', ghdr.version)
    _LOGGER.debug('    .unused = %#d', ghdr.reserved)


def print_genl_msg(msg, hdr, ops, payloadlen):
    """https://github.com/thom311/libnl/blob/master/lib/msg.c#L831

    Positional arguments:
    msg -- message to print (nl_msg class instance).
    hdr -- netlink message header (nlmsghdr class instance).
    ops -- TODO issues/8
    payloadlen -- length of payload in message (ctypes.c_int instance).

    Returns:
    data
    """
    data = nlmsg_data(hdr)
    if payloadlen.value < GENL_HDRLEN:
        return data

    print_genl_hdr(data)
    payloadlen.value -= GENL_HDRLEN

    if ops:
        hdrsize = ops.co_hdrsize - GENL_HDRLEN
        if hdrsize > 0:
            if payloadlen.value < hdrsize:
                return data
            _LOGGER.debug('  [HEADER] %d octets', hdrsize)
            dump_hex(data, hdrsize, 0)
            payloadlen.value -= hdrsize

    return data


def dump_error_msg(msg):
    """https://github.com/thom311/libnl/blob/master/lib/msg.c#L908

    Positional arguments:
    msg -- message to print (nl_msg class instance).
    """
    hdr = nlmsg_hdr(msg)
    err = nlmsgerr.from_buffer(nlmsg_data(hdr))

    _LOGGER.debug('  [ERRORMSG] %d octets', err.SIZEOF)

    if nlmsg_len(hdr) >= err.SIZEOF:
        _LOGGER.debug('    .error = %d "%s"', err.error, os.strerror(-err.error))
        _LOGGER.debug('  [ORIGINAL MESSAGE] %d octets', hdr.SIZEOF)
        errmsg = nlmsg_inherit(err.msg)
        print_hdr(errmsg)


def print_msg(msg, hdr):
    """https://github.com/thom311/libnl/blob/master/lib/msg.c#L929

    Positional arguments:
    msg -- netlink message (nl_msg class instance).
    hdr -- netlink message header (nlmsghdr class instance).
    """
    payloadlen = ctypes.c_int(nlmsg_len(hdr))
    attrlen = 0
    data = None
    ops = None  # = nl_cache_ops_associate_safe(nlmsg_get_proto(msg), hdr.nlmsg_type) # TODO issues/8
    if ops:
        raise NotImplementedError
    if msg.nm_protocol == NETLINK_GENERIC:
        data = print_genl_msg(msg, hdr, ops, payloadlen)
    if payloadlen.value:
        _LOGGER.debug('  [PAYLOAD] %d octets', payloadlen.value)
        dump_hex(data, payloadlen, 0)
    if attrlen:
        raise NotImplementedError
    if ops:
        raise NotImplementedError


def nl_msg_dump(msg):
    """Dump message in human readable format to handle.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L970

    Positional arguments:
    msg -- message to print (nl_msg class instance).
    """
    hdr = nlmsg_hdr(msg)

    _LOGGER.debug('--------------------------   BEGIN NETLINK MESSAGE ---------------------------')

    _LOGGER.debug('  [NETLINK HEADER] %d octets', hdr.SIZEOF)
    print_hdr(msg)

    if hdr.nlmsg_type == NLMSG_ERROR:
        dump_error_msg(msg)
    elif nlmsg_len(hdr) > 0:
        print_msg(msg, hdr)

    _LOGGER.debug('---------------------------  END NETLINK MESSAGE   ---------------------------')
