"""Netlink Messages Interface (lib/msg.c).
https://github.com/thom311/libnl/blob/master/lib/msg.c
https://github.com/thom311/libnl/blob/master/include/netlink/msg.h

Netlink message construction/parsing interface.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from ctypes import byref

from libnl.attr import nla_for_each_attr
from libnl.linux_private.netlink import NLMSG_ALIGN, nlmsghdr
from libnl.netlink_private.types import nl_msg, NL_MSG_CRED_PRESENT

NL_AUTO_PORT = 0
NL_AUTO_PID = NL_AUTO_PORT
NL_AUTO_SEQ = 0


def nlmsg_size(payload):
    """Calculates size of netlink message based on payload length.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L54

    Positional arguments:
    payload -- length of payload (integer).

    Returns:
    Size of netlink message without padding (integer).
    """
    return int(NLMSG_HDRLEN + payload)
nlmsg_msg_size = nlmsg_size


def nlmsg_total_size(payload):
    """Calculates size of netlink message including padding based on payload length.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L72

    This function is identical to nlmsg_size() + nlmsg_padlen().

    Positional arguments:
    payload -- length of payload (integer).

    Returns:
    Size of netlink message including padding (integer).
    """
    return int(NLMSG_ALIGN(nlmsg_msg_size(payload)))


def nlmsg_data(nlh):
    """Return pointer to message payload.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L105

    Positional arguments:
    nlh -- netlink message header.

    Returns:
    Pointer to start of message payload.
    """
    return byref(nlh, NLMSG_HDRLEN)


def nlmsg_for_each_attr(nlh):
    """Iterate over a stream of attributes in a message.
    https://github.com/thom311/libnl/blob/master/include/netlink/msg.h#L123

    Positional arguments:
    nlh -- netlink message header (nlmsghdr class instance).

    Returns:
    Generator yielding nl_attr instances.
    """
    return nla_for_each_attr(nlh.payload)


def nlmsg_alloc():
    """Instantiate a new netlink message.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L299

    Instantiates a new netlink message without any further payload.

    Returns:
    Newly allocated netlink message.
    """
    nm = nl_msg()
    nm.nm_nlh = nlmsghdr()
    nm.nm_refcnt = 1
    nm.nm_protocol = -1
    return nm


def nlmsg_inherit(hdr=None):
    """Allocate a new netlink message and inherit netlink message header.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L322

    Allocates a new netlink message and inherits the original message header. If `hdr` is not None it will be used as a
    template for the netlink message header, otherwise the header is left blank.

    Keyword arguments:
    hdr -- netlink message header template (nlmsghdr class instance).

    Returns:
    Newly allocated netlink message (nl_msg class instance) or None.
    """
    nm = nlmsg_alloc()
    if hdr:
        new = nm.nm_nlh
        new.nlmsg_type = hdr.nlmsg_type
        new.nlmsg_flags = hdr.nlmsg_flags
        #new.nlmsg_seq = hdr.nlmsg_seq
        new.nlmsg_pid = hdr.nlmsg_pid
    return nm


def nlmsg_alloc_simple(nlmsgtype, flags):
    """Allocate a new netlink message.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L346

    Positional arguments:
    nlmsgtype -- netlink message type (integer).
    flags -- message flags (integer).

    Returns:
    Newly allocated netlink message (nl_msg class instance) or None.
    """
    nlh = nlmsghdr(nlmsg_type=nlmsgtype, nlmsg_flags=flags)
    msg = nlmsg_inherit(nlh)
    return msg


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
    return 0


def nlmsg_hdr(msg):
    """Return actual netlink message.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L536

    Returns the actual netlink message casted to the type of the netlink message header.

    Positional arguments:
    msg -- netlink message.

    Returns:
    A pointer to the netlink message.
    """
    return msg.nm_nlh


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
