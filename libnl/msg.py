"""Netlink Messages Interface (lib/msg.c).
https://github.com/thom311/libnl/blob/master/lib/msg.c
https://github.com/thom311/libnl/blob/master/include/netlink/msg.h

Netlink message construction/parsing interface.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from ctypes import sizeof
from resource import getpagesize

from libnl.linux_private.netlink import NLMSG_ALIGN, NLMSG_HDRLEN, nlmsghdr
from libnl.types import nl_msg

default_msg_size = None
NL_AUTO_PORT = 0
NL_AUTO_PID = NL_AUTO_PORT
NL_AUTO_SEQ = 0


def init_msg_size():
    """https://github.com/thom311/libnl/blob/master/lib/msg.c#L38"""
    global default_msg_size
    default_msg_size = getpagesize()


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


def _nlmsg_alloc(len_):
    """Message Building/Access.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L261

    Positional arguments:
    len_ -- payload size.

    Returns:
    Newly allocated netlink message.
    """
    nm = nl_msg()
    len_ = sizeof(nlmsghdr) if len_ < sizeof(nlmsghdr) else len_
    nm.nm_refcnt = 1
    nm.nm_protocol = -1
    nm.nm_size = len_
    return nm


def nlmsg_alloc():
    """Allocate a new netlink message with the default maximum payload size.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L299

    Allocates a new netlink message without any further payload. The maximum payload size defaults to PAGESIZE or as
    otherwise specified with nlmsg_set_default_size().

    Returns:
    Newly allocated netlink message.
    """
    return _nlmsg_alloc(default_msg_size)


def nlmsg_alloc_size(max_):
    """Allocate a new netlink message with maximum payload size specified.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L307

    Positional arguments:
    max_ -- specified maximum payload size.

    Return:
    Newly allocated netlink message.
    """
    return _nlmsg_alloc(max_)


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
