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

from libnl.linux_private.netlink import NLMSG_ALIGN, nlmsghdr
from libnl.types import nl_msg

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
