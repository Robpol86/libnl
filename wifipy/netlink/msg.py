"""Port of Netlink Messages Interface (lib/msg.c) C library.
http://www.infradead.org/~tgr/libnl/doc/api/msg_8c_source.html

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from ctypes import sizeof
from resource import getpagesize

from wifipy.netlink.netlink import NLMSG_ALIGN, NLMSG_HDRLEN, nlmsghdr
from wifipy.netlink.types import nl_msg

PAGESIZE = getpagesize()


def nlmsg_size(payload):
    """Calculates size of netlink message based on payload length.

    Modeled after:
    http://www.infradead.org/~tgr/libnl/doc/api/msg_8c_source.html#l00054

    Positional arguments:
    payload -- length of payload (integer).

    Returns:
    Size of netlink message without padding (integer).
    """
    return int(NLMSG_HDRLEN + payload)


def nlmsg_msg_size(payload):
    """Calculates size of netlink message based on payload length.

    Modeled after:
    http://www.infradead.org/~tgr/libnl/doc/api/msg_8c_source.html#l00059

    Positional arguments:
    payload -- length of payload (integer).

    Returns:
    Size of netlink message without padding (integer).
    """
    return int(nlmsg_size(payload))


def nlmsg_total_size(payload):
    """Calculates size of netlink message including padding based on payload length.

    Modeled after:
    http://www.infradead.org/~tgr/libnl/doc/api/msg_8c_source.html#l00072

    Positional arguments:
    payload -- length of payload (integer).

    Returns:
    Size of netlink message including padding (integer).
    """
    return int(NLMSG_ALIGN(nlmsg_msg_size(payload)))


def nlmsg_alloc():
    """Allocate a new netlink message with the default maximum payload size.

    Modeled after:
    http://www.infradead.org/~tgr/libnl/doc/api/msg_8c_source.html#l00261

    Returns:
    Newly allocated netlink message.
    """
    nm = nl_msg()
    len_ = sizeof(nlmsghdr) if PAGESIZE < sizeof(nlmsghdr) else PAGESIZE
    nm.nm_refcnt = 1
    nm.nm_protocol = -1
    nm.nm_size = len_
    return nm
