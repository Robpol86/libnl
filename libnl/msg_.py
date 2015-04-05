"""Netlink Messages Interface (lib/msg.c).

https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c

Netlink message construction/parsing interface.

Only difference between msg_.py and msg.py is msg_.py mitigates
circular Python imports.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from libnl.linux_private.netlink import NLMSG_ALIGN, NLMSG_HDRLEN
from libnl.misc import bytearray_ptr


def nlmsg_data(nlh):
    """Return bytearray_ptr of the message payload.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L105

    Positional arguments:
    nlh -- Netlink message header (nlmsghdr class instance).

    Returns:
    bytearray_ptr beginning with the start of the message payload.
    """
    return bytearray_ptr(nlh.bytearray, NLMSG_HDRLEN)


def nlmsg_tail(nlh):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L110.

    Positional arguments:
    nlh -- nlmsghdr class instance.

    Returns:
    bytearray_ptr instance after the last nla in the nlmsghdr.
    """
    return bytearray_ptr(nlh.bytearray, NLMSG_ALIGN(nlh.nlmsg_len))


def nlmsg_datalen(nlh):
    """Return length of message payload.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L121

    Positional arguments:
    nlh -- Netlink message header (nlmsghdr class instance).

    Returns:
    Length of message payload in bytes.
    """
    return int(nlh.nlmsg_len - NLMSG_HDRLEN)


nlmsg_len = nlmsg_datalen  # Alias. https://github.com/thom311/libnl/blob/libnl3_2_25/lib/msg.c#L126
