"""Netlink Socket (lib/socket.c).
https://github.com/thom311/libnl/blob/master/lib/socket.c

Representation of a netlink socket.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from socket import AF_NETLINK
from libnl.handlers import NL_CB_DEFAULT, nl_cb_alloc

from libnl.linux_private.netlink import NETLINK_ADD_MEMBERSHIP, NETLINK_DROP_MEMBERSHIP
from libnl.types import nl_sock, NL_OWN_PORT

SOL_NETLINK = 270


def nl_socket_alloc(cb=None):
    """Allocate new netlink socket. Does not yet actually open a socket.
    https://github.com/thom311/libnl/blob/master/lib/socket.c#L206

    Keyword arguments:
    cb -- custom callback handler.

    Returns:
    Newly allocated netlink socket (nl_sock class instance) or None.
    """
    # Allocate the callback.
    cb = cb or nl_cb_alloc(NL_CB_DEFAULT)
    if not cb:
        return None

    # Allocate the socket.
    sk = nl_sock()
    sk.s_cb = cb
    sk.s_local.nl_family = AF_NETLINK
    sk.s_peer.nl_family = AF_NETLINK
    sk.s_flags = NL_OWN_PORT  # The port is 0 (unspecified), meaning NL_OWN_PORT.
    return sk


def nl_socket_add_memberships(sk, *group):
    """Join groups.
    https://github.com/thom311/libnl/blob/master/lib/socket.c#L417

    Joins the specified groups using the modern socket option which is available since kernel version 2.6.14. It allows
    joining an almost arbitary number of groups without limitation. The list of groups has to be terminated by 0
    (%NFNLGRP_NONE).

    Make sure to use the correct group definitions as the older bitmask definitions for nl_join_groups() are likely to
    still be present for backward compatibility reasons.

    Positional arguments:
    sk -- AF_NETLINK socket.
    group -- group identifier integer.

    Returns:
    0 on success or a negative error code.
    """
    sk.setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, group)  # TODO group is now a list.


def nl_socket_add_membership(sk, group):
    """Join a group.
    https://github.com/thom311/libnl/blob/master/lib/socket.c#L448

    Positional arguments:
    sk -- AF_NETLINK socket.
    group -- group identifier integer.

    Returns:
    0 on success or a negative error code.
    """
    return nl_socket_add_memberships(sk, group, 0)


def nl_socket_drop_memberships(sk, *group):
    """Leave groups.
    https://github.com/thom311/libnl/blob/master/lib/socket.c#L465

    Leaves the specified groups using the modern socket option which is available since kernel version 2.6.14. The list
    of groups has to terminated by 0 (%NFNLGRP_NONE).


    Positional arguments:
    sk -- AF_NETLINK socket.
    group -- group identifier integer.

    Returns:
    0 on success or a negative error code.
    """
    sk.setsockopt(SOL_NETLINK, NETLINK_DROP_MEMBERSHIP, group)  # TODO group is now a list.


def nl_socket_drop_membership(sk, group):
    """Leave a group.
    https://github.com/thom311/libnl/blob/master/lib/socket.c#L496

    Positional arguments:
    sk -- AF_NETLINK socket.
    group -- group identifier integer.

    Returns:
    0 on success or a negative error code.
    """
    return nl_socket_drop_memberships(sk, group, 0)
