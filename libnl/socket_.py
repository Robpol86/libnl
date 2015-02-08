"""Netlink Socket (lib/socket.c).
https://github.com/thom311/libnl/blob/master/lib/socket.c

Representation of a netlink socket.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

import socket
import time

from libnl.errno_ import NLE_BAD_SOCK
from libnl.error import nl_syserr2nlerr
from libnl.handlers import NL_CB_DEFAULT, nl_cb_alloc
from libnl.linux_private.netlink import NETLINK_ADD_MEMBERSHIP, NETLINK_DROP_MEMBERSHIP
from libnl.netlink_private.types import nl_sock, NL_OWN_PORT, NL_SOCK_BUFSIZE_SET

_PREVIOUS_LOCAL_PORT = None
SOL_NETLINK = 270


def generate_local_port():
    """https://github.com/thom311/libnl/blob/master/lib/socket.c#L63"""
    global _PREVIOUS_LOCAL_PORT
    if _PREVIOUS_LOCAL_PORT is None:
        with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW) as s:
            s.bind((0, 0))
            _PREVIOUS_LOCAL_PORT = int(s.getsockname()[0])
    return int(_PREVIOUS_LOCAL_PORT)


def nl_socket_alloc(cb=None):
    """Allocate new netlink socket. Does not yet actually open a socket.
    https://github.com/thom311/libnl/blob/master/lib/socket.c#L206

    Also has code for generating local port once.
    https://github.com/thom311/libnl/blob/master/lib/nl.c#L123

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
    sk.s_local.nl_family = socket.AF_NETLINK
    sk.s_peer.nl_family = socket.AF_NETLINK
    sk.s_seq_expect = sk.s_seq_next = int(time.time())
    sk.s_flags = NL_OWN_PORT  # The port is 0 (unspecified), meaning NL_OWN_PORT.

    # Generate local port.
    nl_socket_get_local_port(sk)  # I didn't find this in the C source, but during testing I saw this behavior.

    return sk


def nl_socket_free(sk):
    """Free a netlink socket (closes the socket).
    https://github.com/thom311/libnl/blob/master/lib/socket.c#L244

    Positional arguments:
    sk -- netlink socket (nl_sock class instance).
    """
    if sk and sk.socket_instance:
        sk.socket_instance.close()


def nl_socket_get_local_port(sk):
    """https://github.com/thom311/libnl/blob/master/lib/socket.c#L357

    Also https://github.com/thom311/libnl/blob/master/lib/socket.c#L338
    """
    if not sk.s_local.nl_pid:
        port = generate_local_port()
        sk.s_flags &= ~NL_OWN_PORT
        sk.s_local.nl_pid = port
        return port
    return sk.s_local.nl_pid


def nl_socket_add_memberships(sk, *group):
    """Join groups.
    https://github.com/thom311/libnl/blob/master/lib/socket.c#L417

    Joins the specified groups using the modern socket option which is available since kernel version 2.6.14. It allows
    joining an almost arbitrary number of groups without limitation. The list of groups has to be terminated by 0
    (%NFNLGRP_NONE).

    Make sure to use the correct group definitions as the older bitmask definitions for nl_join_groups() are likely to
    still be present for backward compatibility reasons.

    Positional arguments:
    sk -- AF_NETLINK socket.
    group -- group identifier integer.

    Returns:
    0 on success or a negative error code.
    """
    sk.setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, group)  # TODO group is now a list. /issues/3


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
    sk.setsockopt(SOL_NETLINK, NETLINK_DROP_MEMBERSHIP, group)  # TODO group is now a list. /issues/3


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


def nl_socket_set_buffer_size(sk, rxbuf, txbuf):
    """Set socket buffer size of netlink socket.
    https://github.com/thom311/libnl/blob/master/lib/socket.c#L675

    Sets the socket buffer size of a netlink socket to the specified values `rxbuf` and `txbuf`. Providing a value of 0
    assumes a good default value.

    Positional arguments:
    sk -- netlink socket (nl_sock class instance).
    rxbuf -- new receive socket buffer size in bytes (integer).
    txbuf -- new transmit socket buffer size in bytes (integer).

    Returns:
    0 on success or a negative error code.
    """
    rxbuf = 32768 if rxbuf <= 0 else rxbuf
    txbuf = 32768 if txbuf <= 0 else txbuf
    if sk.s_fd == -1:
        return -NLE_BAD_SOCK

    try:
        sk.socket_instance.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, txbuf)
    except OSError as exc:
        return -nl_syserr2nlerr(exc.errno)

    try:
        sk.socket_instance.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rxbuf)
    except OSError as exc:
        return -nl_syserr2nlerr(exc.errno)

    sk.s_flags |= NL_SOCK_BUFSIZE_SET
    return 0
