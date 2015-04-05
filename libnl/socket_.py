"""Netlink Socket (lib/socket.c).

https://github.com/thom311/libnl/blob/libnl3_2_25/lib/socket.c

Representation of a Netlink socket.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

import contextlib
import logging
import os
import socket
import time

from libnl.errno_ import NLE_BAD_SOCK, NLE_INVAL
from libnl.error import nl_syserr2nlerr
from libnl.handlers import nl_cb_alloc, NL_CB_DEBUG, NL_CB_DEFAULT, nl_cb_err, nl_cb_set, NL_CB_VERBOSE
from libnl.linux_private.netlink import NETLINK_ADD_MEMBERSHIP, NETLINK_DROP_MEMBERSHIP
from libnl.misc import __init
from libnl.netlink_private.netlink import BUG
from libnl.netlink_private.types import NL_OWN_PORT, nl_sock, NL_SOCK_BUFSIZE_SET

_LOGGER = logging.getLogger(__name__)
_PREVIOUS_LOCAL_PORT = None
default_cb = NL_CB_DEFAULT  # https://github.com/thom311/libnl/blob/libnl3_2_25/lib/socket.c#L40
SOL_NETLINK = 270


@__init
def init_default_cb():
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/socket.c#L42."""
    global default_cb
    nlcb = os.environ.get('NLCB', '').lower()
    if not nlcb:
        return

    if nlcb == 'default':
        default_cb = NL_CB_DEFAULT
    elif nlcb == 'verbose':
        default_cb = NL_CB_VERBOSE
    elif nlcb == 'debug':
        default_cb = NL_CB_DEBUG
    else:
        _LOGGER.warning('Unknown value for NLCB, valid values: {default | verbose | debug}')


def generate_local_port():
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/socket.c#L63."""
    global _PREVIOUS_LOCAL_PORT
    if _PREVIOUS_LOCAL_PORT is None:
        try:
            with contextlib.closing(socket.socket(getattr(socket, 'AF_NETLINK', -1), socket.SOCK_RAW)) as s:
                s.bind((0, 0))
                _PREVIOUS_LOCAL_PORT = int(s.getsockname()[0])
        except OSError:
            _PREVIOUS_LOCAL_PORT = 4294967295  # UINT32_MAX
    return int(_PREVIOUS_LOCAL_PORT)


def nl_socket_alloc(cb=None):
    """Allocate new Netlink socket. Does not yet actually open a socket.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/socket.c#L206

    Also has code for generating local port once.
    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/nl.c#L123

    Keyword arguments:
    cb -- custom callback handler.

    Returns:
    Newly allocated Netlink socket (nl_sock class instance) or None.
    """
    # Allocate the callback.
    cb = cb or nl_cb_alloc(default_cb)
    if not cb:
        return None

    # Allocate the socket.
    sk = nl_sock()
    sk.s_cb = cb
    sk.s_local.nl_family = getattr(socket, 'AF_NETLINK', -1)
    sk.s_peer.nl_family = getattr(socket, 'AF_NETLINK', -1)
    sk.s_seq_expect = sk.s_seq_next = int(time.time())
    sk.s_flags = NL_OWN_PORT  # The port is 0 (unspecified), meaning NL_OWN_PORT.

    # Generate local port.
    nl_socket_get_local_port(sk)  # I didn't find this in the C source, but during testing I saw this behavior.

    return sk


def nl_socket_free(sk):
    """Free a Netlink socket (closes the socket).

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/socket.c#L244

    Positional arguments:
    sk -- Netlink socket (nl_sock class instance).
    """
    if sk and sk.socket_instance:
        sk.socket_instance.close()


def nl_socket_get_local_port(sk):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/socket.c#L357.

    Also https://github.com/thom311/libnl/blob/libnl3_2_25/lib/socket.c#L338
    """
    if not sk.s_local.nl_pid:
        port = generate_local_port()
        sk.s_flags &= ~NL_OWN_PORT
        sk.s_local.nl_pid = port
        return port
    return sk.s_local.nl_pid


def nl_socket_add_memberships(sk, *group):
    """Join groups.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/socket.c#L417

    Joins the specified groups using the modern socket option. The list of groups has to be terminated by 0.

    Make sure to use the correct group definitions as the older bitmask definitions for nl_join_groups() are likely to
    still be present for backward compatibility reasons.

    Positional arguments:
    sk -- Netlink socket (nl_sock class instance).
    group -- group identifier (integer).

    Returns:
    0 on success or a negative error code.
    """
    if sk.s_fd == -1:
        return -NLE_BAD_SOCK
    for grp in group:
        if not grp:
            break
        if grp < 0:
            return -NLE_INVAL
        try:
            sk.socket_instance.setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, grp)
        except OSError as exc:
            return -nl_syserr2nlerr(exc.errno)
    return 0


def nl_socket_add_membership(sk, group):
    """Join a group.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/socket.c#L448

    Positional arguments:
    sk -- Netlink socket (nl_sock class instance).
    group -- group identifier (integer).

    Returns:
    0 on success or a negative error code.
    """
    return nl_socket_add_memberships(sk, group, 0)


def nl_socket_drop_memberships(sk, *group):
    """Leave groups.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/socket.c#L465

    Leaves the specified groups using the modern socket option. The list of groups has to terminated by 0.

    Positional arguments:
    sk -- Netlink socket (nl_sock class instance).
    group -- group identifier (integer).

    Returns:
    0 on success or a negative error code.
    """
    if sk.s_fd == -1:
        return -NLE_BAD_SOCK
    for grp in group:
        if not grp:
            break
        if grp < 0:
            return -NLE_INVAL
        try:
            sk.socket_instance.setsockopt(SOL_NETLINK, NETLINK_DROP_MEMBERSHIP, grp)
        except OSError as exc:
            return -nl_syserr2nlerr(exc.errno)
    return 0


def nl_socket_drop_membership(sk, group):
    """Leave a group.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/socket.c#L496

    Positional arguments:
    sk -- Netlink socket (nl_sock class instance).
    group -- group identifier (integer).

    Returns:
    0 on success or a negative error code.
    """
    return nl_socket_drop_memberships(sk, group, 0)


def nl_socket_get_cb(sk):
    """Get the current nl_cb callback handler stored in the nl_sock socket.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/socket.c#L609

    Positional arguments:
    sk -- Netlink socket (nl_sock class instance).

    Returns:
    nl_cb class instance.
    """
    return sk.s_cb


def nl_socket_set_cb(sk, cb):
    """Store nl_cb callback handler in the nl_sock socket, overwriting the previous callbacks.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/socket.c#L614

    Positional arguments:
    sk -- Netlink socket (nl_sock class instance).
    cb -- callbacks (nl_cb class instance).
    """
    if cb is None:
        raise BUG
    sk.s_cb = cb


def nl_socket_modify_cb(sk, type_, kind, func, arg):
    """Modify the callback handler associated with the socket.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/socket.c#L633

    Sets specific callback functions in the existing nl_cb class instance stored in the nl_sock socket.

    Positional arguments:
    sk -- Netlink socket (nl_sock class instance).
    type_ -- which type callback to set (integer).
    kind -- kind of callback (integer).
    func -- callback function.
    arg -- argument to be passed to callback function.

    Returns:
    0 on success or a negative error code.
    """
    return int(nl_cb_set(sk.s_cb, type_, kind, func, arg))


def nl_socket_modify_err_cb(sk, kind, func, arg):
    """Modify the error callback handler associated with the socket.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/socket.c#L649

    Positional arguments:
    sk -- Netlink socket (nl_sock class instance).
    kind -- kind of callback (integer).
    func -- callback function.
    arg -- argument to be passed to callback function.

    Returns:
    0 on success or a negative error code.
    """
    return int(nl_cb_err(sk.s_cb, kind, func, arg))


def nl_socket_set_buffer_size(sk, rxbuf, txbuf):
    """Set socket buffer size of Netlink socket.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/socket.c#L675

    Sets the socket buffer size of a Netlink socket to the specified values `rxbuf` and `txbuf`. Providing a value of 0
    assumes a good default value.

    Positional arguments:
    sk -- Netlink socket (nl_sock class instance).
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
