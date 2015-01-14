"""Port of Netlink Socket (lib/socket.c) C library.
http://www.infradead.org/~tgr/libnl/doc/api/socket_8c_source.html

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from socket import AF_NETLINK, SOCK_DGRAM, socket

from wifipy.backends.netlink.netlink import NETLINK_ADD_MEMBERSHIP, NETLINK_DROP_MEMBERSHIP

SOL_NETLINK = 270


def nl_socket_alloc():
    """Creates an AF_NETLINK socket and returns the handle.

    Modeled after:
    http://www.infradead.org/~tgr/libnl/doc/api/socket_8c_source.html#l00142

    Returns:
    socket.socket() instance.
    """
    sk = socket(AF_NETLINK, SOCK_DGRAM)
    return sk


def nl_socket_add_membership(sk, group):
    """Have socket join a group. Probably just for kernel multicast messages.

    Modeled after:
    http://www.infradead.org/~tgr/libnl/doc/api/socket_8c_source.html#l00330

    Positional arguments:
    sk -- AF_NETLINK socket.
    group -- group identifier integer.
    """
    sk.setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, group)


def nl_socket_drop_membership(sk, group):
    """Have socket leave a group.

    Modeled after:
    http://www.infradead.org/~tgr/libnl/doc/api/socket_8c_source.html#l00378

    Positional arguments:
    sk -- AF_NETLINK socket.
    group -- group identifier integer.
    """
    sk.setsockopt(SOL_NETLINK, NETLINK_DROP_MEMBERSHIP, group)
