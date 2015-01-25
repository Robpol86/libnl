"""Netlink Types (netlink-private/types.h).
https://github.com/thom311/libnl/blob/master/include/netlink-private/types.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from ctypes import c_char, c_int, c_uint, c_uint16, c_uint32, POINTER, Structure

from libnl.netlink_private.cache_api import nl_cache_ops
from libnl.hashtable import nl_hash_table
from libnl.linux_private.netlink import sockaddr_nl
from libnl.list import nl_list_head
from libnl.netlink_private.object_api import NLHDR_COMMON

NL_SOCK_BUFSIZE_SET = 1 << 0
NL_SOCK_PASSCRED = 1 << 1
NL_OWN_PORT = 1 << 2
NL_MSG_PEEK = 1 << 3
NL_NO_AUTO_ACK = 1 << 4
NL_MSG_CRED_PRESENT = 1


class nl_cb(object):  # TODO
    """Netlink callback class (C struct equivalent).
    https://github.com/thom311/libnl/blob/master/include/netlink-private/types.h#L39

    Instance variables:
    cb_set -- dictionary of callback functions (values), indexed by callback type (keys).
    cb_args -- dictionary of arguments to be passed to callback functions (values), indexed by callback type (keys).
    """

    def __init__(self):
        self.cb_set = dict()
        self.cb_args = dict()
        self.cb_err = None
        self.cb_err_arg = None
        self.cb_recvmsgs_ow = None
        self.cb_recv_ow = None
        self.cb_send_ow = None
        self.cb_refcnt = None
        self.cb_active = None


class nl_sock(object):
    """Netlink socket class (C struct equivalent).
    https://github.com/thom311/libnl/blob/master/include/netlink-private/types.h#L69

    Instance variables:
    s_local -- struct sockaddr_nl.
    s_peer -- struct sockaddr_nl.
    s_fd -- returns -1 if the socket has not been opened, or the socket's file descriptor integer.
    s_proto -- int.
    s_seq_next -- unsigned int.
    s_seq_expect -- unsigned int.
    s_flags -- int.
    s_cb -- struct nl_cb.
    s_bufsize -- size_t.
    socket_instance -- the actual socket.socket() instance.
    """

    def __init__(self):
        self.s_local = sockaddr_nl()
        self.s_peer = sockaddr_nl()
        self.s_proto = None
        self.s_seq_next = None
        self.s_seq_expect = None
        self.s_flags = None
        self.s_cb = None
        self.s_bufsize = None
        self.socket_instance = None

    @property
    def s_fd(self):
        return -1 if self.socket_instance is None else self.socket_instance.fileno()


class nl_cache(Structure):
    """https://github.com/thom311/libnl/blob/master/include/netlink-private/types.h#L82"""
    _fields_ = [
        ('c_items', nl_list_head),
        ('c_nitems', c_int),
        ('c_iarg1', c_int),
        ('c_iarg2', c_int),
        ('c_refcnt', c_int),
        ('c_flags', c_uint),
        ('hashtable', POINTER(nl_hash_table)),
        ('c_ops', POINTER(nl_cache_ops)),
    ]


class nl_msg(object):
    """https://github.com/thom311/libnl/blob/master/include/netlink-private/types.h#L133"""

    def __init__(self):
        self.nm_protocol = None
        self.nm_flags = None
        self.nm_src = None
        self.nm_dst = None
        self.nm_creds = None
        self.nm_nlh = None
        self.nm_refcnt = None


class genl_family(Structure):
    """https://github.com/thom311/libnl/blob/master/include/netlink-private/types.h#L783"""
    _fields_ = NLHDR_COMMON + [
        ('gf_id', c_uint16),
        ('gf_name', c_char),
        ('gf_version', c_uint32),
        ('gf_hdrsize', c_uint32),
        ('gf_maxattr', c_uint32),
        ('gf_ops', nl_list_head),
        ('gf_mc_grps', nl_list_head),
    ]
