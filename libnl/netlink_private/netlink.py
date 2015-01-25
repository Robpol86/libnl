"""Local Netlink Interface (netlink-private/netlink.h).
https://github.com/thom311/libnl/blob/master/include/netlink-private/netlink.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from libnl.handlers import NL_CB_TYPE_MAX


class BUG(Exception):
    """https://github.com/thom311/libnl/blob/master/include/netlink-private/netlink.h#L99"""
    pass


def nl_cb_call(cb, type_, msg):
    """Calls a callback function.
    https://github.com/thom311/libnl/blob/master/include/netlink-private/netlink.h#L137

    Positional arguments:
    cb -- callback class instance
    type_ -- callback type integer (e.g. NL_CB_MSG_OUT).
    msg -- netlink message (nl_msg class instance).

    Returns:
    Integer from the callback function (like NL_OK, NL_SKIP, etc).
    """
    cb.cb_active = type_
    ret = cb.cb_set[type_](msg, cb.cb_args[type_])
    cb.cb_active = NL_CB_TYPE_MAX + 1
    return int(ret)
