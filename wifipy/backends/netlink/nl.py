"""Port of Core Netlink Interface (lib/nl.c) C library.
http://www.infradead.org/~tgr/libnl/doc/api/nl_8c_source.html

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""


def nl_sendmsg(sk, msg, hdr):
    """
    http://www.infradead.org/~tgr/libnl/doc/api/nl_8c_source.html#l00251
    :param sk:
    :param msg:
    :param hdr:
    :return:
    """
    sk.sendmsg()


def nl_send_iovec(sk, msg, iov):
    nl_sendmsg()
    pass


def nl_send(sk, msg):
    nl_send_iovec()
    pass


def nl_send_auto(sk, msg):
    nl_complete_msg()
    nl_send()
    pass
