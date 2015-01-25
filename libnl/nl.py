"""Core Netlink Interface (lib/nl.c).
https://github.com/thom311/libnl/blob/master/lib/nl.c

Socket handling, connection management, sending and receiving of data, message construction and parsing, object caching
system, ...

This is the API reference of the core library. It is not meant as a guide but as a reference. Please refer to the core
library guide for detailed documentation on the library architecture and examples.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from socket import AF_NETLINK, SOCK_CLOEXEC, SOCK_RAW, socket

from libnl.errno_ import NLE_BAD_SOCK, NLE_AF_NOSUPPORT
from libnl.error import nl_syserr2nlerr
from libnl.handlers import NL_OK, NL_CB_MSG_OUT
from libnl.linux_private.netlink import NLM_F_REQUEST, NLM_F_ACK
from libnl.misc import msghdr
from libnl.msg import nlmsg_alloc_simple, nlmsg_append, NL_AUTO_PORT, nlmsg_get_dst, nlmsg_get_creds, nlmsg_set_src
from libnl.netlink_private.netlink import nl_cb_call
from libnl.netlink_private.types import NL_OWN_PORT, NL_NO_AUTO_ACK
from libnl.socket_ import nl_socket_get_local_port


def nl_connect(sk, protocol):
    """Create file descriptor and bind socket.
    https://github.com/thom311/libnl/blob/master/lib/nl.c#L96

    Creates a new Netlink socket using `socket.socket()` and binds the socket to the protocol and local port specified
    in the `sk` socket object (if any). Fails if the socket is already connected.

    Positional arguments:
    sk -- netlink socket (nl_sock class instance).
    protocol -- netlink protocol to use (integer).

    Returns:
    0 on success or a negative error code.
    """
    flags = SOCK_CLOEXEC
    if sk.s_fd != -1:
        return -NLE_BAD_SOCK
    try:
        sk.socket_instance = socket(AF_NETLINK, SOCK_RAW | flags, protocol)
    except OSError as exc:
        return -nl_syserr2nlerr(exc.errno)

    if not sk.s_local.nl_pid:
        sk.s_flags &= ~NL_OWN_PORT
    try:
        sk.socket_instance.bind((sk.s_local.nl_pid, sk.s_local.nl_groups))
    except OSError as exc:
        sk.socket_instance.close()
        return -nl_syserr2nlerr(exc.errno)
    sk.s_local.nl_pid = sk.socket_instance.getsockname()[1]

    if sk.s_local.nl_family != AF_NETLINK:
        sk.socket_instance.close()
        return -NLE_AF_NOSUPPORT

    sk.s_proto = protocol
    return 0


def nl_sendmsg(sk, msg, hdr):
    """Transmit Netlink message using socket.sendmsg().
    https://github.com/thom311/libnl/blob/master/lib/nl.c#L299

    Transmits the message specified in `hdr` over the Netlink socket using the sendmsg() system call.

    ATTENTION: The `msg` argument will *not* be used to derive the message payload that is being sent out. The `msg`
    argument is *only* passed on to the `NL_CB_MSG_OUT` callback. The caller is responsible to initialize the `hdr`
    struct properly and have it point to the message payload and socket address.

    This function uses `nlmsg_set_src()` to modify the `msg` argument prior to invoking the `NL_CB_MSG_OUT` callback to
    provide the local port number.

    This function triggers the `NL_CB_MSG_OUT` callback.

    ATTENTION: Think twice before using this function. It provides a low level access to the Netlink socket. Among other
    limitations, it does not add credentials even if enabled or respect the destination address specified in the `msg`
    object.

    Positional arguments:
    sk -- netlink socket (nl_sock class instance).
    msg -- netlink message to be sent (nl_msg class instance).
    hdr -- sendmsg() message header (msghdr class instance).

    Returns:
    Number of bytes sent on success or a negative error code.
    """
    if sk.s_fd < 0:
        return -NLE_BAD_SOCK
    nlmsg_set_src(msg, sk.s_local)
    cb = sk.s_cb
    if cb.cb_set[NL_CB_MSG_OUT]:
        ret = nl_cb_call(cb, NL_CB_MSG_OUT, msg)
        if ret != NL_OK:
            return ret
    try:
        ret = sk.socket_instance.sendmsg(hdr)  # TODO
    except OSError as exc:
        return -nl_syserr2nlerr(exc.errno)
    return ret


def nl_send_iovec(sk, msg):
    """Transmit Netlink message.
    https://github.com/thom311/libnl/blob/master/lib/nl.c#L342

    This function is identical to nl_send().

    This function triggers the `NL_CB_MSG_OUT` callback.

    Positional arguments:
    sk -- netlink socket (nl_sock class instance).
    msg -- netlink message (nl_msg class instance).

    Returns:
    Number of bytes sent on success or a negative error code.
    """
    hdr = msghdr(msg_name=sk.s_peer)

    # Overwrite destination if specified in the message itself, defaults to the peer address of the socket.
    dst = nlmsg_get_dst(msg)
    if dst.nl_family == AF_NETLINK:
        hdr.msg_name = dst

    # Add credentials if present.
    creds = nlmsg_get_creds(msg)
    if creds:
        raise NotImplementedError  # TODO

    return nl_sendmsg(sk, msg, hdr)


def nl_send(sk, msg):
    """Transmit Netlink message.
    https://github.com/thom311/libnl/blob/master/lib/nl.c#L416

    Transmits the Netlink message `msg` over the Netlink socket using the `socket.sendmsg()`. This function is based on
    `nl_send_iovec()`.

    The message is addressed to the peer as specified in the socket by either the nl_socket_set_peer_port() or
    nl_socket_set_peer_groups() function. The peer address can be overwritten by specifying an address in the `msg`
    object using nlmsg_set_dst().

    If present in the `msg`, credentials set by the nlmsg_set_creds() function are added to the control buffer of the
    message.

    Calls to this function can be overwritten by providing an alternative using the nl_cb_overwrite_send() function.

    This function triggers the `NL_CB_MSG_OUT` callback.

    ATTENTION:  Unlike `nl_send_auto()`, this function does *not* finalize the message in terms of automatically adding
    needed flags or filling out port numbers.

    Positional arguments:
    sk -- netlink socket (nl_sock class instance).
    msg -- netlink message (nl_msg class instance).

    Returns:
    Number of bytes sent on success or a negative error code.
    """
    cb = sk.s_cb
    if cb.cb_send_ow:
        return cb.cb_send_ow(sk, msg)
    return nl_send_iovec(sk, msg)


def nl_complete_msg(sk, msg):
    """Finalize Netlink message.
    https://github.com/thom311/libnl/blob/master/lib/nl.c#L450

    This function finalizes a Netlink message by completing the message with desirable flags and values depending on the
    socket configuration.

    - If not yet filled out, the source address of the message (`nlmsg_pid`) will be set to the local port number of the
      socket.
    - If not yet specified, the protocol field of the message will be set to the protocol field of the socket.
    - The `NLM_F_REQUEST` Netlink message flag will be set.
    - The `NLM_F_ACK` flag will be set if Auto-ACK mode is enabled on the socket.

    Positional arguments:
    sk -- netlink socket (nl_sock class instance).
    msg -- netlink message (nl_msg class instance.
    """
    nlh = msg.nm_nlh
    if nlh.nlmsg_pid == NL_AUTO_PORT:
        nlh.nlmsg_pid = nl_socket_get_local_port(sk)
    if msg.nm_protocol == -1:
        msg.nm_protocol = sk.s_proto
    nlh.nlmsg_flags |= NLM_F_REQUEST
    if not sk.s_flags & NL_NO_AUTO_ACK:
        nlh.nlmsg_flags |= NLM_F_ACK


def nl_send_auto(sk, msg):
    """Finalize and transmit Netlink message.
    https://github.com/thom311/libnl/blob/master/lib/nl.c#L485

    Finalizes the message by passing it to `nl_complete_msg()` and transmits it by passing it to `nl_send()`.

    This function triggers the `NL_CB_MSG_OUT` callback.

    Positional arguments:
    sk -- netlink socket (nl_sock class instance).
    msg -- netlink message (nl_msg class instance).

    Returns:
    Number of bytes sent on success or a negative error code.
    """
    nl_complete_msg(sk, msg)
    nl_send(sk, msg)
nl_send_auto_complete = nl_send_auto  # Alias.


def nl_send_simple(sk, type_, flags, buf=None):
    """Construct and transmit a Netlink message.
    https://github.com/thom311/libnl/blob/master/lib/nl.c#L549

    Allocates a new Netlink message based on `type_` and `flags`. If `buf` is specified that payload will be appended to
    the message.

    Sends out the message using `nl_send_auto()`.

    Positional arguments:
    sk -- netlink socket (nl_sock class instance).
    type_ -- netlink message type (integer).
    flags -- netlink message flags (integer).

    Keyword arguments:
    buf -- payload data.

    Returns:
    Number of characters sent on success or a negative error code.
    """
    msg = nlmsg_alloc_simple(type_, flags)
    if buf:
        err = nlmsg_append(msg, buf)
        if err < 0:
            return err
    return nl_send_auto(sk, msg)
