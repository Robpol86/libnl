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
from libnl.msg import nlmsg_alloc_simple, nlmsg_append
from libnl.netlink_private.types import NL_OWN_PORT


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
    """Transmit Netlink message using sendmsg().
    https://github.com/thom311/libnl/blob/master/lib/nl.c#L299

    Transmits the message specified in \c hdr over the Netlink socket using the sendmsg() system call.

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
    sk -- generic netlink socket.
    msg -- netlink message to be sent.
    hdr -- sendmsg() message header.

    Returns:
    Number of bytes sent on success or a negative error code.
    """
    sk.sendmsg()  # TODO


def nl_send_iovec(sk, msg, iov, iovlen):
    """Transmit Netlink message (taking IO vector)
    https://github.com/thom311/libnl/blob/master/lib/nl.c#L342

    This function is identical to nl_send() except that instead of taking a `struct nl_msg` object it takes an IO
    vector. Please see the description of `nl_send()`.

    This function triggers the `NL_CB_MSG_OUT` callback.

    Positional arguments:
    sk -- generic netlink socket.
    msg -- netlink message to be sent.
    iov -- IO vector to be sent.
    iovlen -- number of struct iovec to be sent.

    Returns:
    Number of bytes sent on success or a negative error code.
    """
    nl_sendmsg()  # TODO


def nl_send(sk, msg):
    """Transmit Netlink message.
    https://github.com/thom311/libnl/blob/master/lib/nl.c#L416

    Transmits the Netlink message `msg` over the Netlink socket using the `sendmsg()` system call. This function is
    based on `nl_send_iovec()` but takes care of initializing a `struct iovec` based on the `msg` object.

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
    sk -- generic netlink socket.
    msg -- netlink message to be sent.

    Returns:
    Number of bytes sent on success or a negative error code.
    """
    nl_send_iovec()  # TODO


def nl_send_auto(sk, msg):
    """Finalize and transmit Netlink message.
    https://github.com/thom311/libnl/blob/master/lib/nl.c#L485

    Finalizes the message by passing it to `nl_complete_msg()` and transmits it by passing it to `nl_send()`.

    This function triggers the `NL_CB_MSG_OUT` callback.

    Positional arguments:
    sk -- generic netlink socket.
    msg -- netlink message to be sent.

    Returns:
    Number of bytes sent on success or a negative error code.
    """
    nl_complete_msg()  # TODO
    nl_send()
nl_send_auto_complete = nl_send_auto


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
