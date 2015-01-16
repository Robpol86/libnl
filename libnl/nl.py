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
