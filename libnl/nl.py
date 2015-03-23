"""Core Netlink Interface (lib/nl.c).
https://github.com/thom311/libnl/blob/libnl3_2_25/lib/nl.c

Socket handling, connection management, sending and receiving of data, message construction and parsing, object caching
system, ...

This is the API reference of the core library. It is not meant as a guide but as a reference. Please refer to the core
library guide for detailed documentation on the library architecture and examples.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

import errno
import logging
import resource
import socket

from libnl.errno_ import (NLE_AF_NOSUPPORT, NLE_BAD_SOCK, NLE_DUMP_INTR, NLE_MSG_OVERFLOW, NLE_MSG_TRUNC,
                          NLE_SEQ_MISMATCH)
from libnl.error import nl_syserr2nlerr
from libnl.handlers import (NL_CB_ACK, nl_cb_clone, NL_CB_CUSTOM, NL_CB_DUMP_INTR, NL_CB_FINISH, NL_CB_INVALID,
                            NL_CB_MSG_IN, NL_CB_MSG_OUT, NL_CB_OVERRUN, NL_CB_SEND_ACK, NL_CB_SEQ_CHECK, nl_cb_set,
                            NL_CB_SKIPPED, NL_CB_VALID, NL_OK, NL_SKIP, NL_STOP)
from libnl.linux_private.netlink import (NLM_F_ACK, NLM_F_DUMP_INTR, NLM_F_MULTI, NLM_F_REQUEST, NLMSG_ALIGNTO,
                                         NLMSG_DONE, NLMSG_ERROR, NLMSG_NOOP, NLMSG_OVERRUN, nlmsgerr, nlmsghdr,
                                         sockaddr_nl)
from libnl.misc import bytearray_ptr, c_int, msghdr, ucred
from libnl.msg import (NL_AUTO_PORT, NL_AUTO_SEQ, nlmsg_alloc_simple, nlmsg_append, nlmsg_convert, nlmsg_data,
                       nlmsg_get_creds, nlmsg_get_dst, nlmsg_hdr, nlmsg_next, nlmsg_ok, nlmsg_set_proto, nlmsg_set_src,
                       nlmsg_size)
from libnl.netlink_private.netlink import nl_cb_call
from libnl.netlink_private.types import NL_MSG_PEEK, NL_NO_AUTO_ACK, NL_SOCK_BUFSIZE_SET, NL_SOCK_PASSCRED
from libnl.socket_ import nl_socket_get_local_port, nl_socket_set_buffer_size

_LOGGER = logging.getLogger(__name__)


def nl_connect(sk, protocol):
    """Create file descriptor and bind socket.
    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/nl.c#L96

    Creates a new Netlink socket using `socket.socket()` and binds the socket to the protocol and local port specified
    in the `sk` socket object (if any). Fails if the socket is already connected.

    Positional arguments:
    sk -- Netlink socket (nl_sock class instance).
    protocol -- Netlink protocol to use (integer).

    Returns:
    0 on success or a negative error code.
    """
    flags = getattr(socket, 'SOCK_CLOEXEC', 0)
    if sk.s_fd != -1:
        return -NLE_BAD_SOCK
    try:
        sk.socket_instance = socket.socket(getattr(socket, 'AF_NETLINK', -1), socket.SOCK_RAW | flags, protocol)
    except OSError as exc:
        return -nl_syserr2nlerr(exc.errno)

    if not sk.s_flags & NL_SOCK_BUFSIZE_SET:
        err = nl_socket_set_buffer_size(sk, 0, 0)
        if err < 0:
            sk.socket_instance.close()
            return err

    try:
        sk.socket_instance.bind((sk.s_local.nl_pid, sk.s_local.nl_groups))
    except OSError as exc:
        sk.socket_instance.close()
        return -nl_syserr2nlerr(exc.errno)
    sk.s_local.nl_pid = sk.socket_instance.getsockname()[0]

    if sk.s_local.nl_family != socket.AF_NETLINK:
        sk.socket_instance.close()
        return -NLE_AF_NOSUPPORT

    sk.s_proto = protocol
    return 0


def nl_sendmsg(sk, msg, hdr):
    """Transmit Netlink message using socket.sendmsg|sendto|send().
    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/nl.c#L299

    Transmits the message specified in `hdr` over the Netlink socket using Python's socket.sendmsg().

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
    sk -- Netlink socket (nl_sock class instance).
    msg -- Netlink message to be sent (nl_msg class instance).
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

    if hdr.msg_name is None:
        address = None
    else:
        address = tuple(hdr.msg_name)
        if address == (0, 0) or address == sk.socket_instance.getsockname:
            address = None

    try:
        if hdr.msg_control:
            ret = sk.socket_instance.sendmsg([hdr.msg_iov], hdr.msg_control, hdr.msg_flags, address)
        elif address:
            ret = sk.socket_instance.sendto(hdr.msg_iov, hdr.msg_flags, address)
        else:
            ret = sk.socket_instance.send(hdr.msg_iov, hdr.msg_flags)
    except OSError as exc:
        return -nl_syserr2nlerr(exc.errno)

    _LOGGER.debug('sent %d bytes', ret)
    return ret


def nl_send_iovec(sk, msg, iov, _):
    """Transmit Netlink message.
    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/nl.c#L342

    This function is identical to nl_send().

    This function triggers the `NL_CB_MSG_OUT` callback.

    Positional arguments:
    sk -- Netlink socket (nl_sock class instance).
    msg -- Netlink message (nl_msg class instance).
    iov -- data payload to be sent (bytearray).

    Returns:
    Number of bytes sent on success or a negative error code.
    """
    hdr = msghdr(msg_name=sk.s_peer, msg_iov=iov)

    # Overwrite destination if specified in the message itself, defaults to the peer address of the socket.
    dst = nlmsg_get_dst(msg)
    if dst.nl_family == socket.AF_NETLINK:
        hdr.msg_name = dst

    # Add credentials if present.
    creds = nlmsg_get_creds(msg)
    if creds:
        raise NotImplementedError  # TODO https://github.com/Robpol86/libnl/issues/2

    return nl_sendmsg(sk, msg, hdr)


def nl_send(sk, msg):
    """Transmit Netlink message.
    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/nl.c#L416

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
    sk -- Netlink socket (nl_sock class instance).
    msg -- Netlink message (nl_msg class instance).

    Returns:
    Number of bytes sent on success or a negative error code.
    """
    cb = sk.s_cb
    if cb.cb_send_ow:
        return cb.cb_send_ow(sk, msg)
    hdr = nlmsg_hdr(msg)
    iov = hdr.bytearray[:hdr.nlmsg_len]
    return nl_send_iovec(sk, msg, iov, 1)


def nl_complete_msg(sk, msg):
    """Finalize Netlink message.
    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/nl.c#L450

    This function finalizes a Netlink message by completing the message with desirable flags and values depending on the
    socket configuration.

    - If not yet filled out, the source address of the message (`nlmsg_pid`) will be set to the local port number of the
      socket.
    - If not yet specified, the next available sequence number is assigned to the message (`nlmsg_seq`).
    - If not yet specified, the protocol field of the message will be set to the protocol field of the socket.
    - The `NLM_F_REQUEST` Netlink message flag will be set.
    - The `NLM_F_ACK` flag will be set if Auto-ACK mode is enabled on the socket.

    Positional arguments:
    sk -- Netlink socket (nl_sock class instance).
    msg -- Netlink message (nl_msg class instance).
    """
    nlh = msg.nm_nlh
    if nlh.nlmsg_pid == NL_AUTO_PORT:
        nlh.nlmsg_pid = nl_socket_get_local_port(sk)
    if nlh.nlmsg_seq == NL_AUTO_SEQ:
        nlh.nlmsg_seq = sk.s_seq_next
        sk.s_seq_next += 1
    if msg.nm_protocol == -1:
        msg.nm_protocol = sk.s_proto
    nlh.nlmsg_flags |= NLM_F_REQUEST
    if not sk.s_flags & NL_NO_AUTO_ACK:
        nlh.nlmsg_flags |= NLM_F_ACK


def nl_send_auto(sk, msg):
    """Finalize and transmit Netlink message.
    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/nl.c#L485

    Finalizes the message by passing it to `nl_complete_msg()` and transmits it by passing it to `nl_send()`.

    This function triggers the `NL_CB_MSG_OUT` callback.

    Positional arguments:
    sk -- Netlink socket (nl_sock class instance).
    msg -- Netlink message (nl_msg class instance).

    Returns:
    Number of bytes sent on success or a negative error code.
    """
    nl_complete_msg(sk, msg)
    return nl_send(sk, msg)


def nl_send_simple(sk, type_, flags, buf=None, size=0):
    """Construct and transmit a Netlink message.
    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/nl.c#L549

    Allocates a new Netlink message based on `type_` and `flags`. If `buf` points to payload of length `size` that
    payload will be appended to the message.

    Sends out the message using `nl_send_auto()`.

    Positional arguments:
    sk -- Netlink socket (nl_sock class instance).
    type_ -- Netlink message type (integer).
    flags -- Netlink message flags (integer).

    Keyword arguments:
    buf -- payload data.
    size -- size of `data` (integer).

    Returns:
    Number of characters sent on success or a negative error code.
    """
    msg = nlmsg_alloc_simple(type_, flags)
    if buf is not None and size:
        err = nlmsg_append(msg, buf, size, NLMSG_ALIGNTO)
        if err < 0:
            return err
    return nl_send_auto(sk, msg)


def nl_recv(sk, nla, buf, creds=None):
    """Receive data from Netlink socket.
    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/nl.c#L625

    Receives data from a connected netlink socket using recvmsg() and returns the number of bytes read. The read data is
    stored in a newly allocated buffer that is assigned to `buf`. The peer's netlink address will be stored in `nla`.

    This function blocks until data is available to be read unless the socket has been put into non-blocking mode using
    nl_socket_set_nonblocking() in which case this function will return immediately with a return value of 0.

    The buffer size used when reading from the netlink socket and thus limiting the maximum size of a netlink message
    that can be read defaults to the size of a memory page (getpagesize()). The buffer size can be modified on a per
    socket level using the function `nl_socket_set_msg_buf_size()`.

    If message peeking is enabled using nl_socket_enable_msg_peek() the size of the message to be read will be
    determined using the MSG_PEEK flag prior to performing the actual read. This leads to an additional recvmsg() call
    for every read operation which has performance implications and is not recommended for high throughput protocols.

    An eventual interruption of the recvmsg() system call is automatically handled by retrying the operation.

    If receiving of credentials has been enabled using the function `nl_socket_set_passcred()`, this function will
    allocate a new struct `ucred` filled with the received credentials and assign it to `creds`.

    Positional arguments:
    sk -- Netlink socket (nl_sock class instance) (input).
    nla -- Netlink socket structure to hold address of peer (sockaddr_nl class instance) (output).
    buf -- destination bytearray() for message content (output).
    creds -- destination class instance for credentials (ucred class instance) (output).

    Returns:
    Two-item tuple. First item is number of bytes read, 0 on EOF, 0 on no data event (non-blocking mode), or a negative
    error code. Second item is the message content from the socket or None.
    """
    flags = 0
    page_size = resource.getpagesize() * 4
    if sk.s_flags & NL_MSG_PEEK:
        flags |= socket.MSG_PEEK | socket.MSG_TRUNC
    iov_len = sk.s_bufsize or page_size

    if creds and sk.s_flags & NL_SOCK_PASSCRED:
        raise NotImplementedError  # TODO https://github.com/Robpol86/libnl/issues/2

    while True:  # This is the `goto retry` implementation.
        try:
            if hasattr(sk.socket_instance, 'recvmsg'):
                iov, _, msg_flags, address = sk.socket_instance.recvmsg(iov_len, 0, flags)
            else:
                iov, address = sk.socket_instance.recvfrom(iov_len, flags)
                msg_flags = 0
        except OSError as exc:
            if exc.errno == errno.EINTR:
                continue  # recvmsg() returned EINTR, retrying.
            return -nl_syserr2nlerr(exc.errno)
        nla.nl_family = sk.socket_instance.family  # recvmsg() in C does this, but not Python's.
        if not iov:
            return 0

        if msg_flags & socket.MSG_CTRUNC:
            raise NotImplementedError  # TODO https://github.com/Robpol86/libnl/issues/2

        if iov_len < len(iov) or msg_flags & socket.MSG_TRUNC:
            # Provided buffer is not long enough.
            # Enlarge it to size of n (which should be total length of the message) and try again.
            iov_len = len(iov)
            continue

        if flags:
            # Buffer is big enough, do the actual reading.
            flags = 0
            continue

        nla.nl_pid = address[0]
        nla.nl_groups = address[1]

        if creds and sk.s_flags * NL_SOCK_PASSCRED:
            raise NotImplementedError  # TODO https://github.com/Robpol86/libnl/issues/2

        if iov:
            buf += iov

        return len(buf)


def recvmsgs(sk, cb):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/nl.c#L775

    This is where callbacks are called.

    Positional arguments:
    sk -- Netlink socket (nl_sock class instance).
    cb -- callbacks (nl_cb class instance).

    Returns:
    Number of bytes received or a negative error code.
    """
    multipart = 0
    interrupted = 0
    nrecv = 0
    buf = bytearray()

    # nla is passed on to not only to nl_recv() but may also be passed to a function pointer provided by the caller
    # which may or may not initialize the variable. Thomas Graf.
    nla = sockaddr_nl()
    creds = ucred()

    while True:  # This is the `goto continue_reading` implementation.
        _LOGGER.debug('Attempting to read from 0x%x', id(sk))
        n = c_int(cb.cb_recv_ow(sk, nla, buf, creds) if cb.cb_recv_ow else nl_recv(sk, nla, buf, creds))
        if n.value <= 0:
            return n.value

        _LOGGER.debug('recvmsgs(0x%x): Read %d bytes', id(sk), n.value)

        hdr = nlmsghdr(bytearray_ptr(buf))
        while nlmsg_ok(hdr, n):
            _LOGGER.debug('recvmsgs(0x%x): Processing valid message...', id(sk))
            msg = nlmsg_convert(hdr)
            nlmsg_set_proto(msg, sk.s_proto)
            nlmsg_set_src(msg, nla)
            if creds:
                raise NotImplementedError  # nlmsg_set_creds(msg, creds)
            nrecv += 1

            # Raw callback is the first, it gives the most control to the user and he can do his very own parsing.
            if cb.cb_set[NL_CB_MSG_IN]:
                err = nl_cb_call(cb, NL_CB_MSG_IN, msg)  # NL_CB_CALL(cb, NL_CB_MSG_IN, msg)
                if err == NL_OK:
                    pass
                elif err == NL_SKIP:
                    hdr = nlmsg_next(hdr, n)
                    continue
                elif err == NL_STOP:
                    return -NLE_DUMP_INTR if interrupted else nrecv
                else:
                    return -NLE_DUMP_INTR if interrupted else (err or nrecv)

            if cb.cb_set[NL_CB_SEQ_CHECK]:
                # Sequence number checking. The check may be done by the user, otherwise a very simple check is applied
                # enforcing strict ordering.
                err = nl_cb_call(cb, NL_CB_SEQ_CHECK, msg)  # NL_CB_CALL(cb, NL_CB_SEQ_CHECK, msg)
                if err == NL_OK:
                    pass
                elif err == NL_SKIP:
                    hdr = nlmsg_next(hdr, n)
                    continue
                elif err == NL_STOP:
                    return -NLE_DUMP_INTR if interrupted else nrecv
                else:
                    return -NLE_DUMP_INTR if interrupted else (err or nrecv)
            elif not sk.s_flags & NL_NO_AUTO_ACK:
                # Only do sequence checking if auto-ack mode is enabled.
                if hdr.nlmsg_seq != sk.s_seq_expect:
                    if cb.cb_set[NL_CB_INVALID]:
                        err = nl_cb_call(cb, NL_CB_INVALID, msg)  # NL_CB_CALL(cb, NL_CB_INVALID, msg)
                        if err == NL_OK:
                            pass
                        elif err == NL_SKIP:
                            hdr = nlmsg_next(hdr, n)
                            continue
                        elif err == NL_STOP:
                            return -NLE_DUMP_INTR if interrupted else nrecv
                        else:
                            return -NLE_DUMP_INTR if interrupted else (err or nrecv)
                    else:
                        return -NLE_SEQ_MISMATCH

            if hdr.nlmsg_type in (NLMSG_DONE, NLMSG_ERROR, NLMSG_NOOP, NLMSG_OVERRUN):
                # We can't check for !NLM_F_MULTI since some Netlink users in the kernel are broken.
                sk.s_seq_expect += 1
                _LOGGER.debug('recvmsgs(0x%x): Increased expected sequence number to %d', id(sk), sk.s_seq_expect)

            if hdr.nlmsg_flags & NLM_F_MULTI:
                multipart = 1

            if hdr.nlmsg_flags & NLM_F_DUMP_INTR:
                if cb.cb_set[NL_CB_DUMP_INTR]:
                    err = nl_cb_call(cb, NL_CB_DUMP_INTR, msg)  # NL_CB_CALL(cb, NL_CB_DUMP_INTR, msg)
                    if err == NL_OK:
                        pass
                    elif err == NL_SKIP:
                        hdr = nlmsg_next(hdr, n)
                        continue
                    elif err == NL_STOP:
                        return -NLE_DUMP_INTR if interrupted else nrecv
                    else:
                        return -NLE_DUMP_INTR if interrupted else (err or nrecv)
                else:
                    # We have to continue reading to clear all messages until a NLMSG_DONE is received and report the
                    # inconsistency.
                    interrupted = 1

            if hdr.nlmsg_flags & NLM_F_ACK:
                # Other side wishes to see an ack for this message.
                if cb.cb_set[NL_CB_SEND_ACK]:
                    err = nl_cb_call(cb, NL_CB_SEND_ACK, msg)  # NL_CB_CALL(cb, NL_CB_SEND_ACK, msg)
                    if err == NL_OK:
                        pass
                    elif err == NL_SKIP:
                        hdr = nlmsg_next(hdr, n)
                        continue
                    elif err == NL_STOP:
                        return -NLE_DUMP_INTR if interrupted else nrecv
                    else:
                        return -NLE_DUMP_INTR if interrupted else (err or nrecv)

            if hdr.nlmsg_type == NLMSG_DONE:
                # Messages terminates a multipart message, this is usually the end of a message and therefore we slip
                # out of the loop by default. the user may overrule this action by skipping this packet.
                multipart = 0
                if cb.cb_set[NL_CB_FINISH]:
                    err = nl_cb_call(cb, NL_CB_FINISH, msg)  # NL_CB_CALL(cb, NL_CB_FINISH, msg)
                    if err == NL_OK:
                        pass
                    elif err == NL_SKIP:
                        hdr = nlmsg_next(hdr, n)
                        continue
                    elif err == NL_STOP:
                        return -NLE_DUMP_INTR if interrupted else nrecv
                    else:
                        return -NLE_DUMP_INTR if interrupted else (err or nrecv)
            elif hdr.nlmsg_type == NLMSG_NOOP:
                # Message to be ignored, the default action is to skip this message if no callback is specified. The
                # user may overrule this action by returning NL_PROCEED.
                if cb.cb_set[NL_CB_SKIPPED]:
                    err = nl_cb_call(cb, NL_CB_SKIPPED, msg)  # NL_CB_CALL(cb, NL_CB_SKIPPED, msg)
                    if err == NL_OK:
                        pass
                    elif err == NL_SKIP:
                        hdr = nlmsg_next(hdr, n)
                        continue
                    elif err == NL_STOP:
                        return -NLE_DUMP_INTR if interrupted else nrecv
                    else:
                        return -NLE_DUMP_INTR if interrupted else (err or nrecv)
                else:
                    hdr = nlmsg_next(hdr, n)
                    continue
            elif hdr.nlmsg_type == NLMSG_OVERRUN:
                # Data got lost, report back to user. The default action is to quit parsing. The user may overrule this
                # action by retuning NL_SKIP or NL_PROCEED (dangerous).
                if cb.cb_set[NL_CB_OVERRUN]:
                    err = nl_cb_call(cb, NL_CB_OVERRUN, msg)  # NL_CB_CALL(cb, NL_CB_OVERRUN, msg)
                    if err == NL_OK:
                        pass
                    elif err == NL_SKIP:
                        hdr = nlmsg_next(hdr, n)
                        continue
                    elif err == NL_STOP:
                        return -NLE_DUMP_INTR if interrupted else nrecv
                    else:
                        return -NLE_DUMP_INTR if interrupted else (err or nrecv)
                else:
                    return -NLE_DUMP_INTR if interrupted else -NLE_MSG_OVERFLOW
            elif hdr.nlmsg_type == NLMSG_ERROR:
                # Message carries a nlmsgerr.
                e = nlmsgerr(nlmsg_data(hdr))
                if hdr.nlmsg_len < nlmsg_size(e.SIZEOF):
                    # Truncated error message, the default action is to stop parsing. The user may overrule this action
                    # by returning NL_SKIP or NL_PROCEED (dangerous).
                    if cb.cb_set[NL_CB_INVALID]:
                        err = nl_cb_call(cb, NL_CB_INVALID, msg)  # NL_CB_CALL(cb, NL_CB_INVALID, msg)
                        if err == NL_OK:
                            pass
                        elif err == NL_SKIP:
                            hdr = nlmsg_next(hdr, n)
                            continue
                        elif err == NL_STOP:
                            return -NLE_DUMP_INTR if interrupted else nrecv
                        else:
                            return -NLE_DUMP_INTR if interrupted else (err or nrecv)
                    else:
                        return -NLE_DUMP_INTR if interrupted else -NLE_MSG_TRUNC
                elif e.error:
                    # Error message reported back from kernel.
                    if cb.cb_err:
                        err = cb.cb_err(nla, e, cb.cb_err_arg)
                        if err < 0:
                            return -NLE_DUMP_INTR if interrupted else err
                        elif err == NL_SKIP:
                            hdr = nlmsg_next(hdr, n)
                            continue
                        elif err == NL_STOP:
                            return -NLE_DUMP_INTR if interrupted else -nl_syserr2nlerr(e.error)
                    else:
                        return -NLE_DUMP_INTR if interrupted else -nl_syserr2nlerr(e.error)
                elif cb.cb_set[NL_CB_ACK]:
                    err = nl_cb_call(cb, NL_CB_ACK, msg)  # NL_CB_CALL(cb, NL_CB_ACK, msg)
                    if err == NL_OK:
                        pass
                    elif err == NL_SKIP:
                        hdr = nlmsg_next(hdr, n)
                        continue
                    elif err == NL_STOP:
                        return -NLE_DUMP_INTR if interrupted else nrecv
                    else:
                        return -NLE_DUMP_INTR if interrupted else (err or nrecv)
            else:
                # Valid message (not checking for MULTIPART bit to get along with broken kernels. NL_SKIP has no effect
                # on this.
                if cb.cb_set[NL_CB_VALID]:
                    err = nl_cb_call(cb, NL_CB_VALID, msg)  # NL_CB_CALL(cb, NL_CB_VALID, msg)
                    if err == NL_OK:
                        pass
                    elif err == NL_SKIP:
                        hdr = nlmsg_next(hdr, n)
                        continue
                    elif err == NL_STOP:
                        return -NLE_DUMP_INTR if interrupted else nrecv
                    else:
                        return -NLE_DUMP_INTR if interrupted else (err or nrecv)

            hdr = nlmsg_next(hdr, n)

        del buf[:]
        creds = None

        if multipart:
            # Multipart message not yet complete, continue reading.
            continue

        err = 0
        if interrupted:
            return -NLE_DUMP_INTR
        if not err:
            err = nrecv
        return err


def nl_recvmsgs_report(sk, cb):
    """Receive a set of messages from a Netlink socket and report parsed messages.
    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/nl.c#L998

    This function is identical to nl_recvmsgs() to the point that it will return the number of parsed messages instead
    of 0 on success.

    See nl_recvmsgs().

    Positional arguments:
    sk -- Netlink socket (nl_sock class instance).
    cb -- set of callbacks to control behaviour (nl_cb class instance).

    Returns:
    Number of received messages or a negative error code from nl_recv().
    """
    if cb.cb_recvmsgs_ow:
        return int(cb.cb_recvmsgs_ow(sk, cb))
    return int(recvmsgs(sk, cb))


def nl_recvmsgs(sk, cb):
    """Receive a set of messages from a Netlink socket.
    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/nl.c#L1023

    Repeatedly calls nl_recv() or the respective replacement if provided by the application (see nl_cb_overwrite_recv())
    and parses the received data as Netlink messages. Stops reading if one of the callbacks returns NL_STOP or nl_recv
    returns either 0 or a negative error code.

    A non-blocking sockets causes the function to return immediately if no data is available.

    See nl_recvmsgs_report().

    Positional arguments:
    sk -- Netlink socket (nl_sock class instance).
    cb -- set of callbacks to control behaviour (nl_cb class instance).

    Returns:
    0 on success or a negative error code from nl_recv().
    """
    err = nl_recvmsgs_report(sk, cb)
    if err > 0:
        return 0
    return int(err)


def nl_recvmsgs_default(sk):
    """Receive a set of message from a Netlink socket using handlers in nl_sock.
    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/nl.c#L1039

    Calls nl_recvmsgs() with the handlers configured in the Netlink socket.

    Positional arguments:
    sk -- Netlink socket (nl_sock class instance).

    Returns:
    0 on success or a negative error code from nl_recvmsgs().
    """
    return int(nl_recvmsgs(sk, sk.s_cb))


def wait_for_ack(sk):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink-private/netlink.h#L210

    Placing this here to avoid circular imports.

    Positional arguments:
    sk -- nl_sock class instance.

    Returns:
    Number of received messages or a negative error code from nl_recvmsgs().
    """
    if sk.s_flags & NL_NO_AUTO_ACK:
        return 0
    return nl_wait_for_ack(sk)


def nl_wait_for_ack(sk):
    """Wait for ACK.
    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/nl.c#L1058

    Waits until an ACK is received for the latest not yet acknowledged Netlink message.

    Positional arguments:
    sk -- Netlink socket (nl_sock class instance).

    Returns:
    Number of received messages or a negative error code from nl_recvmsgs().
    """
    cb = nl_cb_clone(sk.s_cb)
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, lambda *_: NL_STOP, None)
    return int(nl_recvmsgs(sk, cb))
