"""Default Netlink Message Handlers (netlink/handlers.h) (lib/handlers.c).

https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink/handlers.h
https://github.com/thom311/libnl/blob/libnl3_2_25/lib/handlers.c

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

import copy
import logging
from os import strerror

from libnl.errno_ import NLE_RANGE
from libnl.error import nl_syserr2nlerr
from libnl.msg import nl_msg_dump, nl_nlmsg_flags2str, nl_nlmsgtype2str, nlmsg_hdr
from libnl.netlink_private.types import nl_cb

_LOGGER = logging.getLogger(__name__)

NL_OK = 0  # Proceed with whatever would come next.
NL_SKIP = 1  # Skip this message.
NL_STOP = 2  # Stop parsing altogether and discard remaining messages.

NL_CB_DEFAULT = 0  # Default handlers (quiet).
NL_CB_VERBOSE = 1  # Verbose default handlers (error messages printed).
NL_CB_DEBUG = 2  # Debug handlers for debugging.
NL_CB_CUSTOM = 3  # Customized handler specified by the user.
NL_CB_KIND_MAX = NL_CB_CUSTOM

NL_CB_VALID = 0  # Message is valid.
NL_CB_FINISH = 1  # Last message in a series of multi part messages received.
NL_CB_OVERRUN = 2  # Report received that data was lost.
NL_CB_SKIPPED = 3  # Message wants to be skipped.
NL_CB_ACK = 4  # Message is an acknowledge.
NL_CB_MSG_IN = 5  # Called for every message received.
NL_CB_MSG_OUT = 6  # Called for every message sent out except for nl_sendto().
NL_CB_INVALID = 7  # Message is malformed and invalid.
NL_CB_SEQ_CHECK = 8  # Called instead of internal sequence number checking.
NL_CB_SEND_ACK = 9  # Sending of an acknowledge message has been requested.
NL_CB_DUMP_INTR = 10  # Flag NLM_F_DUMP_INTR is set in message.
NL_CB_TYPE_MAX = NL_CB_DUMP_INTR


def print_header_content(nlh):
    """Return header content (doesn't actually print like the C library does).

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/handlers.c#L34

    Positional arguments:
    nlh -- nlmsghdr class instance.
    """
    answer = 'type={0} length={1} flags=<{2}> sequence-nr={3} pid={4}'.format(
        nl_nlmsgtype2str(nlh.nlmsg_type, bytearray(), 32).decode('ascii'),
        nlh.nlmsg_len,
        nl_nlmsg_flags2str(nlh.nlmsg_flags, bytearray(), 128).decode('ascii'),
        nlh.nlmsg_seq,
        nlh.nlmsg_pid,
    )
    return answer


def nl_valid_handler_verbose(msg, arg):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/handlers.c#L45."""
    ofd = arg or _LOGGER.debug
    ofd('-- Warning: unhandled valid message: ' + print_header_content(nlmsg_hdr(msg)))
    return NL_OK


def nl_invalid_handler_verbose(msg, arg):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/handlers.c#L56."""
    ofd = arg or _LOGGER.debug
    ofd('-- Error: Invalid message: ' + print_header_content(nlmsg_hdr(msg)))
    return NL_STOP


def nl_overrun_handler_verbose(msg, arg):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/handlers.c#L67."""
    ofd = arg or _LOGGER.debug
    ofd('-- Error: Netlink Overrun: ' + print_header_content(nlmsg_hdr(msg)))
    return NL_STOP


def nl_error_handler_verbose(_, err, arg):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/handlers.c#L78."""
    ofd = arg or _LOGGER.debug
    ofd('-- Error received: ' + strerror(-err.error))
    ofd('-- Original message: ' + print_header_content(err.msg))
    return -nl_syserr2nlerr(err.error)


def nl_valid_handler_debug(msg, arg):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/handlers.c#L92."""
    ofd = arg or _LOGGER.debug
    ofd('-- Debug: Unhandled Valid message: ' + print_header_content(nlmsg_hdr(msg)))
    return NL_OK


def nl_finish_handler_debug(msg, arg):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/handlers.c#L103."""
    ofd = arg or _LOGGER.debug
    ofd('-- Debug: End of multipart message block: ' + print_header_content(nlmsg_hdr(msg)))
    return NL_STOP


def nl_msg_in_handler_debug(msg, arg):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/handlers.c#L114."""
    ofd = arg or _LOGGER.debug
    ofd('-- Debug: Received Message:')
    nl_msg_dump(msg, ofd)
    return NL_OK


def nl_msg_out_handler_debug(msg, arg):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/handlers.c#L124."""
    ofd = arg or _LOGGER.debug
    ofd('-- Debug: Sent Message:')
    nl_msg_dump(msg, ofd)
    return NL_OK


def nl_skipped_handler_debug(msg, arg):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/handlers.c#L134."""
    ofd = arg or _LOGGER.debug
    ofd('-- Debug: Skipped message: ' + print_header_content(nlmsg_hdr(msg)))
    return NL_SKIP


def nl_ack_handler_debug(msg, arg):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/handlers.c#L145."""
    ofd = arg or _LOGGER.debug
    ofd('-- Debug: ACK: ' + print_header_content(nlmsg_hdr(msg)))
    return NL_STOP


cb_def = dict((a, dict((b, None) for b in range(NL_CB_KIND_MAX + 1))) for a in range(NL_CB_TYPE_MAX + 1))
cb_def[NL_CB_VALID].update({NL_CB_VERBOSE: nl_valid_handler_verbose, NL_CB_DEBUG: nl_valid_handler_debug})
cb_def[NL_CB_FINISH].update({NL_CB_DEBUG: nl_finish_handler_debug})
cb_def[NL_CB_INVALID].update({NL_CB_VERBOSE: nl_invalid_handler_verbose, NL_CB_DEBUG: nl_invalid_handler_verbose})
cb_def[NL_CB_MSG_IN].update({NL_CB_DEBUG: nl_msg_in_handler_debug})
cb_def[NL_CB_MSG_OUT].update({NL_CB_DEBUG: nl_msg_out_handler_debug})
cb_def[NL_CB_OVERRUN].update({NL_CB_VERBOSE: nl_overrun_handler_verbose, NL_CB_DEBUG: nl_overrun_handler_verbose})
cb_def[NL_CB_SKIPPED].update({NL_CB_DEBUG: nl_skipped_handler_debug})
cb_def[NL_CB_ACK].update({NL_CB_DEBUG: nl_ack_handler_debug})
cb_err_def = dict((a, None) for a in range(NL_CB_KIND_MAX + 1))
cb_err_def.update({NL_CB_VERBOSE: nl_error_handler_verbose, NL_CB_DEBUG: nl_error_handler_verbose})


def nl_cb_alloc(kind):
    """Allocate a new callback handle.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/handlers.c#L201

    Positional arguments:
    kind -- callback kind to be used for initialization.

    Returns:
    Newly allocated callback handle (nl_cb class instance) or None.
    """
    if kind < 0 or kind > NL_CB_KIND_MAX:
        return None
    cb = nl_cb()
    cb.cb_active = NL_CB_TYPE_MAX + 1
    for i in range(NL_CB_TYPE_MAX):
        nl_cb_set(cb, i, kind, None, None)
    nl_cb_err(cb, kind, None, None)
    return cb


def nl_cb_clone(orig):
    """Clone an existing callback handle.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/handlers.c#L230

    Positional arguments:
    orig -- original callback handle (nl_cb class instance).

    Returns:
    New nl_cb instance being a duplicate of `orig`.
    """
    return copy.deepcopy(orig)


def nl_cb_get(cb):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/handlers.c#L244."""
    return cb


def nl_cb_set(cb, type_, kind, func, arg):
    """Set up a callback. Updates `cb` in place.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/handlers.c#L293

    Positional arguments:
    cb -- nl_cb class instance.
    type_ -- callback to modify (integer).
    kind -- kind of implementation (integer).
    func -- callback function (NL_CB_CUSTOM).
    arg -- argument passed to callback.

    Returns:
    0 on success or a negative error code.
    """
    if type_ < 0 or type_ > NL_CB_TYPE_MAX or kind < 0 or kind > NL_CB_KIND_MAX:
        return -NLE_RANGE

    if kind == NL_CB_CUSTOM:
        cb.cb_set[type_] = func
        cb.cb_args[type_] = arg
    else:
        cb.cb_set[type_] = cb_def[type_][kind]
        cb.cb_args[type_] = arg

    return 0


def nl_cb_err(cb, kind, func, arg):
    """Set up an error callback. Updates `cb` in place.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/handlers.c#L343

    Positional arguments:
    cb -- nl_cb class instance.
    kind -- kind of callback (integer).
    func -- callback function.
    arg -- argument to be passed to callback function.

    Returns:
    0 on success or a negative error code.
    """
    if kind < 0 or kind > NL_CB_KIND_MAX:
        return -NLE_RANGE

    if kind == NL_CB_CUSTOM:
        cb.cb_err = func
        cb.cb_err_arg = arg
    else:
        cb.cb_err = cb_err_def[kind]
        cb.cb_err_arg = arg

    return 0


def nl_cb_overwrite_recv(cb, func):
    """Overwrite internal calls to nl_recv().

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/handlers.c#L383

    Positional arguments:
    cb -- nl_cb class instance.
    func -- replacement callback for nl_recv() (a function with args (sk, nla, buf, creds)).
    """
    cb.cb_recv_ow = func


def nl_cb_overwrite_send(cb, func):
    """Overwrite internal calls to nl_send().

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/handlers.c#L395

    Positional arguments:
    cb -- nl_cb class instance.
    func -- replacement callback for nl_send() (a function with args (sk, msg)).
    """
    cb.cb_send_ow = func
