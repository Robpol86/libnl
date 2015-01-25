"""Default Netlink Message Handlers (netlink/handlers.h) (lib/handlers.c).
https://github.com/thom311/libnl/blob/master/include/netlink/handlers.h
https://github.com/thom311/libnl/blob/master/lib/handlers.c

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from libnl.errno_ import NLE_RANGE
from libnl.netlink_private.types import nl_cb

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


def nl_valid_handler_verbose(msg, arg):
    """https://github.com/thom311/libnl/blob/master/lib/handlers.c#L45"""
    # TODO implement
    return NL_OK


def nl_invalid_handler_verbose(msg, arg):
    """https://github.com/thom311/libnl/blob/master/lib/handlers.c#L56"""
    # TODO implement
    return NL_STOP


def nl_overrun_handler_verbose(msg, arg):
    """https://github.com/thom311/libnl/blob/master/lib/handlers.c#L67"""
    # TODO implement
    return NL_STOP


def nl_error_handler_verbose(who, err, arg):
    """https://github.com/thom311/libnl/blob/master/lib/handlers.c#L78"""
    # TODO implement
    #return -nl_syserr2nlerr(err.error)
    raise NotImplementedError


def nl_valid_handler_debug(msg, arg):
    """https://github.com/thom311/libnl/blob/master/lib/handlers.c#L92"""
    # TODO implement
    return NL_OK


def nl_finish_handler_debug(msg, arg):
    """https://github.com/thom311/libnl/blob/master/lib/handlers.c#L103"""
    # TODO implement
    return NL_STOP


def nl_msg_in_handler_debug(msg, arg):
    """https://github.com/thom311/libnl/blob/master/lib/handlers.c#L114"""
    # TODO implement
    return NL_OK


def nl_msg_out_handler_debug(msg, arg):
    """https://github.com/thom311/libnl/blob/master/lib/handlers.c#L124"""
    # TODO implement
    return NL_OK


def nl_skipped_handler_debug(msg, arg):
    """https://github.com/thom311/libnl/blob/master/lib/handlers.c#L134"""
    # TODO implement
    return NL_SKIP


def nl_ack_handler_debug(msg, arg):
    """https://github.com/thom311/libnl/blob/master/lib/handlers.c#L145"""
    # TODO implement
    return NL_STOP


cb_def = {a: {b: None for b in range(NL_CB_KIND_MAX + 1)} for a in range(NL_CB_TYPE_MAX + 1)}
cb_def[NL_CB_VALID].update({NL_CB_VERBOSE: nl_valid_handler_verbose, NL_CB_DEBUG: nl_valid_handler_debug})
cb_def[NL_CB_FINISH].update({NL_CB_DEBUG: nl_finish_handler_debug})
cb_def[NL_CB_INVALID].update({NL_CB_VERBOSE: nl_invalid_handler_verbose, NL_CB_DEBUG: nl_invalid_handler_verbose})
cb_def[NL_CB_MSG_IN].update({NL_CB_DEBUG: nl_msg_in_handler_debug})
cb_def[NL_CB_MSG_OUT].update({NL_CB_DEBUG: nl_msg_out_handler_debug})
cb_def[NL_CB_OVERRUN].update({NL_CB_VERBOSE: nl_overrun_handler_verbose, NL_CB_DEBUG: nl_overrun_handler_verbose})
cb_def[NL_CB_SKIPPED].update({NL_CB_DEBUG: nl_skipped_handler_debug})
cb_def[NL_CB_ACK].update({NL_CB_DEBUG: nl_ack_handler_debug})
cb_err_def = {a: None for a in range(NL_CB_KIND_MAX + 1)}
cb_err_def.update({NL_CB_VERBOSE: nl_error_handler_verbose, NL_CB_DEBUG: nl_error_handler_verbose})


def nl_cb_alloc(kind):
    """Allocate a new callback handle.
    https://github.com/thom311/libnl/blob/master/lib/handlers.c#L201

    Positional arguments:
    kind -- callback kind to be used for initialization.

    Returns:
    Newly allocated callback handle (nl_cb class instance) or None.
    """
    if kind > NL_CB_KIND_MAX:
        return None
    cb = nl_cb()
    cb.cb_active = NL_CB_TYPE_MAX + 1
    for i in range(NL_CB_TYPE_MAX):
        nl_cb_set(cb, i, kind, None, None)
    nl_cb_err(cb, kind, None, None)
    return cb


def nl_cb_get(cb):
    """https://github.com/thom311/libnl/blob/master/lib/handlers.c#L244"""
    return cb


def nl_cb_set(cb, type_, kind, func, arg):
    """Set up a callback. Updates `cb` in place.
    https://github.com/thom311/libnl/blob/master/lib/handlers.c#L293

    Positional arguments:
    cb -- callback class instance.
    type_ -- callback to modify.
    kind -- kind of implementation.
    func -- callback function (NL_CB_CUSTOM).
    arg -- argument passed to callback.

    Returns:
    0 on success or a negative error code.
    """
    if type_ > NL_CB_TYPE_MAX or kind > NL_CB_KIND_MAX:
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
    https://github.com/thom311/libnl/blob/master/lib/handlers.c#L343

    Positional arguments:
    cb -- callback class instance.
    kind -- kind of callback.
    func -- callback function.
    arg -- argument to be passed to callback function.

    Returns:
    0 on success or a negative error code.
    """
    if kind > NL_CB_KIND_MAX:
        return -NLE_RANGE

    if kind == NL_CB_CUSTOM:
        cb.cb_err = func
        cb.cb_err_arg = arg
    else:
        cb.cb_err = cb_err_def[kind]
        cb.cb_err_arg = arg

    return 0
