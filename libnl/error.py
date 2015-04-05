"""Error Handling (lib/error.c).

https://github.com/thom311/libnl/blob/libnl3_2_25/lib/error.c

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

import errno

import libnl.errno_

errmsg = dict((i, '') for i in range(libnl.errno_.NLE_MAX + 1))
errmsg.update({  # https://github.com/thom311/libnl/blob/libnl3_2_25/lib/error.c#L15
    libnl.errno_.NLE_SUCCESS: 'Success',
    libnl.errno_.NLE_FAILURE: 'Unspecific failure',
    libnl.errno_.NLE_INTR: 'Interrupted system call',
    libnl.errno_.NLE_BAD_SOCK: 'Bad socket',
    libnl.errno_.NLE_AGAIN: 'Try again',
    libnl.errno_.NLE_NOMEM: 'Out of memory',
    libnl.errno_.NLE_EXIST: 'Object exists',
    libnl.errno_.NLE_INVAL: 'Invalid input data or parameter',
    libnl.errno_.NLE_RANGE: 'Input data out of range',
    libnl.errno_.NLE_MSGSIZE: 'Message size not sufficient',
    libnl.errno_.NLE_OPNOTSUPP: 'Operation not supported',
    libnl.errno_.NLE_AF_NOSUPPORT: 'Address family not supported',
    libnl.errno_.NLE_OBJ_NOTFOUND: 'Object not found',
    libnl.errno_.NLE_NOATTR: 'Attribute not available',
    libnl.errno_.NLE_MISSING_ATTR: 'Missing attribute',
    libnl.errno_.NLE_AF_MISMATCH: 'Address family mismatch',
    libnl.errno_.NLE_SEQ_MISMATCH: 'Message sequence number mismatch',
    libnl.errno_.NLE_MSG_OVERFLOW: 'Kernel reported message overflow',
    libnl.errno_.NLE_MSG_TRUNC: 'Kernel reported truncated message',
    libnl.errno_.NLE_NOADDR: 'Invalid address for specified address family',
    libnl.errno_.NLE_SRCRT_NOSUPPORT: 'Source based routing not supported',
    libnl.errno_.NLE_MSG_TOOSHORT: 'Netlink message is too short',
    libnl.errno_.NLE_MSGTYPE_NOSUPPORT: 'Netlink message type is not supported',
    libnl.errno_.NLE_OBJ_MISMATCH: 'Object type does not match cache',
    libnl.errno_.NLE_NOCACHE: 'Unknown or invalid cache type',
    libnl.errno_.NLE_BUSY: 'Object busy',
    libnl.errno_.NLE_PROTO_MISMATCH: 'Protocol mismatch',
    libnl.errno_.NLE_NOACCESS: 'No Access',
    libnl.errno_.NLE_PERM: 'Operation not permitted',
    libnl.errno_.NLE_PKTLOC_FILE: 'Unable to open packet location file',
    libnl.errno_.NLE_PARSE_ERR: 'Unable to parse object',
    libnl.errno_.NLE_NODEV: 'No such device',
    libnl.errno_.NLE_IMMUTABLE: 'Immutable attribute',
    libnl.errno_.NLE_DUMP_INTR: 'Dump inconsistency detected, interrupted',
})


def nl_syserr2nlerr(error_):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/error.c#L84."""
    error_ = abs(error_)
    legend = {
        errno.EBADF: libnl.errno_.NLE_BAD_SOCK,
        errno.EADDRINUSE: libnl.errno_.NLE_EXIST,
        errno.EEXIST: libnl.errno_.NLE_EXIST,
        errno.EADDRNOTAVAIL: libnl.errno_.NLE_NOADDR,
        errno.ESRCH: libnl.errno_.NLE_OBJ_NOTFOUND,
        errno.ENOENT: libnl.errno_.NLE_OBJ_NOTFOUND,
        errno.EINTR: libnl.errno_.NLE_INTR,
        errno.EAGAIN: libnl.errno_.NLE_AGAIN,
        errno.ENOTSOCK: libnl.errno_.NLE_BAD_SOCK,
        errno.ENOPROTOOPT: libnl.errno_.NLE_INVAL,
        errno.EFAULT: libnl.errno_.NLE_INVAL,
        errno.EACCES: libnl.errno_.NLE_NOACCESS,
        errno.EINVAL: libnl.errno_.NLE_INVAL,
        errno.ENOBUFS: libnl.errno_.NLE_NOMEM,
        errno.ENOMEM: libnl.errno_.NLE_NOMEM,
        errno.EAFNOSUPPORT: libnl.errno_.NLE_AF_NOSUPPORT,
        errno.EPROTONOSUPPORT: libnl.errno_.NLE_PROTO_MISMATCH,
        errno.EOPNOTSUPP: libnl.errno_.NLE_OPNOTSUPP,
        errno.EPERM: libnl.errno_.NLE_PERM,
        errno.EBUSY: libnl.errno_.NLE_BUSY,
        errno.ERANGE: libnl.errno_.NLE_RANGE,
        errno.ENODEV: libnl.errno_.NLE_NODEV,
    }
    return int(legend.get(error_, libnl.errno_.NLE_FAILURE))
