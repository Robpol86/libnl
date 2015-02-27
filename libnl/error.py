"""Error Handling (lib/error.c).
https://github.com/thom311/libnl/blob/libnl3_2_25/lib/error.c

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from errno import *

from libnl.errno_ import *

errmsg = {i: '' for i in range(NLE_MAX + 1)}
errmsg.update({  # https://github.com/thom311/libnl/blob/libnl3_2_25/lib/error.c#L15
    NLE_SUCCESS: 'Success',
    NLE_FAILURE: 'Unspecific failure',
    NLE_INTR: 'Interrupted system call',
    NLE_BAD_SOCK: 'Bad socket',
    NLE_AGAIN: 'Try again',
    NLE_NOMEM: 'Out of memory',
    NLE_EXIST: 'Object exists',
    NLE_INVAL: 'Invalid input data or parameter',
    NLE_RANGE: 'Input data out of range',
    NLE_MSGSIZE: 'Message size not sufficient',
    NLE_OPNOTSUPP: 'Operation not supported',
    NLE_AF_NOSUPPORT: 'Address family not supported',
    NLE_OBJ_NOTFOUND: 'Object not found',
    NLE_NOATTR: 'Attribute not available',
    NLE_MISSING_ATTR: 'Missing attribute',
    NLE_AF_MISMATCH: 'Address family mismatch',
    NLE_SEQ_MISMATCH: 'Message sequence number mismatch',
    NLE_MSG_OVERFLOW: 'Kernel reported message overflow',
    NLE_MSG_TRUNC: 'Kernel reported truncated message',
    NLE_NOADDR: 'Invalid address for specified address family',
    NLE_SRCRT_NOSUPPORT: 'Source based routing not supported',
    NLE_MSG_TOOSHORT: 'Netlink message is too short',
    NLE_MSGTYPE_NOSUPPORT: 'Netlink message type is not supported',
    NLE_OBJ_MISMATCH: 'Object type does not match cache',
    NLE_NOCACHE: 'Unknown or invalid cache type',
    NLE_BUSY: 'Object busy',
    NLE_PROTO_MISMATCH: 'Protocol mismatch',
    NLE_NOACCESS: 'No Access',
    NLE_PERM: 'Operation not permitted',
    NLE_PKTLOC_FILE: 'Unable to open packet location file',
    NLE_PARSE_ERR: 'Unable to parse object',
    NLE_NODEV: 'No such device',
    NLE_IMMUTABLE: 'Immutable attribute',
    NLE_DUMP_INTR: 'Dump inconsistency detected, interrupted',
})


def nl_syserr2nlerr(error_):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/error.c#L84"""
    error_ = abs(error_)
    legend = {
        EBADF: NLE_BAD_SOCK,
        EADDRINUSE: NLE_EXIST,
        EEXIST: NLE_EXIST,
        EADDRNOTAVAIL: NLE_NOADDR,
        ESRCH: NLE_OBJ_NOTFOUND,
        ENOENT: NLE_OBJ_NOTFOUND,
        EINTR: NLE_INTR,
        EAGAIN: NLE_AGAIN,
        ENOTSOCK: NLE_BAD_SOCK,
        ENOPROTOOPT: NLE_INVAL,
        EFAULT: NLE_INVAL,
        EACCES: NLE_NOACCESS,
        EINVAL: NLE_INVAL,
        ENOBUFS: NLE_NOMEM,
        ENOMEM: NLE_NOMEM,
        EAFNOSUPPORT: NLE_AF_NOSUPPORT,
        EPROTONOSUPPORT: NLE_PROTO_MISMATCH,
        EOPNOTSUPP: NLE_OPNOTSUPP,
        EPERM: NLE_PERM,
        EBUSY: NLE_BUSY,
        ERANGE: NLE_RANGE,
        ENODEV: NLE_NODEV,
    }
    return int(legend.get(error_, NLE_FAILURE))
