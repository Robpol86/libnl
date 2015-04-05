"""Error Numbers (netlink/errno.h).

https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink/errno.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""


NLE_SUCCESS = 0
NLE_FAILURE = 1
NLE_INTR = 2
NLE_BAD_SOCK = 3
NLE_AGAIN = 4
NLE_NOMEM = 5
NLE_EXIST = 6
NLE_INVAL = 7
NLE_RANGE = 8
NLE_MSGSIZE = 9
NLE_OPNOTSUPP = 10
NLE_AF_NOSUPPORT = 11
NLE_OBJ_NOTFOUND = 12
NLE_NOATTR = 13
NLE_MISSING_ATTR = 14
NLE_AF_MISMATCH = 15
NLE_SEQ_MISMATCH = 16
NLE_MSG_OVERFLOW = 17
NLE_MSG_TRUNC = 18
NLE_NOADDR = 19
NLE_SRCRT_NOSUPPORT = 20
NLE_MSG_TOOSHORT = 21
NLE_MSGTYPE_NOSUPPORT = 22
NLE_OBJ_MISMATCH = 23
NLE_NOCACHE = 24
NLE_BUSY = 25
NLE_PROTO_MISMATCH = 26
NLE_NOACCESS = 27
NLE_PERM = 28
NLE_PKTLOC_FILE = 29
NLE_PARSE_ERR = 30
NLE_NODEV = 31
NLE_IMMUTABLE = 32
NLE_DUMP_INTR = 33
NLE_MAX = NLE_DUMP_INTR
