"""Utility Functions (lib/utils.c).

https://github.com/thom311/libnl/blob/libnl3_2_25/lib/utils.c

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""


def __type2str(type_, buf, _, tbl):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/utils.c#L968.

    Positional arguments:
    type_ -- integer, key to lookup in `tbl`.
    buf -- bytearray().
    _ -- unused.
    tbl -- dict.

    Returns:
    Reference to `buf`.
    """
    del buf[:]
    if type_ in tbl:
        buf.extend(tbl[type_].encode('ascii'))
    else:
        buf.extend('0x{0:x}'.format(type_).encode('ascii'))
    return buf
