"""Utility Functions (lib/utils.c).
https://github.com/thom311/libnl/blob/master/lib/utils.c

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""


def __type2str(type_, tbl):
    """https://github.com/thom311/libnl/blob/master/lib/utils.c#L968

    Positional arguments:
    type_ -- integer, key to lookup in `tbl`.
    tbl -- dict.

    Returns:
    String, a value from `tbl`.
    """
    if type_ in tbl:
        return str(tbl[type_])
    return '0x{0:x}'.format(type_)
