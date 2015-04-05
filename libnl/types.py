"""Definition of public types (netlink/types.h).

https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink/types.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""


NL_DUMP_LINE = 0  # Dump object briefly on one line.
NL_DUMP_DETAILS = 1  # Dump all attributes but no statistics.
NL_DUMP_STATS = 2  # Dump all attributes including statistics.
NL_DUMP_MAX = NL_DUMP_STATS
