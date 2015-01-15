"""Port of Generic Netlink Controller (lib/genl/ctrl.c) C library.
http://www.infradead.org/~tgr/libnl/doc/api/ctrl_8c_source.html

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""


def genl_ctrl_probe_by_name(sk, name):
    """Look up generic netlink family by family name querying the kernel directly.

    Modeled after:
    http://www.infradead.org/~tgr/libnl/doc/api/ctrl_8c_source.html#l00237

    Positional arguments:
    sk -- Generic Netlink socket.
    name -- family name.
    """
    pass


def genl_ctrl_resolve(sk, name):
    """Resolve Generic Netlink family name to numeric identifier.

    Resolves the Generic Netlink family name to the corresponding numeric family identifier. This function queries the
    kernel directly

    Modeled after:
    http://www.infradead.org/~tgr/libnl/doc/api/ctrl_8c_source.html#l00429

    Positional arguments:
    sk -- Generic Netlink socket.
    name -- name of Generic Netlink family.

    Returns:
    Numeric family identifier (integer).
    """
    pass


def genl_ctrl_resolve_grp(sk, family_name, grp_name):
    """Resolve Generic Netlink family group name.

    Modeled after:
    http://www.infradead.org/~tgr/libnl/doc/api/ctrl_8c_source.html#l00471

    Positional arguments:
    sk -- Generic Netlink socket.
    family_name -- name of Generic Netlink family.
    grp_name -- name of group to resolve.

    Returns:
    Numeric group identifier (integer).
    """
    family = genl_family()
