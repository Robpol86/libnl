"""Generic Netlink Controller (lib/genl/ctrl.c).
https://github.com/thom311/libnl/blob/master/lib/genl/ctrl.c

Resolves Generic Netlink family names to numeric identifiers.

The controller is a component in the kernel that resolves Generic Netlink family names to their numeric identifiers.
This module provides functions to query the controller to access the resolving functionality.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from wifipy.backends.netlink.types import genl_family


def genl_ctrl_probe_by_name(sk, name):
    """Look up generic netlink family by family name querying the kernel directly.
    https://github.com/thom311/libnl/blob/master/lib/genl/ctrl.c#L237

    Directly query's the kernel for a given family name. The caller will own a reference on the returned object which
    needs to be given back after usage using genl_family_put.

    Note: This API call differs from genl_ctrl_search_by_name in that it queries the kernel directly, allowing for
    module autoload to take place to resolve the family request. Using an nl_cache prevents that operation.

    Positional arguments:
    sk -- generic netlink socket.
    name -- family name.

    Returns:
    Generic netlink family object or None if no match was found.
    """
    ret = genl_family_alloc()  # TODO


def genl_ctrl_resolve(sk, name):
    """Resolve Generic Netlink family name to numeric identifier.
    https://github.com/thom311/libnl/blob/master/lib/genl/ctrl.c#L429

    Resolves the Generic Netlink family name to the corresponding numeric family identifier. This function queries the
    kernel directly, use genl_ctrl_search_by_name() if you need to resolve multiple names.

    Positional arguments:
    sk -- generic netlink socket.
    name -- name of generic netlink family.

    Returns:
    The numeric family identifier or a negative error code.
    """
    pass  # TODO


def genl_ctrl_resolve_grp(sk, family_name, grp_name):
    """Resolve Generic Netlink family group name.
    https://github.com/thom311/libnl/blob/master/lib/genl/ctrl.c#L471

    Looks up the family object and resolves the group name to the numeric group identifier.

    Positional arguments:
    sk -- generic netlink socket.
    family_name -- name of generic netlink family.
    grp_name -- name of group to resolve.

    Returns:
    Numeric group identifier or a negative error code.
    """
    family = genl_family()  # TODO
