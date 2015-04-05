"""Generic Netlink Family (lib/genl/family.c).

https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/family.c

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from libnl.linux_private.genetlink import GENL_ID_GENERATE
from libnl.list_ import nl_init_list_head, nl_list_add_tail, nl_list_del, nl_list_for_each_entry_safe, nl_list_head
from libnl.netlink_private.object_api import nl_object_ops
from libnl.netlink_private.types import genl_family, genl_family_grp, genl_family_op
from libnl.object import nl_object_alloc
from libnl.types import NL_DUMP_DETAILS, NL_DUMP_LINE, NL_DUMP_STATS

FAMILY_ATTR_ID = 0x01
FAMILY_ATTR_NAME = 0x02
FAMILY_ATTR_VERSION = 0x04
FAMILY_ATTR_HDRSIZE = 0x08
FAMILY_ATTR_MAXATTR = 0x10
FAMILY_ATTR_OPS = 0x20


def family_constructor(c):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/family.c#L37.

    Positional arguments:
    c -- nl_object-derived class instance.
    """
    family = c
    if not hasattr(family, 'gf_ops'):
        setattr(family, 'gf_ops', nl_list_head(container_of=family))
    if not hasattr(family, 'gf_mc_grps'):
        setattr(family, 'gf_mc_grps', nl_list_head(container_of=family))
    nl_init_list_head(family.gf_ops)
    nl_init_list_head(family.gf_mc_grps)


def family_free_data(c):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/family.c#L45.

    Positional arguments:
    c -- nl_object-derived class instance.
    """
    family = c
    if not hasattr(family, 'gf_ops'):
        setattr(family, 'gf_ops', nl_list_head(container_of=family))
    if not hasattr(family, 'gf_mc_grps'):
        setattr(family, 'gf_mc_grps', nl_list_head(container_of=family))
    ops = tmp = genl_family_op()
    grp = t_grp = genl_family_grp()
    if family is None:
        return
    for ops in nl_list_for_each_entry_safe(ops, tmp, family.gf_ops, 'o_list'):
        nl_list_del(ops.o_list)
    for grp in nl_list_for_each_entry_safe(grp, t_grp, family.gf_mc_grps, 'list_'):
        nl_list_del(grp.list_)


def family_clone(dst, src):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/family.c#L66.

    Positional arguments:
    dst -- nl_object class instance.
    src -- nl_object class instance.

    Returns:
    Integer.
    """
    raise NotImplementedError


def family_dump_line(obj, p):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/family.c#L90.

    Positional arguments:
    obj -- nl_object class instance.
    p -- nl_dump_params class instance.
    """
    raise NotImplementedError


def family_dump_details(obj, p):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/family.c#L110.

    Positional arguments:
    obj -- nl_object class instance.
    p -- nl_dump_params class instance.
    """
    raise NotImplementedError


def family_dump_stats(obj, p):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/family.c#L145.

    Positional arguments:
    obj -- nl_object class instance.
    p -- nl_dump_params class instance.
    """
    family_dump_details(obj, p)


def family_compare(a, b, attrs, flags):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/family.c#L150.

    Positional arguments:
    a -- nl_object class instance.
    b -- nl_object class instance.
    attrs -- integer.
    flags -- integer.

    Returns:
    Integer.
    """
    raise NotImplementedError


def genl_family_alloc():
    """Instantiate new Generic Netlink family object.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/family.c#L181

    Returns:
    New `genl_family` class instance.
    """
    return genl_family(nl_object_alloc(genl_family_ops))


def genl_family_get_id(family):
    """Return numeric identifier.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/family.c#L213

    Positional arguments:
    family -- Generic Netlink family object (genl_family class instance).

    Returns:
    Numeric identifier or 0 if not available.
    """
    return int(family.gf_id if family.ce_mask & FAMILY_ATTR_ID else GENL_ID_GENERATE)


def genl_family_set_id(family, id_):
    """Set the numeric identifier.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/family.c#L226

    Positional arguments:
    family -- Generic Netlink family object (genl_family class instance).
    id_ -- new numeric identifier (integer).
    """
    family.gf_id = id_
    family.ce_mask |= FAMILY_ATTR_ID


def genl_family_set_name(family, name):
    """Set human readable name.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/family.c#L258

    Positional arguments:
    family -- Generic Netlink family object (genl_family class instance).
    name -- new human readable name (bytes()).
    """
    family.gf_name = name
    family.ce_mask |= FAMILY_ATTR_NAME


def genl_family_add_grp(family, id_, name):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/family.c#L366.

    Positional arguments:
    family -- Generic Netlink family object (genl_family class instance).
    id_ -- new numeric identifier (integer).
    name -- new human readable name (string).

    Returns:
    0
    """
    grp = genl_family_grp(id_=id_, name=name)
    nl_list_add_tail(grp.list_, family.gf_mc_grps)
    return 0


genl_family_ops = nl_object_ops(  # https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/family.c#L386
    oo_name='genl/family',
    oo_size=genl_family.SIZEOF,
    oo_constructor=family_constructor,
    oo_free_data=family_free_data,
    oo_clone=family_clone,
    oo_dump={NL_DUMP_LINE: family_dump_line, NL_DUMP_DETAILS: family_dump_details, NL_DUMP_STATS: family_dump_stats},
    oo_compare=family_compare,
    oo_id_attrs=FAMILY_ATTR_ID,
)
