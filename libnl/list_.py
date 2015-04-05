"""Netlink List Utilities (netlink/list.h).

https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink/list.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""


class nl_list_head(object):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink/list.h#L15.

    Instance variables:
    next_ -- reference to the next nl_list_head instance.
    prev -- reference to the previous nl_list_head instance.
    container_of -- parent object referencing the nl_list_head instance. Mitigates lack of pointers in Python.
    """

    def __init__(self, next_=None, prev=None, container_of=None):
        """Constructor."""
        self.next_ = next_
        self.prev = prev
        self.container_of = container_of


def _nl_list_add(obj, prev, next_):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink/list.h#L27.

    Positional arguments:
    obj -- nl_list_head class instance.
    prev -- nl_list_head class instance.
    next_ -- nl_list_head class instance.
    """
    prev.next_ = obj
    obj.prev = prev
    next_.prev = obj
    obj.next_ = next_


def nl_list_add_tail(obj, head):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink/list.h#L37.

    Positional arguments:
    obj -- nl_list_head class instance.
    head -- nl_list_head class instance.
    """
    _nl_list_add(obj, head.prev, head)


def nl_list_add_head(obj, head):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink/list.h#L43.

    Positional arguments:
    obj -- nl_list_head class instance.
    head -- nl_list_head class instance.
    """
    _nl_list_add(obj, head, head.next_)


def nl_list_del(obj):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink/list.h#L49.

    Positional arguments:
    obj -- nl_list_head class instance.
    """
    obj.next.prev = obj.prev
    obj.prev.next_ = obj.next_


def nl_list_entry(ptr, type_, member):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink/list.h#L64."""
    if ptr.container_of:
        return ptr.container_of
    null_data = type_()
    setattr(null_data, member, ptr)
    return null_data


def nl_list_for_each_entry(pos, head, member):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink/list.h#L79.

    Positional arguments:
    pos -- class instance holding an nl_list_head instance.
    head -- nl_list_head class instance.
    member -- attribute (string).

    Returns:
    Generator yielding a class instances.
    """
    pos = nl_list_entry(head.next_, type(pos), member)
    while True:
        yield pos
        if getattr(pos, member) != head:
            pos = nl_list_entry(getattr(pos, member).next_, type(pos), member)
            continue
        break


def nl_list_for_each_entry_safe(pos, n, head, member):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink/list.h#L84.

    Positional arguments:
    pos -- class instance holding an nl_list_head instance.
    n -- class instance holding an nl_list_head instance.
    head -- nl_list_head class instance.
    member -- attribute (string).

    Returns:
    Generator yielding a class instances.
    """
    pos = nl_list_entry(head.next_, type(pos), member)
    n = nl_list_entry(pos.member.next_, type(pos), member)
    while True:
        yield pos
        if getattr(pos, member) != head:
            pos = n
            n = nl_list_entry(n.member.next_, type(n), member)
            continue
        break


def nl_init_list_head(head):
    """https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink/list.h#L90."""
    head.next_ = head
    head.prev = head
