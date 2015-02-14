"""Netlink Messages Interface (lib/msg.c).
https://github.com/thom311/libnl/blob/master/lib/msg.c
https://github.com/thom311/libnl/blob/master/include/netlink/msg.h

Netlink message construction/parsing interface.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from libnl.attr import nla_for_each_attr, nla_find
from libnl.linux_private.netlink import nlmsghdr, NLMSG_ERROR, NLMSG_HDRLEN
from libnl.netlink_private.types import nl_msg, NL_MSG_CRED_PRESENT

NL_AUTO_PORT = 0
NL_AUTO_PID = NL_AUTO_PORT
NL_AUTO_SEQ = 0


def nlmsg_data(nlh):
    """Return the message payload.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L105

    Positional arguments:
    nlh -- netlink message header (nlmsghdr class instance).

    Returns:
    Message payload (list of objects).
    """
    return nlh.payload


def nlmsg_for_each_attr(nlh):
    """Iterate over a stream of attributes in a message.
    https://github.com/thom311/libnl/blob/master/include/netlink/msg.h#L123

    Positional arguments:
    nlh -- netlink message header (nlmsghdr class instance).

    Returns:
    Generator yielding nl_attr instances.
    """
    return nla_for_each_attr(nlh.payload)


def nlmsg_datalen(nlh):
    """Return length of message payload.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L121

    Positional arguments:
    nlh -- netlink message header (nlmsghdr class instance).

    Returns:
    Length of message payload in bytes.
    """
    return nlh.nlmsg_len - NLMSG_HDRLEN


nlmsg_len = nlmsg_datalen  # Alias. https://github.com/thom311/libnl/blob/master/lib/msg.c#L126


def nlmsg_attrdata(nlh):
    """Returns list of attributes/payload from netlink message header.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L143

    Positional arguments:
    nlh -- netlink message header (nlmsghdr class instance).

    Returns:
    List of attributes.
    """
    return nlh.payload


def nlmsg_find_attr(nlh, attrtype):
    """Find a specific attribute in a netlink message.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L231

    Positional arguments:
    nlh -- netlink message header (nlmsghdr class instance).
    attrtype -- type of attribute to look for.

    Returns:
    The first attribute which matches the specified type (nlattr class instance).
    """
    return nla_find(nlmsg_attrdata(nlh), attrtype)


def nlmsg_alloc():
    """Instantiate a new netlink message.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L299

    Instantiates a new netlink message without any further payload.

    Returns:
    Newly allocated netlink message.
    """
    nm = nl_msg()
    nm.nm_nlh = nlmsghdr()
    nm.nm_refcnt = 1
    nm.nm_protocol = -1
    return nm


def nlmsg_inherit(hdr=None):
    """Allocate a new netlink message and inherit netlink message header.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L322

    Allocates a new netlink message and inherits the original message header. If `hdr` is not None it will be used as a
    template for the netlink message header, otherwise the header is left blank.

    Keyword arguments:
    hdr -- netlink message header template (nlmsghdr class instance).

    Returns:
    Newly allocated netlink message (nl_msg class instance) or None.
    """
    nm = nlmsg_alloc()
    if hdr:
        new = nm.nm_nlh
        new.nlmsg_type = hdr.nlmsg_type
        new.nlmsg_flags = hdr.nlmsg_flags
        new.nlmsg_seq = hdr.nlmsg_seq
        new.nlmsg_pid = hdr.nlmsg_pid
    return nm


def nlmsg_alloc_simple(nlmsgtype, flags):
    """Allocate a new netlink message.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L346

    Positional arguments:
    nlmsgtype -- netlink message type (integer).
    flags -- message flags (integer).

    Returns:
    Newly allocated netlink message (nl_msg class instance) or None.
    """
    nlh = nlmsghdr(nlmsg_type=nlmsgtype, nlmsg_flags=flags)
    msg = nlmsg_inherit(nlh)
    return msg


def nlmsg_convert(hdr):
    """Convert a netlink message received from a netlink socket to a nl_msg.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L382

    Allocates a new netlink message and copies all of the data pointed to by `hdr` into the new message object.

    Positional arguments:
    hdr -- nlmsghdr class instance.

    Returns:
    New nl_msg class instance derived,
    """
    nm = nlmsg_alloc()
    nm.nm_nlh = hdr
    return nm


def nlmsg_append(msg, data):
    """Append data to tail of a netlink message.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L442

    Positional arguments:
    msg -- netlink message (nl_msg class instance).
    data -- data to add.

    Returns:
    0 on success or a negative error code.
    """
    msg.nm_nlh.payload.append(data)
    return 0


def nlmsg_hdr(msg):
    """Return actual netlink message.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L536

    Returns the actual netlink message.

    Positional arguments:
    msg -- netlink message (nl_msg class instance).

    Returns:
    The netlink message object.
    """
    return msg.nm_nlh


def nlmsg_set_proto(msg, protocol):
    """https://github.com/thom311/libnl/blob/master/lib/msg.c#L584

    Positional arguments:
    msg -- netlink message (nl_msg class instance).
    protocol -- integer.
    """
    msg.nm_protocol = protocol


def nlmsg_set_src(msg, addr):
    """https://github.com/thom311/libnl/blob/master/lib/msg.c#L599"""
    msg.nm_src = addr


def nlmsg_get_dst(msg):
    """https://github.com/thom311/libnl/blob/master/lib/msg.c#L614"""
    return msg.nm_dst


def nlmsg_get_creds(msg):
    """https://github.com/thom311/libnl/blob/master/lib/msg.c#L625"""
    if msg.nm_flags & NL_MSG_CRED_PRESENT:
        return msg.nm_creds
    return None


def print_hdr(ofd, msg):
    """https://github.com/thom311/libnl/blob/master/lib/msg.c#L793

    Positional arguments:
    ofd -- handle to write to (open(), sys.stdout, etc.).
    msg -- message to print (nl_msg class instance).
    """
    nlh = nlmsg_hdr(msg)
    pass  # not done, TODO https://github.com/Robpol86/libnl/issues/7


def dump_error_msg(msg, ofd):
    """https://github.com/thom311/libnl/blob/master/lib/msg.c#L908
    Positional arguments:
    msg -- message to print (nl_msg class instance).
    ofd -- handle to write to (open(), sys.stdout, etc.).
    """
    hdr = nlmsg_hdr(msg)
    err = nlmsg_data(hdr)

    ofd.write('  [ERRORMSG] {0} octets\n'.format(err.SIZEOF))
    pass  # not done, TODO https://github.com/Robpol86/libnl/issues/7


def print_msg(msg, ofd, hdr):
    """https://github.com/thom311/libnl/blob/master/lib/msg.c#L929

    Positional arguments:
    msg -- netlink message (nl_msg class instance).
    ofd -- handle to write to (open(), sys.stdout, etc.).
    hdr -- netlink message header (nlmsghdr class instance).
    """
    pass  # TODO https://github.com/Robpol86/libnl/issues/7


def nl_msg_dump(msg, ofd):
    """Dump message in human readable format to handle.
    https://github.com/thom311/libnl/blob/master/lib/msg.c#L970

    Positional arguments:
    msg -- message to print (nl_msg class instance).
    ofd -- handle to write to (open(), sys.stdout, etc.).
    """
    hdr = nlmsg_hdr(msg)

    ofd.write('--------------------------   BEGIN NETLINK MESSAGE ---------------------------\n')

    ofd.write('  [NETLINK HEADER] {0} octets\n'.format(hdr.SIZEOF))
    print_hdr(ofd, msg)

    if hdr.nlmsg_type == NLMSG_ERROR:
        dump_error_msg(msg, ofd)
    elif nlmsg_len(hdr) > 0:
        print_msg(msg, ofd, hdr)

    ofd.write('---------------------------  END NETLINK MESSAGE   ---------------------------\n')
