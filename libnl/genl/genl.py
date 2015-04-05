"""Generic Netlink (lib/genl/genl.c).

https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/genl.c

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

import logging

from libnl.attr import nla_parse
from libnl.errno_ import NLE_MSG_TOOSHORT
from libnl.linux_private.genetlink import GENL_HDRLEN, genlmsghdr
from libnl.linux_private.netlink import NETLINK_GENERIC, nlattr, NLMSG_ALIGN, NLMSG_HDRLEN, nlmsghdr
from libnl.misc import bytearray_ptr
from libnl.msg import nlmsg_data, nlmsg_put, nlmsg_valid_hdr
from libnl.nl import nl_connect, nl_send_simple

_LOGGER = logging.getLogger(__name__)


def genl_connect(sk):
    """Connect a Generic Netlink socket.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/genl.c#L45

    This function expects a nl_socket class instance previously allocated via nl_socket_alloc(). It calls nl_connect()
    to create the local socket file descriptor and binds the socket to the NETLINK_GENERIC Netlink protocol.

    Using this function is equivalent to:
    nl_connect(sk, NETLINK_GENERIC)

    Positional arguments:
    sk -- unconnected Netlink socket (nl_sock class instance).

    Returns:
    0 on success or a negative error code.
    """
    return int(nl_connect(sk, NETLINK_GENERIC))


def genl_send_simple(sk, family, cmd, version, flags):
    """Send a Generic Netlink message consisting only of a header.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/genl.c#L84

    This function is a shortcut for sending a Generic Netlink message without any message payload. The message will only
    consist of the Netlink and Generic Netlink headers. The header is constructed based on the specified parameters and
    passed on to nl_send_simple() to send it on the specified socket.

    Positional arguments:
    sk -- Generic Netlink socket (nl_sock class instance).
    family -- numeric family identifier (integer).
    cmd -- numeric command identifier (integer).
    version -- interface version (integer).
    flags -- additional Netlink message flags (integer).

    Returns:
    0 on success or a negative error code.
    """
    hdr = genlmsghdr(cmd=cmd, version=version)
    return int(nl_send_simple(sk, family, flags, hdr, hdr.SIZEOF))


def genlmsg_valid_hdr(nlh, hdrlen):
    """Validate Generic Netlink message headers.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/genl.c#L117

    Verifies the integrity of the Netlink and Generic Netlink headers by enforcing the following requirements:
    - Valid Netlink message header (`nlmsg_valid_hdr()`)
    - Presence of a complete Generic Netlink header
    - At least `hdrlen` bytes of payload included after the generic Netlink header.

    Positional arguments:
    nlh -- Netlink message header (nlmsghdr class instance).
    hdrlen -- length of user header (integer).

    Returns:
    True if the headers are valid or False if not.
    """
    if not nlmsg_valid_hdr(nlh, GENL_HDRLEN):
        return False

    ghdr = genlmsghdr(nlmsg_data(nlh))
    if genlmsg_len(ghdr) < NLMSG_ALIGN(hdrlen):
        return False

    return True


def genlmsg_parse(nlh, hdrlen, tb, maxtype, policy):
    """Parse Generic Netlink message including attributes.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/genl.c#L191

    Verifies the validity of the Netlink and Generic Netlink headers using genlmsg_valid_hdr() and calls nla_parse() on
    the message payload to parse eventual attributes.

    Positional arguments:
    nlh -- Netlink message header (nlmsghdr class instance).
    hdrlen -- length of user header (integer).
    tb -- empty dict, to be updated with nlattr class instances to store parsed attributes.
    maxtype -- maximum attribute id expected (integer).
    policy -- dictionary of nla_policy class instances as values, with nla types as keys.

    Returns:
    0 on success or a negative error code.
    """
    if not genlmsg_valid_hdr(nlh, hdrlen):
        return -NLE_MSG_TOOSHORT

    ghdr = genlmsghdr(nlmsg_data(nlh))
    return int(nla_parse(tb, maxtype, genlmsg_attrdata(ghdr, hdrlen), genlmsg_attrlen(ghdr, hdrlen), policy))


def genlmsg_hdr(nlh):
    """Return reference to Generic Netlink header.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/genl.c#L210

    Positional arguments:
    nlh -- Netlink message header (nlmsghdr class instance).

    Returns:
    Reference to Generic Netlink message header.
    """
    return nlmsg_data(nlh)


def genlmsg_len(gnlh):
    """Return length of message payload including user header.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/genl.c#L224

    Positional arguments:
    gnlh -- Generic Netlink message header (genlmsghdr class instance).

    Returns:
    Length of user payload including an eventual user header in number of bytes.
    """
    nlh = nlmsghdr(bytearray_ptr(gnlh.bytearray, -NLMSG_HDRLEN, oob=True))
    return nlh.nlmsg_len - GENL_HDRLEN - NLMSG_HDRLEN


def genlmsg_user_hdr(gnlh):
    """Return bytearray_ptr of the user header.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/genl.c#L242

    Calculates the bytearray_ptr of the user header based on the Generic Netlink message header.

    Positional arguments:
    gnlh -- Generic Netlink message header (genlmsghdr class instance).

    Returns:
    bytearray_ptr of the user header.
    """
    return bytearray_ptr(gnlh.bytearray, GENL_HDRLEN)


def genlmsg_user_data(gnlh, hdrlen):
    """Return bytearray_ptr of the user data.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/genl.c#L259

    Calculates the bytearray_ptr of the user data based on the Generic Netlink message header.

    Positional arguments:
    gnlh -- Generic Netlink message header (genlmsghdr class instance).
    hdrlen -- length of user header (integer).

    Returns:
    bytearray_ptr of the user data.
    """
    return bytearray_ptr(genlmsg_user_hdr(gnlh), NLMSG_ALIGN(hdrlen))


def genlmsg_attrdata(gnlh, hdrlen):
    """Return nlattr at the start of message attributes.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/genl.c#L287

    Positional arguments:
    gnlh -- Generic Netlink message header (genlmsghdr class instance).
    hdrlen -- length of user header (integer).

    Returns:
    nlattr class instance with others in its payload.
    """
    return nlattr(genlmsg_user_data(gnlh, hdrlen))


def genlmsg_attrlen(gnlh, hdrlen):
    """Return length of message attributes.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/genl.c#L302

    Positional arguments:
    gnlh -- Generic Netlink message header (genlmsghdr class instance).
    hdrlen -- length of user header (integer).

    Returns:
    Length of the message section containing attributes in number of bytes.
    """
    return genlmsg_len(gnlh) - NLMSG_ALIGN(hdrlen)


def genlmsg_put(msg, port, seq, family, hdrlen, flags, cmd, version):
    """Add Generic Netlink headers to Netlink message.

    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/genl.c#L348

    Calls nlmsg_put() on the specified message object to reserve space for the Netlink header, the Generic Netlink
    header, and a user header of specified length. Fills out the header fields with the specified parameters.

    Positional arguments:
    msg -- Netlink message object (nl_msg class instance).
    port -- Netlink port or NL_AUTO_PORT (c_uint32).
    seq -- sequence number of message or NL_AUTO_SEQ (c_uint32).
    family -- numeric family identifier (integer).
    hdrlen -- length of user header (integer).
    flags -- additional Netlink message flags (integer).
    cmd -- numeric command identifier (c_uint8).
    version -- interface version (c_uint8).

    Returns:
    bytearray starting at user header or None if an error occurred.
    """
    hdr = genlmsghdr(cmd=cmd, version=version)
    nlh = nlmsg_put(msg, port, seq, family, GENL_HDRLEN + hdrlen, flags)
    if nlh is None:
        return None
    nlmsg_data(nlh)[:hdr.SIZEOF] = hdr.bytearray[:hdr.SIZEOF]
    _LOGGER.debug('msg 0x%x: Added generic netlink header cmd=%d version=%d', id(msg), cmd, version)
    return bytearray_ptr(nlmsg_data(nlh), GENL_HDRLEN)
