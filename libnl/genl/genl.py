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
from libnl.linux_private.netlink import NETLINK_GENERIC, NLMSG_ALIGN, NLMSG_HDRLEN
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
    return int(nl_send_simple(sk, family, flags, hdr))


def genlmsg_valid_hdr(nlh, hdrlen):
    """Validate Generic Netlink message headers.
    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/genl.c#L117

    Verifies the integrity of the Netlink and Generic Netlink headers by enforcing the following requirements:
    - Valid Netlink message header (`nlmsg_valid_hdr()`)
    - Presence of a complete Generic Netlink header
    - At least `hdrlen` bytes of payload included after the generic netlink header.

    Positional arguments:
    nlh -- Netlink message header (nlmsghdr class instance).
    hdrlen -- length of user header.

    Returns:
    True if the headers are valid or False if not.
    """
    if not nlmsg_valid_hdr(nlh, GENL_HDRLEN):
        return False

    if nlh.nlmsg_len - GENL_HDRLEN - NLMSG_HDRLEN < NLMSG_ALIGN(hdrlen):
        return False

    return True


def genlmsg_parse(nlh, hdrlen, tb, maxtype, policy):
    """Parse Generic Netlink message including attributes.
    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/genl.c#L191

    Verifies the validity of the Netlink and Generic Netlink headers using genlmsg_valid_hdr() and calls nla_parse() on
    the message payload to parse eventual attributes.

    Positional arguments:
    nlh -- Netlink message header (nlmsghdr class instance).
    hdrlen -- length of user header.
    tb -- empty dict, to be updated with nlattr class instances to store parsed attributes.
    maxtype -- maximum attribute id expected.
    policy -- attribute validation policy.

    Returns:
    0 on success or a negative error code.
    """
    if not genlmsg_valid_hdr(nlh, hdrlen):
        return -NLE_MSG_TOOSHORT

    ghdr = genlmsghdr.from_buffer(nlmsg_data(nlh))
    return nla_parse(tb, maxtype, genlmsg_attrdata(ghdr, hdrlen), policy)


def genlmsg_attrdata(gnlh, _):
    """Return list of message attributes.
    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/genl.c#L287

    Positional arguments:
    gnlh -- Generic Netlink message header (genlmsghdr class instance).

    Returns:
    List of message attributes.
    """
    return gnlh.payload


def genlmsg_put(msg, port, seq, family, _, flags, cmd, version):
    """Add Generic Netlink headers to Netlink message.
    https://github.com/thom311/libnl/blob/libnl3_2_25/lib/genl/genl.c#L348

    Calls nlmsg_put() on the specified message object to reserve space for the Netlink header, the Generic Netlink
    header, and a user header of specified length. Fills out the header fields with the specified parameters.

    Positional arguments:
    msg -- Netlink message object (nl_msg class instance).
    port -- Netlink port or NL_AUTO_PORT.
    seq -- sequence number of message or NL_AUTO_SEQ.
    family -- numeric family identifier.
    flags -- additional Netlink message flags.
    cmd -- numeric command identifier.
    version -- interface version.

    Returns:
    genlmsghdr class instance.
    """
    hdr = genlmsghdr(cmd=cmd, version=version)
    nlh = nlmsg_put(msg, port, seq, family, flags)
    nlh.payload.append(hdr)
    _LOGGER.debug('msg 0x%x: Added generic netlink header cmd=%d version=%d', id(msg), cmd, version)
    return hdr
