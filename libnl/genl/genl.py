"""Generic Netlink (lib/genl/genl.c).
https://github.com/thom311/libnl/blob/master/lib/genl/genl.c

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

from ctypes import byref, cast, POINTER

from libnl.attr import nla_parse
from libnl.errno import NLE_MSG_TOOSHORT
from libnl.linux_private.genetlink import GENL_HDRLEN
from libnl.linux_private.netlink import NLMSG_ALIGN, NLMSG_HDRLEN, nlmsghdr
from libnl.msg import nlmsg_data, nlmsg_valid_hdr


def genlmsg_valid_hdr(nlh, hdrlen):
    """Validate Generic Netlink message headers.
    https://github.com/thom311/libnl/blob/master/lib/genl/genl.c#L117

    Verifies the integrity of the Netlink and Generic Netlink headers by enforcing the following requirements:
        - Valid Netlink message header (nlmsg_valid_hdr()).
        - Presence of a complete Generic Netlink header.
        - At least \c hdrlen bytes of payload included after the generic netlink header.

    Returns:
    A positive integer (True) if the headers are valid or 0 (False) if not.
    """
    if not nlmsg_valid_hdr(nlh, GENL_HDRLEN):
        return 0
    ghdr = nlmsg_data(nlh)
    if genlmsg_len(ghdr) < NLMSG_ALIGN(hdrlen):
        return 0
    return 1


def genlmsg_parse(nlh, hdrlen, tb, maxtype, policy):
    """Parse Generic Netlink message including attributes.
    https://github.com/thom311/libnl/blob/master/lib/genl/genl.c#L191

    Verifies the validity of the Netlink and Generic Netlink headers using genlmsg_valid_hdr() and calls nla_parse() on
    the message payload to parse eventual attributes.

    Positional arguments:
    nlh -- pointer to Netlink message header.
    hdrlen -- length of user header.
    tb -- array to store parsed attributes.
    maxtype -- maximum attribute id expected.
    policy -- attribute validation policy.

    Returns:
    0 on success or a negative error code.
    """
    if not genlmsg_valid_hdr(nlh, hdrlen):
        return -NLE_MSG_TOOSHORT
    ghdr = nlmsg_data(nlh)
    _gad = genlmsg_attrdata(ghdr, hdrlen)
    _gal = genlmsg_attrlen(ghdr, hdrlen)
    return int(nla_parse(tb, maxtype, _gad, _gal, policy))


def genlmsg_len(gnlh):
    """Return length of message payload including user header.
    https://github.com/thom311/libnl/blob/master/lib/genl/genl.c#L224

    Positional arguments:
    gnlh -- generic Netlink message header.

    Returns:
    Length of user payload including an eventual user header in number of bytes.
    """
    nlh = cast(byref(gnlh, -NLMSG_HDRLEN), POINTER(nlmsghdr))
    return int(nlh.nlmsg_len - GENL_HDRLEN - NLMSG_HDRLEN)


def genlmsg_user_hdr(gnlh):
    """Return pointer to user header.
    https://github.com/thom311/libnl/blob/master/lib/genl/genl.c#L242

    Calculates the pointer to the user header based on the pointer to the Generic Netlink message header.

    Positional arguments:
    gnlh -- generic Netlink message header.

    Returns:
    Pointer to the user header.
    """
    return genlmsg_data(gnlh)


def genlmsg_user_data(gnlh, hdrlen):
    """Return pointer to user data.
    https://github.com/thom311/libnl/blob/master/lib/genl/genl.c#L259

    Calculates the pointer to the user data based on the pointer to the Generic Netlink message header.

    Positional arguments:
    gnlh -- generic Netlink message header.
    hdrlen -- length of user header.

    Returns:
    Pointer to the user data.
    """
    return genlmsg_user_hdr(gnlh) + NLMSG_ALIGN(hdrlen)


def genlmsg_attrdata(gnlh, hdrlen):
    """Return pointer to message attributes.
    https://github.com/thom311/libnl/blob/master/lib/genl/genl.c#L287

    Positional arguments:
    gnlh -- generic Netlink message header.
    hdrlen -- length of user header.

    Returns:
    Pointer to the start of the message's attributes section.
    """
    return genlmsg_user_data(gnlh, hdrlen)


def genlmsg_attrlen(gnlh, hdrlen):
    """Return length of message attributes.
    https://github.com/thom311/libnl/blob/master/lib/genl/genl.c#L302

    Positional arguments:
    gnlh -- generic Netlink message header.
    hdrlen -- length of user header.

    Returns:
    Length of the message section containing attributes in number of bytes.
    """
    _gml = genlmsg_len(gnlh)
    _nma = NLMSG_ALIGN(hdrlen)
    return int(_gml - _nma)


def genlmsg_data(gnlh):
    """(Deprecated) Return pointer to message payload.
    https://github.com/thom311/libnl/blob/master/lib/genl/genl.c#L385

    This function has been deprecated due to inability to specify the length of the user header. Use genlmsg_user_hdr()
    respectively genlmsg_user_data().

    Positional arguments:
    gnlh -- generic Netlink message header.

    Returns:
    Pointer to payload section.
    """
    return byref(gnlh, GENL_HDRLEN)
