#!/usr/bin/env python
"""Shows basic info about a wireless interface through Netlink (Linux only).

Python version of the C program located at:
https://github.com/Robpol86/wifinl/blob/master/example_c/show_wifi_interface.c

Requires:
pip install pyroute2 docopt

Usage:
    show_wifi_interface.py wlan0
    show_wifi_interface.py all
    show_wifi_interface.py -h | --help
"""

from __future__ import print_function
import signal
import sys

from docopt import docopt
from pyroute2 import IPRoute
from pyroute2.netlink import genlmsg
from pyroute2.netlink.generic import GenericNetlinkSocket

NL80211_ATTR_IFINDEX = 3
NL80211_CMD_GET_INTERFACE = 5
OPTIONS = docopt(__doc__) if __name__ == '__main__' else dict()


def main():
    ip = IPRoute()
    if_index = ip.link_lookup(ifname='wlan0')[0]
    ip.close()

    # Open socket to the kernel.
    nl_sock = GenericNetlinkSocket()
    nl_sock.marshal.msg_map[NL80211_CMD_GET_INTERFACE] = genlmsg
    nl_sock.bind('nl80211', genlmsg)

    # Send the request for all network interfaces.
    msg = genlmsg()
    msg['attrs'] = [[NL80211_ATTR_IFINDEX], if_index]
    msg.encode()
    ret = nl_sock.nlm_request(msg, NL80211_CMD_GET_INTERFACE, 0)
    # TODO broken


if __name__ == '__main__':
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))  # Properly handle Control+C
    main()
