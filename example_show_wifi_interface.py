#!/usr/bin/env python
"""Shows basic info about a wireless interface through Netlink (Linux only).

Python version of the C program located at:
https://github.com/Robpol86/wifipy/blob/master/example_c/show_wifi_interface.c

Requires:
pip install pyroute2 docopt

Usage:
    show_wifi_interface.py wlan0
    show_wifi_interface.py all
    show_wifi_interface.py -h | --help
"""

from __future__ import print_function
import signal
import socket
import sys

from docopt import docopt

from libnl.genl.ctrl import genl_ctrl_resolve

OPTIONS = docopt(__doc__) if __name__ == '__main__' else dict()


def main():
    if_index = socket.if_nametoindex('wlan0')

    # Open socket to the kernel.
    nl_sock = socket.socket(socket.AF_NETLINK)
    driver_id = genl_ctrl_resolve(socket, "nl80211")

    # Send the request for all network interfaces.
    msg = genlmsg()
    msg['attrs'] = [[NL80211_ATTR_IFINDEX], if_index]
    msg.encode()
    ret = nl_sock.nlm_request(msg, NL80211_CMD_GET_INTERFACE, 0)
    # TODO broken


if __name__ == '__main__':
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))  # Properly handle Control+C
    main()
