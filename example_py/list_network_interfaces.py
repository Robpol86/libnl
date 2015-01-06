#!/usr/bin/env python
"""Lists network interfaces on the host through Netlink (Linux only).

Python version of the C program located at:
https://github.com/Robpol86/wifinl/blob/master/example_c/list_network_interfaces.c

Requires:
pip install pyroute2 docopt

Usage:
    list_network_interfaces.py print
    list_network_interfaces.py -h | --help
"""

from __future__ import print_function
from _socket import AF_UNSPEC
import signal
import sys

from docopt import docopt
from pyroute2.netlink import NLM_F_DUMP, NLM_F_REQUEST
from pyroute2.netlink.rtnl import ifinfmsg, IPRSocket, RTM_GETLINK

OPTIONS = docopt(__doc__) if __name__ == '__main__' else dict()


def main():
    # Easy way: [dict(i['attrs'])['IFLA_IFNAME'] for i in pyroute2.IPRoute().get_links()]

    # Open socket to the kernel.
    nl_sock = IPRSocket()
    nl_sock.bind()

    # Send the request for all network interfaces.
    rtgenmsg = ifinfmsg()
    rtgenmsg['family'] = AF_UNSPEC
    ret = nl_sock.nlm_request(rtgenmsg, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP)

    # Print the kernel's answer.
    for iface in ret:
        print('Found network interface %d: %s' % (iface['index'], dict(iface['attrs'])['IFLA_IFNAME']))


if __name__ == '__main__':
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))  # Properly handle Control+C
    main()
