=======
 libnl
=======

A port of `libnl <http://www.infradead.org/~tgr/libnl/>`_, a collection of libraries providing APIs to the Netlink
protocol based Linux kernel interfaces. This library is API-equivalent to the original C library, and should make it
relatively easy to convert C programs into pure Python without having to call external binaries.

As Netlink is a Linux-specific protocol, this library will only work on Linux hosts. All communication is done using
sockets between the Python process and the Linux kernel. The main driver for porting libnl was to use
`nl80211 <https://wireless.wiki.kernel.org/en/developers/documentation/nl80211>`_ in Python to scan for wireless access
points natively, without having to run an external program and parse its output.

* Python 2.6, 2.7, PyPy, PyPy3, 3.3, and 3.4 supported on Linux

.. |buildWercker| image:: https://img.shields.io/wercker/ci/54f908261d0e8d4b221bfc9d.svg?style=flat-square
   :target: https://app.wercker.com/#applications/54f908261d0e8d4b221bfc9d
   :alt: Build Status WiFi

.. |buildTravis| image:: https://img.shields.io/travis/Robpol86/libnl/master.svg?style=flat-square
   :target: https://travis-ci.org/Robpol86/libnl
   :alt: Build Status

.. |coverage| image:: https://img.shields.io/codecov/c/github/Robpol86/libnl/master.svg?style=flat-square
   :target: https://codecov.io/github/Robpol86/libnl
   :alt: Coverage Status

.. |latestVersion| image:: https://img.shields.io/pypi/v/libnl.svg?style=flat-square
   :target: https://pypi.python.org/pypi/libnl/
   :alt: Latest Version

.. |downloads| image:: https://img.shields.io/pypi/dm/libnl.svg?style=flat-square
   :target: https://pypi.python.org/pypi/libnl/
   :alt: Downloads

============== ================ ============= =============== ===========
WiFi           Linux            Coverage      Latest          Downloads
============== ================ ============= =============== ===========
|buildWercker| |buildTravis|    |coverage|    |latestVersion| |downloads|
============== ================ ============= =============== ===========

`Quickstart`_
=============

Install:

.. code:: bash

    pip install libnl

`Example Implementations`_
==========================

A simple Python program that merely lists network adapters on the host:

.. code:: python

    import ctypes
    import socket

    from libnl.error import errmsg
    from libnl.handlers import NL_CB_CUSTOM, NL_CB_VALID, NL_OK
    from libnl.linux_private.if_link import IFLA_IFNAME, IFLA_RTA
    from libnl.linux_private.netlink import NETLINK_ROUTE, NLMSG_LENGTH, NLM_F_DUMP, NLM_F_REQUEST
    from libnl.linux_private.rtnetlink import RTA_DATA, RTA_NEXT, RTA_OK, RTM_GETLINK, ifinfomsg, rtgenmsg
    from libnl.misc import get_string
    from libnl.msg import nlmsg_data, nlmsg_hdr
    from libnl.nl import nl_connect, nl_recvmsgs_default, nl_send_simple
    from libnl.socket_ import nl_socket_alloc, nl_socket_modify_cb


    def callback(msg, _):
        nlh = nlmsg_hdr(msg)
        iface = ifinfomsg(nlmsg_data(nlh))
        hdr = IFLA_RTA(iface)
        remaining = ctypes.c_int(nlh.nlmsg_len - NLMSG_LENGTH(iface.SIZEOF))
        while RTA_OK(hdr, remaining):
            if hdr.rta_type == IFLA_IFNAME:
                print('Found interface {0}: {1}'.format(iface.ifi_index, get_string(RTA_DATA(hdr)).decode('ascii')))
            hdr = RTA_NEXT(hdr, remaining)
        return NL_OK


    sk = nl_socket_alloc()  # Creates an nl_sock instance.
    ret = nl_connect(sk, NETLINK_ROUTE)  # Create file descriptor and bind socket.
    if ret < 0:
        raise RuntimeError('nl_connect() returned {0} ({1})'.format(ret, errmsg[abs(ret)]))
    rt_hdr = rtgenmsg(rtgen_family=socket.AF_PACKET)
    ret = nl_send_simple(sk, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, rt_hdr, rt_hdr.SIZEOF)
    if ret < 0:
        raise RuntimeError('nl_send_simple() returned {0} ({1})'.format(ret, errmsg[abs(ret)]))
    nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, callback, None)  # Add callback to the nl_sock instance.
    ret = nl_recvmsgs_default(sk)  # Get kernel's answer, and call attached callbacks.
    if ret < 0:
        raise RuntimeError('nl_recvmsgs_default() returned {0} ({1})'.format(ret, errmsg[abs(ret)]))

Here are some more examples with their C equivalents in order from "easy" to "hard":

* `example_list_network_interfaces.py <https://github.com/Robpol86/libnl/blob/master/example_list_network_interfaces.py>`_ (`list_network_interfaces.c <https://github.com/Robpol86/libnl/blob/master/example_c/list_network_interfaces.c>`_)
* `example_show_wifi_interface.py <https://github.com/Robpol86/libnl/blob/master/example_show_wifi_interface.py>`_ (`show_wifi_interface.c <https://github.com/Robpol86/libnl/blob/master/example_c/show_wifi_interface.c>`_)
* `example_scan_access_points.py <https://github.com/Robpol86/libnl/blob/master/example_scan_access_points.py>`_ (`scan_access_points.c <https://github.com/Robpol86/libnl/blob/master/example_c/scan_access_points.c>`_)

`Changelog`_
============

This project adheres to `Semantic Versioning <http://semver.org/>`_.

`0.2.0 - 2015-03-26`_
---------------------

Added
    * Python2.6, PyPy, and PyPy3 support.

`0.1.1 - 2015-03-15`_
---------------------

* Initial release.
