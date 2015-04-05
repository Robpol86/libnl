#!/usr/bin/env python
"""Perform a scan for wireless access points and prints them in a table.

Root access is required to issue a scan request to the kernel.

This is a pure-Python port of the C program available here:
    github.com/Robpol86/libnl/blob/8f35e52/example_c/scan_access_points.c

This script is a showcase for the Linux Netlink libnl Python library, ported
from the C library with the same name. Using libnl, Python scripts/applications
can communicate with the Linux kernel and device drivers directly just like
C/C++ programs do, without having to call a binary on the system.

More information about the Python libnl is available here:
    https://github.com/Robpol86/libnl

Debug messages are available with the -v option, and even more debug messages
are available by setting the NLCB environment variable to either 'verbose' or
'debug' like so:
    NLCB=debug example_scan_access_points.py -v wlan0

Usage:
    example_show_wifi_interface.py [-k COLUMN] [-n] [-r] [-v ...] <interface>
    example_show_wifi_interface.py -h | --help

Options:
    -k --key=COLUMN     Sort table by column name (case insensitive).
                        [default: SSID]
    -n --no-sudo        Don't trigger a scan. Attempt to read previous scan's
                        results. Use this if you use something like
                        `sudo iw dev wlan0 scan` very recently. The kernel may
                        still have the results stored in memory.
    -r --reverse        Reverse the results.
    -v --verbose        Print debug messages to stderr. Specify twice for more.
"""

from __future__ import print_function

import ctypes
import fcntl
import logging
import math
import os
import signal
import socket
import struct
import sys
import time

from docopt import docopt
from terminaltables import AsciiTable

import libnl.handlers
from libnl.attr import nla_parse, nla_parse_nested, nla_put, nla_put_nested, nla_put_u32
from libnl.error import errmsg
from libnl.genl.ctrl import genl_ctrl_resolve, genl_ctrl_resolve_grp
from libnl.genl.genl import genl_connect, genlmsg_attrdata, genlmsg_attrlen, genlmsg_put
from libnl.linux_private.genetlink import genlmsghdr
from libnl.linux_private.netlink import NLM_F_DUMP
from libnl.msg import nlmsg_alloc, nlmsg_data, nlmsg_hdr
from libnl.nl import nl_recvmsgs, nl_send_auto
from libnl.nl80211 import nl80211
from libnl.nl80211.helpers import parse_bss
from libnl.nl80211.iw_scan import bss_policy
from libnl.socket_ import nl_socket_add_membership, nl_socket_alloc, nl_socket_drop_membership

_LOGGER = logging.getLogger(__name__)
COLUMNS = ['SSID', 'Security', 'Channel', 'Frequency', 'Signal', 'BSSID']
OPTIONS = docopt(__doc__) if __name__ == '__main__' else dict()


def error(message, code=1):
    """Print an error message to stderr and exits with a status of 1 by default."""
    if message:
        print('ERROR: {0}'.format(message), file=sys.stderr)
    else:
        print(file=sys.stderr)
    sys.exit(code)


def ok(no_exit, func, *args, **kwargs):
    """Exit if `ret` is not OK (a negative number)."""
    ret = func(*args, **kwargs)
    if no_exit or ret >= 0:
        return ret
    reason = errmsg[abs(ret)]
    error('{0}() returned {1} ({2})'.format(func.__name__, ret, reason))


def error_handler(_, err, arg):
    """Update the mutable integer `arg` with the error code."""
    arg.value = err.error
    return libnl.handlers.NL_STOP


def ack_handler(_, arg):
    """Update the mutable integer `arg` with 0 as an acknowledgement."""
    arg.value = 0
    return libnl.handlers.NL_STOP


def callback_trigger(msg, arg):
    """Called when the kernel is done scanning. Only signals if it was successful or if it failed. No other data.

    Positional arguments:
    msg -- nl_msg class instance containing the data sent by the kernel.
    arg -- mutable integer (ctypes.c_int()) to update with results.

    Returns:
    An integer, value of NL_SKIP. It tells libnl to stop calling other callbacks for this message and proceed with
    processing the next kernel message.
    """
    gnlh = genlmsghdr(nlmsg_data(nlmsg_hdr(msg)))
    if gnlh.cmd == nl80211.NL80211_CMD_SCAN_ABORTED:
        arg.value = 1  # The scan was aborted for some reason.
    elif gnlh.cmd == nl80211.NL80211_CMD_NEW_SCAN_RESULTS:
        arg.value = 0  # The scan completed successfully. `callback_dump` will collect the results later.
    return libnl.handlers.NL_SKIP


def callback_dump(msg, results):
    """Here is where SSIDs and their data is decoded from the binary data sent by the kernel.

    This function is called once per SSID. Everything in `msg` pertains to just one SSID.

    Positional arguments:
    msg -- nl_msg class instance containing the data sent by the kernel.
    results -- dictionary to populate with parsed data.
    """
    bss = dict()  # To be filled by nla_parse_nested().

    # First we must parse incoming data into manageable chunks and check for errors.
    gnlh = genlmsghdr(nlmsg_data(nlmsg_hdr(msg)))
    tb = dict((i, None) for i in range(nl80211.NL80211_ATTR_MAX + 1))
    nla_parse(tb, nl80211.NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), None)
    if not tb[nl80211.NL80211_ATTR_BSS]:
        print('WARNING: BSS info missing for an access point.')
        return libnl.handlers.NL_SKIP
    if nla_parse_nested(bss, nl80211.NL80211_BSS_MAX, tb[nl80211.NL80211_ATTR_BSS], bss_policy):
        print('WARNING: Failed to parse nested attributes for an access point!')
        return libnl.handlers.NL_SKIP
    if not bss[nl80211.NL80211_BSS_BSSID]:
        print('WARNING: No BSSID detected for an access point!')
        return libnl.handlers.NL_SKIP
    if not bss[nl80211.NL80211_BSS_INFORMATION_ELEMENTS]:
        print('WARNING: No additional information available for an access point!')
        return libnl.handlers.NL_SKIP

    # Further parse and then store. Overwrite existing data for BSSID if scan is run multiple times.
    bss_parsed = parse_bss(bss)
    results[bss_parsed['bssid']] = bss_parsed
    return libnl.handlers.NL_SKIP


def do_scan_trigger(sk, if_index, driver_id, mcid):
    """Issue a scan request to the kernel and wait for it to reply with a signal.

    This function issues NL80211_CMD_TRIGGER_SCAN which requires root privileges.

    The way NL80211 works is first you issue NL80211_CMD_TRIGGER_SCAN and wait for the kernel to signal that the scan is
    done. When that signal occurs, data is not yet available. The signal tells us if the scan was aborted or if it was
    successful (if new scan results are waiting). This function handles that simple signal.

    May exit the program (sys.exit()) if a fatal error occurs.

    Positional arguments:
    sk -- nl_sock class instance (from nl_socket_alloc()).
    if_index -- interface index (integer).
    driver_id -- nl80211 driver ID from genl_ctrl_resolve() (integer).
    mcid -- nl80211 scanning group ID from genl_ctrl_resolve_grp() (integer).

    Returns:
    0 on success or a negative error code.
    """
    # First get the "scan" membership group ID and join the socket to the group.
    _LOGGER.debug('Joining group %d.', mcid)
    ret = nl_socket_add_membership(sk, mcid)  # Listen for results of scan requests (aborted or new results).
    if ret < 0:
        return ret

    # Build the message to be sent to the kernel.
    msg = nlmsg_alloc()
    genlmsg_put(msg, 0, 0, driver_id, 0, 0, nl80211.NL80211_CMD_TRIGGER_SCAN, 0)  # Setup which command to run.
    nla_put_u32(msg, nl80211.NL80211_ATTR_IFINDEX, if_index)  # Setup which interface to use.
    ssids_to_scan = nlmsg_alloc()
    nla_put(ssids_to_scan, 1, 0, b'')  # Scan all SSIDs.
    nla_put_nested(msg, nl80211.NL80211_ATTR_SCAN_SSIDS, ssids_to_scan)  # Setup what kind of scan to perform.

    # Setup the callbacks to be used for triggering the scan only.
    err = ctypes.c_int(1)  # Used as a mutable integer to be updated by the callback function. Signals end of messages.
    results = ctypes.c_int(-1)  # Signals if the scan was successful (new results) or aborted, or not started.
    cb = libnl.handlers.nl_cb_alloc(libnl.handlers.NL_CB_DEFAULT)
    libnl.handlers.nl_cb_set(cb, libnl.handlers.NL_CB_VALID, libnl.handlers.NL_CB_CUSTOM, callback_trigger, results)
    libnl.handlers.nl_cb_err(cb, libnl.handlers.NL_CB_CUSTOM, error_handler, err)
    libnl.handlers.nl_cb_set(cb, libnl.handlers.NL_CB_ACK, libnl.handlers.NL_CB_CUSTOM, ack_handler, err)
    libnl.handlers.nl_cb_set(cb, libnl.handlers.NL_CB_SEQ_CHECK, libnl.handlers.NL_CB_CUSTOM,
                             lambda *_: libnl.handlers.NL_OK, None)  # Ignore sequence checking.

    # Now we send the message to the kernel, and retrieve the acknowledgement. The kernel takes a few seconds to finish
    # scanning for access points.
    _LOGGER.debug('Sending NL80211_CMD_TRIGGER_SCAN...')
    ret = nl_send_auto(sk, msg)
    if ret < 0:
        return ret
    while err.value > 0:
        _LOGGER.debug('Retrieving NL80211_CMD_TRIGGER_SCAN acknowledgement...')
        ret = nl_recvmsgs(sk, cb)
        if ret < 0:
            return ret
    if err.value < 0:
        error('Unknown error {0} ({1})'.format(err.value, errmsg[abs(err.value)]))

    # Block until the kernel is done scanning or aborted the scan.
    while results.value < 0:
        _LOGGER.debug('Retrieving NL80211_CMD_TRIGGER_SCAN final response...')
        ret = nl_recvmsgs(sk, cb)
        if ret < 0:
            return ret
    if results.value > 0:
        error('The kernel aborted the scan.')

    # Done, cleaning up.
    _LOGGER.debug('Leaving group %d.', mcid)
    return nl_socket_drop_membership(sk, mcid)  # No longer need to receive multicast messages.


def do_scan_results(sk, if_index, driver_id, results):
    """Retrieve the results of a successful scan (SSIDs and data about them).

    This function does not require root privileges. It eventually calls a callback that actually decodes data about
    SSIDs but this function kicks that off.

    May exit the program (sys.exit()) if a fatal error occurs.

    Positional arguments:
    sk -- nl_sock class instance (from nl_socket_alloc()).
    if_index -- interface index (integer).
    driver_id -- nl80211 driver ID from genl_ctrl_resolve() (integer).
    results -- dictionary to populate with results. Keys are BSSIDs (MAC addresses) and values are dicts of data.

    Returns:
    0 on success or a negative error code.
    """
    msg = nlmsg_alloc()
    genlmsg_put(msg, 0, 0, driver_id, 0, NLM_F_DUMP, nl80211.NL80211_CMD_GET_SCAN, 0)
    nla_put_u32(msg, nl80211.NL80211_ATTR_IFINDEX, if_index)
    cb = libnl.handlers.nl_cb_alloc(libnl.handlers.NL_CB_DEFAULT)
    libnl.handlers.nl_cb_set(cb, libnl.handlers.NL_CB_VALID, libnl.handlers.NL_CB_CUSTOM, callback_dump, results)
    _LOGGER.debug('Sending NL80211_CMD_GET_SCAN...')
    ret = nl_send_auto(sk, msg)
    if ret >= 0:
        _LOGGER.debug('Retrieving NL80211_CMD_GET_SCAN response...')
        ret = nl_recvmsgs(sk, cb)
    return ret


def eta_letters(seconds):
    """Convert seconds remaining into human readable strings.

    From https://github.com/Robpol86/etaprogress/blob/ad934d4/etaprogress/components/eta_conversions.py.

    Positional arguments:
    seconds -- integer/float indicating seconds remaining.
    """
    final_days, final_hours, final_minutes, final_seconds = 0, 0, 0, seconds
    if final_seconds >= 86400:
        final_days = int(final_seconds / 86400.0)
        final_seconds -= final_days * 86400
    if final_seconds >= 3600:
        final_hours = int(final_seconds / 3600.0)
        final_seconds -= final_hours * 3600
    if final_seconds >= 60:
        final_minutes = int(final_seconds / 60.0)
        final_seconds -= final_minutes * 60
    final_seconds = int(math.ceil(final_seconds))

    if final_days:
        template = '{1:d}d {2:d}h {3:02d}m {4:02d}s'
    elif final_hours:
        template = '{2:d}h {3:02d}m {4:02d}s'
    elif final_minutes:
        template = '{3:02d}m {4:02d}s'
    else:
        template = '{4:02d}s'

    return template.format(final_days, final_hours, final_minutes, final_seconds)


def print_table(data):
    """Print the table of detected SSIDs and their data to screen.

    Positional arguments:
    data -- list of dictionaries.
    """
    table = AsciiTable([COLUMNS])
    table.justify_columns[2] = 'right'
    table.justify_columns[3] = 'right'
    table.justify_columns[4] = 'right'
    table_data = list()
    for row_in in data:
        row_out = [
            str(row_in.get('ssid', '')).replace('\0', ''),
            str(row_in.get('security', '')),
            str(row_in.get('channel', '')),
            str(row_in.get('frequency', '')),
            str(row_in.get('signal', '')),
            str(row_in.get('bssid', '')),
        ]
        if row_out[3]:
            row_out[3] += ' MHz'
        if row_out[4]:
            row_out[4] += ' dBm'
        table_data.append(row_out)

    sort_by_column = [c.lower() for c in COLUMNS].index(OPTIONS['--key'].lower())
    table_data.sort(key=lambda c: c[sort_by_column], reverse=OPTIONS['--reverse'])

    table.table_data.extend(table_data)
    print(table.table)


def main():
    """Main function called upon script execution."""
    # First get the wireless interface index.
    pack = struct.pack('16sI', OPTIONS['<interface>'].encode('ascii'), 0)
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = struct.unpack('16sI', fcntl.ioctl(sk.fileno(), 0x8933, pack))
    except OSError:
        return error('Wireless interface {0} does not exist.'.format(OPTIONS['<interface>']))
    finally:
        sk.close()
    if_index = int(info[1])

    # Next open a socket to the kernel and bind to it. Same one used for sending and receiving.
    sk = nl_socket_alloc()  # Creates an `nl_sock` instance.
    ok(0, genl_connect, sk)  # Create file descriptor and bind socket.
    _LOGGER.debug('Finding the nl80211 driver ID...')
    driver_id = ok(0, genl_ctrl_resolve, sk, b'nl80211')
    _LOGGER.debug('Finding the nl80211 scanning group ID...')
    mcid = ok(0, genl_ctrl_resolve_grp, sk, b'nl80211', b'scan')

    # Scan for access points 1 or more (if requested) times.
    if not OPTIONS['--no-sudo']:
        print('Scanning for access points, may take about 8 seconds...')
    else:
        print("Attempting to read results of previous scan.")
    results = dict()
    for i in range(2, -1, -1):  # Three tries on errors.
        if not OPTIONS['--no-sudo']:
            ret = ok(i, do_scan_trigger, sk, if_index, driver_id, mcid)
            if ret < 0:
                _LOGGER.warning('do_scan_trigger() returned %d, retrying in 5 seconds.', ret)
                time.sleep(5)
                continue
        ret = ok(i, do_scan_results, sk, if_index, driver_id, results)
        if ret < 0:
            _LOGGER.warning('do_scan_results() returned %d, retrying in 5 seconds.', ret)
            time.sleep(5)
            continue
        break
    if not results:
        print('No access points detected.')
        return

    # Print results.
    print('Found {0} access points:'.format(len(results)))
    print_table(results.values())


def setup_logging():
    """Called when __name__ == '__main__' below. Sets up logging library.

    All logging messages go to stderr, from DEBUG to CRITICAL. This script uses print() for regular messages.
    """
    fmt = 'DBG<0>%(pathname)s:%(lineno)d  %(funcName)s: %(message)s'

    handler_stderr = logging.StreamHandler(sys.stderr)
    handler_stderr.setFormatter(logging.Formatter(fmt))
    if OPTIONS['--verbose'] == 1:
        handler_stderr.addFilter(logging.Filter(__name__))

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(handler_stderr)


if __name__ == '__main__':
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))  # Properly handle Control+C
    if OPTIONS.get('--verbose'):
        setup_logging()
    else:
        logging.disable(logging.CRITICAL)
    if OPTIONS['--key'].lower() not in [c.lower() for c in COLUMNS]:
        error('Invalid column specified. Must be one of: {0}'.format(' '.join(COLUMNS)))
    if os.getuid() and not OPTIONS['--no-sudo']:
        print('WARNING: Script should be run as root. Might get error -28.')
    main()
