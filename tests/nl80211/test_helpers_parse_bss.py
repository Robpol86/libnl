from datetime import timedelta
import base64

from libnl.attr import nla_parse, nla_parse_nested
from libnl.genl.genl import genlmsg_attrdata, genlmsg_attrlen
from libnl.linux_private.genetlink import genlmsghdr
from libnl.nl80211.helpers import parse_bss
from libnl.nl80211.iw_scan import bss_policy
from libnl.nl80211.nl80211 import NL80211_ATTR_MAX, NL80211_BSS_MAX, NL80211_ATTR_BSS


def test_no_security():
    """BSS 00:0d:67:23:b8:46(on wlan0)
    TSF: 1680943821184 usec (19d, 10:55:43)
    freq: 2412
    beacon interval: 100 TUs
    capability: ESS ShortPreamble ShortSlotTime (0x0421)
    signal: -66.00 dBm
    last seen: 4630 ms ago
    Information elements from Probe Response frame:
    SSID: CableWiFi
    Supported rates: 2.0* 5.5* 11.0* 6.0 9.0 12.0 18.0 24.0
    DS Parameter set: channel 1
    TIM: DTIM Count 0 DTIM Period 1 Bitmap Control 0x0 Bitmap[0] 0x0
    Country: US    Environment: Outdoor only
        Channels [1 - 11] @ 36 dBm
    ERP: <no flags>
    Extended supported rates: 36.0 48.0 54.0
    HT capabilities:
        Capabilities: 0x2d
            RX LDPC
            HT20
            SM Power Save disabled
            RX HT20 SGI
            No RX STBC
            Max AMSDU length: 3839 bytes
            No DSSS/CCK HT40
        Maximum RX AMPDU length 65535 bytes (exponent: 0x003)
        Minimum RX AMPDU time spacing: No restriction (0x00)
        HT RX MCS rate indexes supported: 0-23
        HT TX MCS rate indexes are undefined
    HT operation:
         * primary channel: 1
         * secondary channel offset: no secondary
         * STA channel width: 20 MHz
         * RIFS: 0
         * HT protection: nonmember
         * non-GF present: 0
         * OBSS non-GF present: 0
         * dual beacon: 0
         * dual CTS protection: 0
         * STBC beacon: 0
         * L-SIG TXOP Prot: 0
         * PCO active: 0
         * PCO phase: 0
    Overlapping BSS scan params:
         * passive dwell: 20 TUs
         * active dwell: 10 TUs
         * channel width trigger scan interval: 300 s
         * scan passive total per channel: 200 TUs
         * scan active total per channel: 20 TUs
         * BSS width channel transition delay factor: 5
         * OBSS Scan Activity Threshold: 0.25 %
    Extended capabilities: HT Information Exchange Supported, SSID List
    WMM:     * Parameter version 1
         * BE: CW 15-1023, AIFSN 3
         * BK: CW 15-1023, AIFSN 7
         * VI: CW 7-15, AIFSN 2, TXOP 3008 usec
         * VO: CW 3-7, AIFSN 2, TXOP 1504 usec
    """
    data = bytearray(base64.b64decode(
        b'IgEAAAgALgCJnxAACAADAAgAAAAMAJkAAQAAAAMAAACgAS8ACgABAAANZyO4RgAADAADAIAxD2CHAQAAowAGAAAJQ2FibGVXaUZpAQiEi5YME'
        b'hgkMAMBAQUEAAEAAAcGVVNPAQskKgEAMgNIYGwtGi0AA////wAAAAAAAAAAAAAAAAAABAbm5w0APRYBAAEAAAAAAAAAAAAAAAAAAAAAAAAASg'
        b'4UAAoALAHIABQABQAZAH8GAQAAAgAA3RgAUPICAQEHAAOkAAAnpAAAQkNeAGIyLwDdCQADfwEBAAD/fwAMAA0AgDEPYIcBAACjAAsAAAlDYWJ'
        b'sZVdpRmkBCISLlgwSGCQwAwEBBQQAAQAABwZVU08BCyQqAQAyA0hgbC0aLQAD////AAAAAAAAAAAAAAAAAAAEBubnDQA9FgEAAQAAAAAAAAAA'
        b'AAAAAAAAAAAAAABKDhQACgAsAcgAFAAFABkAfwYBAAACAADdGABQ8gIBAQcAA6QAACekAABCQ14AYjIvAN0JAAN/AQEAAP9/AAYABABkAAAAB'
        b'gAFACEEAAAIAAIAbAkAAAgADAAAAAAACAAKAGwgAAAIAAcAOOb//w=='
    ))
    gnlh = genlmsghdr(data)
    tb = {i: None for i in range(NL80211_ATTR_MAX + 1)}
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), None)
    bss = dict()
    nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS], bss_policy)
    bss_parsed = parse_bss(bss)
    assert '00:0d:67:23:b8:46' == bss_parsed['bssid']
    assert timedelta(microseconds=1680943821184) == bss_parsed['tsf']
    assert 2412 == bss_parsed['frequency']
    assert 100 == bss_parsed['beacon_interval']
    assert ['ESS', 'ShortPreamble', 'ShortSlotTime'] == sorted(bss_parsed['capability'])
    assert -66.0 == bss_parsed['signal']
    assert timedelta(milliseconds=4630) < bss_parsed['seen_ms_ago'] < timedelta(milliseconds=9999)
    assert u'CableWiFi' == bss_parsed['ssid']
    assert ['11.0*', '12.0', '18.0', '2.0*', '24.0', '5.5*', '6.0', '9.0'] == sorted(bss_parsed['supported_rates'])
    assert 1 == bss_parsed['channel']
    assert ['36.0', '48.0', '54.0'] == sorted(bss_parsed['extended_supported_rates'])
    assert 20 == bss_parsed['channel_width']
