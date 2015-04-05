"""Convenience methods for nl80211."""

from datetime import timedelta

import libnl.attr
from libnl.nl80211 import iw_scan
from libnl.nl80211 import nl80211


def _get(out_parsed, in_bss, key, parser_func):
    """Handle calling the parser function to convert bytearray data into Python data types.

    Positional arguments:
    out_parsed -- dictionary to update with parsed data and string keys.
    in_bss -- dictionary of integer keys and bytearray values.
    key -- key string to lookup (must be a variable name in libnl.nl80211.nl80211).
    parser_func -- function to call, with the bytearray data as the only argument.
    """
    short_key = key[12:].lower()
    key_integer = getattr(nl80211, key)
    if in_bss.get(key_integer) is None:
        return dict()
    data = parser_func(in_bss[key_integer])
    if parser_func == libnl.attr.nla_data:
        data = data[:libnl.attr.nla_len(in_bss[key_integer])]
    out_parsed[short_key] = data


def _fetch(in_parsed, *keys):
    """Retrieve nested dict data from either information elements or beacon IES dicts.

    Positional arguments:
    in_parsed -- dictionary to read from.
    keys -- one or more nested dict keys to lookup.

    Returns:
    Found value or None.
    """
    for ie in ('information_elements', 'beacon_ies'):
        target = in_parsed.get(ie, {})
        for key in keys:
            target = target.get(key, {})
        if target:
            return target
    return None


def parse_bss(bss):
    """Parse data prepared by nla_parse() and nla_parse_nested() into Python-friendly formats.

    Automatically chooses the right data-type for each attribute and converts it into Python integers, strings, unicode,
    etc objects.

    Positional arguments:
    bss -- dictionary with integer keys and nlattr values.

    Returns:
    New dictionary with the same integer keys and converted values. Excludes null/empty data from `bss`.
    """
    # First parse data into Python data types. Weed out empty values.
    intermediate = dict()
    _get(intermediate, bss, 'NL80211_BSS_BSSID', libnl.attr.nla_data)  # MAC address of access point.
    _get(intermediate, bss, 'NL80211_BSS_FREQUENCY', libnl.attr.nla_get_u32)  # Frequency in MHz.
    _get(intermediate, bss, 'NL80211_BSS_TSF', libnl.attr.nla_get_msecs)  # Timing Synchronization Function.
    _get(intermediate, bss, 'NL80211_BSS_BEACON_INTERVAL', libnl.attr.nla_get_u16)
    _get(intermediate, bss, 'NL80211_BSS_CAPABILITY', libnl.attr.nla_get_u16)
    _get(intermediate, bss, 'NL80211_BSS_INFORMATION_ELEMENTS', libnl.attr.nla_data)
    _get(intermediate, bss, 'NL80211_BSS_SIGNAL_MBM', libnl.attr.nla_get_u32)
    _get(intermediate, bss, 'NL80211_BSS_SIGNAL_UNSPEC', libnl.attr.nla_get_u8)
    _get(intermediate, bss, 'NL80211_BSS_STATUS', libnl.attr.nla_get_u32)
    _get(intermediate, bss, 'NL80211_BSS_SEEN_MS_AGO', libnl.attr.nla_get_u32)
    _get(intermediate, bss, 'NL80211_BSS_BEACON_IES', libnl.attr.nla_data)

    # Parse easy data into final Python types.
    parsed = dict()
    if 'bssid' in intermediate:
        parsed['bssid'] = ':'.join(format(x, '02x') for x in intermediate['bssid'][:6])
    if 'frequency' in intermediate:
        parsed['frequency'] = intermediate['frequency']
    if 'tsf' in intermediate:
        parsed['tsf'] = timedelta(microseconds=intermediate['tsf'])
    if 'beacon_interval' in intermediate:
        parsed['beacon_interval'] = intermediate['beacon_interval']
    if 'signal_mbm' in intermediate:
        data_u32 = intermediate['signal_mbm']
        data_s32 = -(data_u32 & 0x80000000) + (data_u32 & 0x7fffffff)
        parsed['signal_mbm'] = data_s32 / 100.0
    if 'signal_unspec' in intermediate:
        parsed['signal_unspec'] = intermediate['signal_unspec'] / 100.0
    if 'seen_ms_ago' in intermediate:
        parsed['seen_ms_ago'] = timedelta(milliseconds=intermediate['seen_ms_ago'])

    # Handle status.
    if intermediate.get('status') == nl80211.NL80211_BSS_STATUS_AUTHENTICATED:
        parsed['status'] = 'authenticated'
    elif intermediate.get('status') == nl80211.NL80211_BSS_STATUS_ASSOCIATED:
        parsed['status'] = 'associated'
    elif intermediate.get('status') == nl80211.NL80211_BSS_STATUS_IBSS_JOINED:
        parsed['status'] = 'joined'
    elif 'status' in intermediate:
        parsed['status'] = 'unknown status: {0}'.format(intermediate['status'])

    # Handle capability.
    if 'capability' in intermediate:
        # http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n1479
        data = intermediate['capability']
        list_of_caps = list()
        if parsed['frequency'] > 45000:
            if data & iw_scan.WLAN_CAPABILITY_DMG_TYPE_MASK == iw_scan.WLAN_CAPABILITY_DMG_TYPE_AP:
                list_of_caps.append('DMG_ESS')
            elif data & iw_scan.WLAN_CAPABILITY_DMG_TYPE_MASK == iw_scan.WLAN_CAPABILITY_DMG_TYPE_PBSS:
                list_of_caps.append('DMG_PCP')
            elif data & iw_scan.WLAN_CAPABILITY_DMG_TYPE_MASK == iw_scan.WLAN_CAPABILITY_DMG_TYPE_IBSS:
                list_of_caps.append('DMG_IBSS')
            if data & iw_scan.WLAN_CAPABILITY_DMG_CBAP_ONLY:
                list_of_caps.append('CBAP_Only')
            if data & iw_scan.WLAN_CAPABILITY_DMG_CBAP_SOURCE:
                list_of_caps.append('CBAP_Src')
            if data & iw_scan.WLAN_CAPABILITY_DMG_PRIVACY:
                list_of_caps.append('Privacy')
            if data & iw_scan.WLAN_CAPABILITY_DMG_ECPAC:
                list_of_caps.append('ECPAC')
            if data & iw_scan.WLAN_CAPABILITY_DMG_SPECTRUM_MGMT:
                list_of_caps.append('SpectrumMgmt')
            if data & iw_scan.WLAN_CAPABILITY_DMG_RADIO_MEASURE:
                list_of_caps.append('RadioMeasure')
        else:
            if data & iw_scan.WLAN_CAPABILITY_ESS:
                list_of_caps.append('ESS')
            if data & iw_scan.WLAN_CAPABILITY_IBSS:
                list_of_caps.append('IBSS')
            if data & iw_scan.WLAN_CAPABILITY_CF_POLLABLE:
                list_of_caps.append('CfPollable')
            if data & iw_scan.WLAN_CAPABILITY_CF_POLL_REQUEST:
                list_of_caps.append('CfPollReq')
            if data & iw_scan.WLAN_CAPABILITY_PRIVACY:
                list_of_caps.append('Privacy')
            if data & iw_scan.WLAN_CAPABILITY_SHORT_PREAMBLE:
                list_of_caps.append('ShortPreamble')
            if data & iw_scan.WLAN_CAPABILITY_PBCC:
                list_of_caps.append('PBCC')
            if data & iw_scan.WLAN_CAPABILITY_CHANNEL_AGILITY:
                list_of_caps.append('ChannelAgility')
            if data & iw_scan.WLAN_CAPABILITY_SPECTRUM_MGMT:
                list_of_caps.append('SpectrumMgmt')
            if data & iw_scan.WLAN_CAPABILITY_QOS:
                list_of_caps.append('QoS')
            if data & iw_scan.WLAN_CAPABILITY_SHORT_SLOT_TIME:
                list_of_caps.append('ShortSlotTime')
            if data & iw_scan.WLAN_CAPABILITY_APSD:
                list_of_caps.append('APSD')
            if data & iw_scan.WLAN_CAPABILITY_RADIO_MEASURE:
                list_of_caps.append('RadioMeasure')
            if data & iw_scan.WLAN_CAPABILITY_DSSS_OFDM:
                list_of_caps.append('DSSS-OFDM')
            if data & iw_scan.WLAN_CAPABILITY_DEL_BACK:
                list_of_caps.append('DelayedBACK')
            if data & iw_scan.WLAN_CAPABILITY_IMM_BACK:
                list_of_caps.append('ImmediateBACK')
        parsed['capability'] = list_of_caps

    # Handle (beacon) information elements.
    for k in ('information_elements', 'beacon_ies'):
        if k not in intermediate:
            continue
        parsed[k] = iw_scan.get_ies(intermediate[k])

    # Make some data more human-readable.
    parsed['signal'] = parsed.get('signal_mbm', parsed.get('signal_unspec'))
    parsed['channel'] = _fetch(parsed, 'DS Parameter set')
    parsed['ssid'] = _fetch(parsed, 'SSID') or _fetch(parsed, 'MESH ID') or ''
    parsed['supported_rates'] = _fetch(parsed, 'Supported rates')
    parsed['extended_supported_rates'] = _fetch(parsed, 'Extended supported rates')
    parsed['channel_width'] = _fetch(parsed, 'HT operation', 'STA channel width')
    return parsed
