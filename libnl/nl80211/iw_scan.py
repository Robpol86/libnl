"""http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n441

Copyright (c) 2015		Robert Pooley
Copyright (c) 2007, 2008	Johannes Berg
Copyright (c) 2007		Andy Lutomirski
Copyright (c) 2007		Mike Kershaw
Copyright (c) 2008-2009		Luis R. Rodriguez

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
"""

import ctypes
import unicodedata

from libnl.attr import nla_policy, NLA_U32, NLA_U64, NLA_U16, NLA_U8
from libnl.misc import SIZEOF_U8, SIZEOF_S8
from libnl.nl80211 import nl80211

WLAN_CAPABILITY_ESS = 1 << 0
WLAN_CAPABILITY_IBSS = 1 << 1
WLAN_CAPABILITY_CF_POLLABLE = 1 << 2
WLAN_CAPABILITY_CF_POLL_REQUEST = 1 << 3
WLAN_CAPABILITY_PRIVACY = 1 << 4
WLAN_CAPABILITY_SHORT_PREAMBLE = 1 << 5
WLAN_CAPABILITY_PBCC = 1 << 6
WLAN_CAPABILITY_CHANNEL_AGILITY = 1 << 7
WLAN_CAPABILITY_SPECTRUM_MGMT = 1 << 8
WLAN_CAPABILITY_QOS = 1 << 9
WLAN_CAPABILITY_SHORT_SLOT_TIME = 1 << 10
WLAN_CAPABILITY_APSD = 1 << 11
WLAN_CAPABILITY_RADIO_MEASURE = 1 << 12
WLAN_CAPABILITY_DSSS_OFDM = 1 << 13
WLAN_CAPABILITY_DEL_BACK = 1 << 14
WLAN_CAPABILITY_IMM_BACK = 1 << 15

# DMG (60gHz) 802.11ad
WLAN_CAPABILITY_DMG_TYPE_MASK = 3 << 0
WLAN_CAPABILITY_DMG_TYPE_IBSS = 1 << 0  # Tx by: STA
WLAN_CAPABILITY_DMG_TYPE_PBSS = 2 << 0  # Tx by: PCP
WLAN_CAPABILITY_DMG_TYPE_AP = 3 << 0  # Tx by: AP
WLAN_CAPABILITY_DMG_CBAP_ONLY = 1 << 2
WLAN_CAPABILITY_DMG_CBAP_SOURCE = 1 << 3
WLAN_CAPABILITY_DMG_PRIVACY = 1 << 4
WLAN_CAPABILITY_DMG_ECPAC = 1 << 5
WLAN_CAPABILITY_DMG_SPECTRUM_MGMT = 1 << 8
WLAN_CAPABILITY_DMG_RADIO_MEASURE = 1 << 12

IEEE80211_COUNTRY_EXTENSION_ID = 201
BSS_MEMBERSHIP_SELECTOR_VHT_PHY = 126
BSS_MEMBERSHIP_SELECTOR_HT_PHY = 127

ms_oui = b'\x00\x50\xf2'
ieee80211_oui = b'\x00\x0f\xac'
wfa_oui = b'\x50\x6f\x9a'


class ieee80211_country_ie_triplet(object):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n60"""

    def __init__(self, data):
        self.first_channel = ctypes.c_uint8.from_buffer(data[:SIZEOF_U8]).value
        self.reg_extension_id = self.first_channel
        data = data[SIZEOF_U8:]
        self.num_channels = ctypes.c_uint8.from_buffer(data[:SIZEOF_U8]).value
        self.reg_class = self.num_channels
        data = data[SIZEOF_U8:]
        self.max_power = ctypes.c_int8.from_buffer(data[:SIZEOF_S8]).value
        self.coverage_class = ctypes.c_uint8.from_buffer(data[:SIZEOF_U8]).value
        self.chans = self.ext = self


def get_supprates(_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n227

    Positional arguments:
    data -- bytearray data to read.
    """
    answer = list()
    for i in range(len(data)):
        r = data[i] & 0x7f
        if r == BSS_MEMBERSHIP_SELECTOR_VHT_PHY and data[i] & 0x80:
            value = 'VHT'
        elif r == BSS_MEMBERSHIP_SELECTOR_HT_PHY and data[i] & 0x80:
            value = 'HT'
        else:
            value = '{0}.{1}'.format(int(r/2), int(5 * (r & 1)))
        answer.append('{0}{1}'.format(value, '*' if data[i] & 0x80 else ''))
    return answer


country_env_str = lambda e: {'I': 'Indoor only', 'O': 'Outdoor only', ' ': 'Indoor/Outdoor'}.get(e, 'bogus')


def get_country(_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n267

    Positional arguments:
    type_ -- corresponding `ieprinters` dictionary key for the instance.
    data -- bytearray data to read.
    """
    answers = {'Environment': country_env_str(chr(data[2]))}
    data = data[3:]

    while len(data) >= 3:
        triplet = ieee80211_country_ie_triplet(data)
        if triplet.ext.reg_extension_id >= IEEE80211_COUNTRY_EXTENSION_ID:
            answers['Extension ID'] = triplet.ext.reg_extension_id
            answers['Regulatory Class'] = triplet.ext.reg_class
            answers['Coverage class'] = triplet.ext.coverage_class
            answers['up to dm'] = triplet.ext.coverage_class * 450
            data = data[3:]
            continue
        if triplet.chans.first_channel <= 14:  # 2 GHz.
            end_channel = triplet.chans.first_channel + (triplet.chans.num_channels - 1)
        else:
            end_channel = triplet.chans.first_channel + (4 * (triplet.chans.num_channels - 1))
        answers['Channels dBm'] = triplet.chans.max_power
        answers['Channels'] = (triplet.chans.first_channel, end_channel)
        data = data[3:]
    return answers


def get_powerconstraint(type_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n312

    Positional arguments:
    type_ -- corresponding `ieprinters` dictionary key for the instance.
    data -- bytearray data to read.
    """
    raise NotImplementedError


def get_ssid(_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/util.c?id=v3.17#n313
    Positional arguments:
    data -- bytearray data to read.
    """
    converted = list()
    for i in range(len(data)):
        c = chr(data[i])
        if unicodedata.category(c) != 'Cc' and c not in (' ', '\\'):
            converted.append(c)
        elif c == ' ' and i not in (0, len(data)):
            converted.append(' ')
        else:
            converted.append('\\{0:02x}'.format(data[i]))
    return ''.join(converted)


def get_tpcreport(type_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n317

    Positional arguments:
    type_ -- corresponding `ieprinters` dictionary key for the instance.
    data -- bytearray data to read.
    """
    raise NotImplementedError


def get_erp(_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n323

    Positional arguments:
    type_ -- corresponding `ieprinters` dictionary key for the instance.
    data -- bytearray data to read.
    """
    if data[0] == 0x00:
        return '<no flags>'
    if data[0] & 0x01:
        return 'NonERP_Present'
    if data[0] & 0x02:
        return 'Use_Protection'
    if data[0] & 0x04:
        return 'Barker_Preamble_Mode'
    return ''


def get_cipher(data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n336

    Positional arguments:
    data -- bytearray data to read.

    Returns:
    WiFi stream cipher used by the access point (string).
    """
    legend = {0: 'Use group cipher suite', 1: 'WEP-40', 2: 'TKIP', 4: 'CCMP', 5: 'WEP-104', }
    key = data[3]
    if ieee80211_oui == bytes(data[:3]):
        legend.update({6: 'AES-128-CMAC', 8: 'GCMP', })
    elif ms_oui != bytes(data[:3]):
        key = None
    return legend.get(key, '{0:.02x}-{1:.02x}-{2:.02x}:{3}'.format(data[0], data[1], data[2], data[3]))


def get_auth(data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n393

    Positional arguments:
    data -- bytearray data to read.

    Returns:
    WiFi authentication method used by the access point (string).
    """
    legend = {1: 'IEEE 802.1X"', 2: 'PSK', }
    key = data[3]
    if ieee80211_oui == bytes(data[:3]):
        legend.update({3: 'FT/IEEE 802.1X', 4: 'FT/PSK', 5: 'IEEE 802.1X/SHA-256', 6: 'PSK/SHA-256', 7: 'TDLS/TPK', })
    elif ms_oui != bytes(data[:3]):
        key = None
    return legend.get(key, '{0:.02x}-{1:.02x}-{2:.02x}:{3}'.format(data[0], data[1], data[2], data[3]))


def get_rsn_ie(defcipher, defauth, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n441"""
    answers = dict()
    answers['version'] = data[0] + (data[1] << 8)
    data = data[2:]

    if len(data) < 4:
        answers['group_cipher'] = answers['pairwise_ciphers'] = defcipher
        return answers
    answers['group_cipher'] = get_cipher(data)
    data = data[4:]
    if len(data) < 2:
        answers['pairwise_ciphers'] = defcipher
        return answers

    count = data[0] | (data[1] << 8)
    if 2 + (count * 4) > len(data):
        answers['bogus tail data'] = data
        return answers
    answers['pairwise_ciphers'] = ' '.join(get_cipher(data[2 + (i * 4):]) for i in range(count))
    data = data[2 + (count * 4):]

    if len(data) < 2:
        answers['authentication_suites'] = defauth
        return answers
    count = data[0] | (data[1] << 8)
    if 2 + (count * 4) > len(data):
        answers['bogus tail data'] = data
        return answers
    answers['authentication_suites'] = ' '.join(get_auth(data[2 + (i * 4):]) for i in range(count))
    data = data[2 + (count * 4):]

    if len(data) >= 2:
        capa = data[0] | (data[1] << 8)
        answers['rsn_ie_capabilities'] = list()
        if capa & 0x0001:
            answers['rsn_ie_capabilities'].append('PreAuth')
        if capa & 0x0002:
            answers['rsn_ie_capabilities'].append('NoPairwise')
        case = {0: '1-PTKSA-RC', 1: '2-PTKSA-RC', 2: '4-PTKSA-RC', 3: '16-PTKSA-RC'}.get((capa & 0x000c) >> 2)
        if case:
            answers['rsn_ie_capabilities'].append(case)
        case = {0: '1-GTKSA-RC', 1: '2-GTKSA-RC', 2: '4-GTKSA-RC', 3: '16-GTKSA-RC'}.get((capa & 0x0030) >> 4)
        if case:
            answers['rsn_ie_capabilities'].append(case)
        if capa & 0x0040:
            answers['rsn_ie_capabilities'].append('MFP-required')
        if capa & 0x0080:
            answers['rsn_ie_capabilities'].append('MFP-capable')
        if capa & 0x0200:
            answers['rsn_ie_capabilities'].append('Peerkey-enabled')
        if capa & 0x0400:
            answers['rsn_ie_capabilities'].append('SPP-AMSDU-capable')
        if capa & 0x0800:
            answers['rsn_ie_capabilities'].append('SPP-AMSDU-required')
        answers['rsn_ie_capabilities'].append('(0x{0:04x})'.format(capa))
        data = data[2:]

    invalid = False
    if len(data) >= 2:
        pmkid_count = data[0] | (data[1] << 8)
        if len(data) >= 2 + 16 * pmkid_count:
            answers['PMKIDs'] = pmkid_count
            data = data[2 + 16 * pmkid_count:]
        else:
            invalid = True

    if len(data) >= 4 and not invalid:
        answers['Group mgmt cipher suite'] = get_cipher(data)
        data = data[4:]

    if data:
        answers['* bogus tail data ({0})'.format(len(data))] = ' '.join(format(x, '02x') for x in data)

    return answers


def get_ht_capa(type_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n602

    Positional arguments:
    type_ -- corresponding `ieprinters` dictionary key for the instance.
    data -- bytearray data to read.
    """
    raise NotImplementedError


def get_interworking(type_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n645

    Positional arguments:
    type_ -- corresponding `ieprinters` dictionary key for the instance.
    data -- bytearray data to read.
    """
    raise NotImplementedError


def get_11u_advert(type_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n676

    Positional arguments:
    type_ -- corresponding `ieprinters` dictionary key for the instance.
    data -- bytearray data to read.
    """
    raise NotImplementedError


def get_11u_rcon(type_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n708

    Positional arguments:
    type_ -- corresponding `ieprinters` dictionary key for the instance.
    data -- bytearray data to read.
    """
    raise NotImplementedError


def get_ht_op(type_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n766

    Positional arguments:
    type_ -- corresponding `ieprinters` dictionary key for the instance.
    data -- bytearray data to read.
    """
    raise NotImplementedError


def get_capabilities(type_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n796

    Positional arguments:
    type_ -- corresponding `ieprinters` dictionary key for the instance.
    data -- bytearray data to read.
    """
    raise NotImplementedError


def get_tim(_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n874

    Positional arguments:
    type_ -- corresponding `ieprinters` dictionary key for the instance.
    data -- bytearray data to read.
    """
    answers = {
        'DTIM Count': data[0],
        'DTIM Period': data[1],
        'Bitmap Control': data[2],
        'Bitmap[0]': data[3],
    }
    if len(data) - 4:
        answers['+ octets'] = len(data) - 4
    return answers


def get_vht_capa(type_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n889

    Positional arguments:
    type_ -- corresponding `ieprinters` dictionary key for the instance.
    data -- bytearray data to read.
    """
    raise NotImplementedError


def get_vht_oper(type_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n897

    Positional arguments:
    type_ -- corresponding `ieprinters` dictionary key for the instance.
    data -- bytearray data to read.
    """
    raise NotImplementedError


def get_obss_scan_params(type_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n914

    Positional arguments:
    type_ -- corresponding `ieprinters` dictionary key for the instance.
    data -- bytearray data to read.
    """
    raise NotImplementedError


def get_secchan_offs(type_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n927

    Positional arguments:
    type_ -- corresponding `ieprinters` dictionary key for the instance.
    data -- bytearray data to read.
    """
    raise NotImplementedError


def get_bss_load(type_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n935

    Positional arguments:
    type_ -- corresponding `ieprinters` dictionary key for the instance.
    data -- bytearray data to read.
    """
    raise NotImplementedError


def get_mesh_conf(type_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n943

    Positional arguments:
    type_ -- corresponding `ieprinters` dictionary key for the instance.
    data -- bytearray data to read.
    """
    raise NotImplementedError


class ie_print(object):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n974

    Instance variables:
    name -- printer label (string).
    print_ -- print function to call. Has arguments type_ (c_uint8) and data (bytearray).
    minlen -- used for validation (c_uint8).
    maxlen -- used for validation (c_uint8).
    flags -- type of printer (c_uint8).
    """

    def __init__(self, name, print_, minlen, maxlen, flags):
        self.name = name
        self.print_ = print_
        self.minlen = minlen
        self.maxlen = maxlen
        self.flags = flags


def get_ie(instance, key, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n981

    Positional arguments:
    instance -- `ie_print` class instance.
    key -- corresponding `ieprinters` dictionary key for the instance.
    data -- bytearray data to read.

    Returns:
    Dictionary of parsed data with string keys.
    """
    if not instance.print_:
        return dict()
    if len(data) < instance.minlen or len(data) > instance.maxlen:
        if data:
            return {'<invalid: {0} byte(s)>'.format(len(data)): ' '.join(format(x, '02x') for x in data)}
        return {'<invalid: no data>': data}
    return {instance.name: instance.print_(key, data)}


ieprinters = {  # http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n1013
    0: ie_print('SSID', get_ssid, 0, 32, 3),
    1: ie_print('Supported rates', get_supprates, 0, 255, 1),
    3: ie_print('DS Parameter set', lambda _, d: d[0], 1, 1, 1),
    5: ie_print('TIM', get_tim, 4, 255, 1),
    6: ie_print('IBSS ATIM window', lambda _, d: '{0} TUs'.format((d[1] << 8) + d[0]), 2, 2, 1),
    7: ie_print('Country', get_country, 3, 255, 1),
    11: ie_print('BSS Load', get_bss_load, 5, 5, 1),
    32: ie_print('Power constraint', get_powerconstraint, 1, 1, 1),
    35: ie_print('TPC report', get_tpcreport, 2, 2, 1),
    42: ie_print('ERP', get_erp, 1, 255, 1),
    45: ie_print('HT capabilities', get_ht_capa, 26, 26, 1),
    47: ie_print('ERP D4.0', get_erp, 1, 255, 1),
    48: ie_print('RSN', lambda _, d: get_rsn_ie('CCMP', 'IEEE 802.1x', d), 2, 255, 1),
    50: ie_print('Extended supported rates', get_supprates, 0, 255, 1),
    61: ie_print('HT operation', get_ht_op, 22, 22, 1),
    62: ie_print('Secondary Channel Offset', get_secchan_offs, 1, 1, 1),
    74: ie_print('Overlapping BSS scan params', get_obss_scan_params, 14, 255, 1),
    107: ie_print('802.11u Interworking', get_interworking, 0, 255, 1),
    108: ie_print('802.11u Advertisement', get_11u_advert, 0, 255, 1),
    111: ie_print('802.11u Roaming Consortium', get_11u_rcon, 0, 255, 1),
    113: ie_print('MESH Configuration', get_mesh_conf, 7, 7, 1),
    114: ie_print('MESH ID', get_ssid, 0, 32, 3),
    127: ie_print('Extended capabilities', get_capabilities, 0, 255, 1),
    191: ie_print('VHT capabilities', get_vht_capa, 12, 255, 1),
    192: ie_print('VHT operation', get_vht_oper, 5, 255, 1),
}


def get_wifi_wmm(type_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n1088

    Positional arguments:
    type_ -- corresponding `ieprinters` dictionary key for the instance.
    data -- bytearray data to read.
    """
    raise NotImplementedError


def get_wifi_wps(type_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n1130

    Positional arguments:
    type_ -- corresponding `ieprinters` dictionary key for the instance.
    data -- bytearray data to read.
    """
    raise NotImplementedError


wifiprinters = {  # http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n1300
    1: ie_print('WPA', lambda _, d: get_rsn_ie('TKIP', 'IEEE 802.1X', d), 2, 255, 1),
    2: ie_print('WMM', get_wifi_wmm, 1, 255, 1),
    4: ie_print('WPS', get_wifi_wps, 0, 255, 1),
}


def get_p2p(type_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n1306

    Positional arguments:
    type_ -- corresponding `ieprinters` dictionary key for the instance.
    data -- bytearray data to read.
    """
    raise NotImplementedError


def get_hs20_ind(type_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n1386

    Positional arguments:
    type_ -- corresponding `ieprinters` dictionary key for the instance.
    data -- bytearray data to read.
    """
    raise NotImplementedError


wfa_printers = {  # http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n1396
    9: ie_print('P2P', get_p2p, 2, 255, 1),
    16: ie_print('HotSpot 2.0 Indication', get_hs20_ind, 1, 255, 1),
}


def get_vendor(data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n1401

    Positional arguments:
    data -- bytearray data to read.

    Returns:
    Dictionary of parsed data with string keys.
    """
    if len(data) < 3:
        return {'Vendor specific: <too short> data': ' '.join(format(x, '02x') for x in data)}
    key = data[3]

    if bytes(data[:3]) == ms_oui:
        if key in wifiprinters and wifiprinters[key].flags & 1:
            return get_ie(wifiprinters[key], key, data[4:])
        return {'MS/WiFi {0:02x}, data'.format(key): ' '.join(format(x, '02x') for x in data[4:])}

    if bytes(data[:3]) == wfa_oui:
        if key in wfa_printers and wfa_printers[key].flags & 1:
            return get_ie(wfa_printers[key], key, data[4:])
        return {'WFA {0:02x}, data'.format(key): ' '.join(format(x, '02x') for x in data[4:])}

    unknown_key = 'Vendor specific: OUI {0:02x}:{1:02x}:{2:02x}, data'.format(data[0], data[1], data[2])
    unknown_value = ' '.join(format(x, '02x') for x in data[3:])
    return {unknown_key: unknown_value}


def get_ies(ie):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n1456

    Positional arguments:
    ie -- bytearray data to read.

    Returns:
    Dictionary of all parsed data. In the iw tool it prints everything to terminal. This function returns a dictionary
    with string keys (being the "titles" of data printed by iw), and data values (integers/strings/etc).
    """
    answers = dict()
    while len(ie) >= 2 and len(ie) >= ie[1]:
        key = ie[0]  # Should be key in `ieprinters` dict.
        len_ = ie[1]  # Length of this information element.
        data = ie[2:len_ + 2]  # Data for this information element.
        if key in ieprinters and ieprinters[key].flags & 1:
            answers.update(get_ie(ieprinters[key], key, data))
        elif key == 221:
            answers.update(get_vendor(data))
        else:
            answers['Unknown IE ({0})'.format(key)] = ' '.join(format(x, '02x') for x in data)
        ie = ie[len_ + 2:]
    return answers


bss_policy = {i: 0 for i in range(nl80211.NL80211_BSS_MAX + 1)}
bss_policy.update({  # http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n1549
    nl80211.NL80211_BSS_BSSID: nla_policy(),
    nl80211.NL80211_BSS_FREQUENCY: nla_policy(type_=NLA_U32),
    nl80211.NL80211_BSS_TSF: nla_policy(type_=NLA_U64),
    nl80211.NL80211_BSS_BEACON_INTERVAL: nla_policy(type_=NLA_U16),
    nl80211.NL80211_BSS_CAPABILITY: nla_policy(type_=NLA_U16),
    nl80211.NL80211_BSS_INFORMATION_ELEMENTS: nla_policy(),
    nl80211.NL80211_BSS_SIGNAL_MBM: nla_policy(type_=NLA_U32),
    nl80211.NL80211_BSS_SIGNAL_UNSPEC: nla_policy(type_=NLA_U8),
    nl80211.NL80211_BSS_STATUS: nla_policy(type_=NLA_U32),
    nl80211.NL80211_BSS_SEEN_MS_AGO: nla_policy(type_=NLA_U32),
    nl80211.NL80211_BSS_BEACON_IES: nla_policy(),
    nl80211.NL80211_BSS_CHAN_WIDTH: nla_policy(),
    nl80211.NL80211_BSS_BEACON_TSF: nla_policy(),
    nl80211.NL80211_BSS_PRESP_DATA: nla_policy(),
})
