"""http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17

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

from libnl.attr import nla_policy, NLA_U16, NLA_U32, NLA_U64, NLA_U8
from libnl.misc import c_int8, c_uint8, SIZEOF_S8, SIZEOF_U8
from libnl.nl80211 import nl80211
from libnl.nl80211.iw_util import ampdu_space, get_ht_capability, get_ht_mcs, get_ssid

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

country_env_str = lambda e: {'I': 'Indoor only', 'O': 'Outdoor only', ' ': 'Indoor/Outdoor'}.get(e, 'bogus')
wifi_wps_dev_passwd_id = lambda e: {0: 'Default (PIN)', 1: 'User-specified', 2: 'Machine-specified', 3: 'Rekey',
                                    4: 'PushButton', 5: 'Registrar-specified'}.get(e, '??')
ht_secondary_offset = ('no secondary', 'above', '[reserved!]', 'below')


class ieee80211_country_ie_triplet(object):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n60"""

    def __init__(self, data):
        self.first_channel = c_uint8.from_buffer(data[:SIZEOF_U8]).value
        self.reg_extension_id = self.first_channel
        data = data[SIZEOF_U8:]
        self.num_channels = c_uint8.from_buffer(data[:SIZEOF_U8]).value
        self.reg_class = self.num_channels
        data = data[SIZEOF_U8:]
        self.max_power = c_int8.from_buffer(data[:SIZEOF_S8]).value
        self.coverage_class = c_uint8.from_buffer(data[:SIZEOF_U8]).value
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


def get_country(_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n267

    Positional arguments:
    data -- bytearray data to read.

    Returns:
    Dict.
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


def get_erp(_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n323

    Positional arguments:
    data -- bytearray data to read.

    Returns:
    String.
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
    return legend.get(key, '{0:02x}-{1:02x}-{2:02x}:{3}'.format(data[0], data[1], data[2], data[3]))


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
    return legend.get(key, '{0:02x}-{1:02x}-{2:02x}:{3}'.format(data[0], data[1], data[2], data[3]))


def get_rsn_ie(defcipher, defauth, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n441

    Positional arguments:
    defcipher -- default cipher if not in data (string).
    defauth -- default authentication suites if not in data (string).
    data -- bytearray data to read.

    Returns:
    Dict.
    """
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


def get_ht_capa(_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n602

    Positional arguments:
    data -- bytearray data to read.

    Returns:
    Dict.
    """
    answers = {
        'Capabilities': get_ht_capability(data[0] | (data[1] << 8)),
        'Minimum RX AMPDU time spacing': ampdu_space.get((data[2] >> 2) & 7, 'BUG (spacing more than 3 bits!)'),
        'Maximum RX AMPDU length': {0: 8191, 1: 16383, 2: 32767, 3: 65535}.get(data[2] & 3, 0),
    }
    answers.update(get_ht_mcs(data[3:]))
    return answers


def get_interworking(type_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n645

    Positional arguments:
    type_ -- corresponding `ieprinters` dictionary key for the instance.
    data -- bytearray data to read.
    """
    raise NotImplementedError


def get_11u_advert(_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n676

    Positional arguments:
    data -- bytearray data to read.

    Returns:
    Dict.
    """
    answers = dict()
    idx = 0
    while idx < len(data) - 1:
        qri = data[idx]
        proto_id = data[idx + 1]
        answers['Query Response Info'] = qri
        answers['Query Response Length Limit'] = qri & 0x7f
        if qri & (1 << 7):
            answers['PAME-BI'] = True
        answers['proto_id'] = {0: 'ANQP', 1: 'MIH Information Service', 3: 'Emergency Alert System (EAS)',
                               2: 'MIH Command and Event Services Capability Discovery',
                               221: 'Vendor Specific'}.get(proto_id, 'Reserved: {0}'.format(proto_id))
        idx += 2
    return answers


def get_11u_rcon(type_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n708

    Positional arguments:
    type_ -- corresponding `ieprinters` dictionary key for the instance.
    data -- bytearray data to read.
    """
    raise NotImplementedError


def get_ht_op(_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n766

    Positional arguments:
    data -- bytearray data to read.

    Returns:
    Dict.
    """
    protection = ('no', 'nonmember', 20, 'non-HT mixed')
    sta_chan_width = (20, 'any')
    answers = {
        'primary channel': data[0],
        'secondary channel offset': ht_secondary_offset[data[1] & 0x3],
        'STA channel width': sta_chan_width[(data[1] & 0x4) >> 2],
        'RIFS': (data[1] & 0x8) >> 3,
        'HT protection': protection[data[2] & 0x3],
        'non-GF present': (data[2] & 0x4) >> 2,
        'OBSS non-GF present': (data[2] & 0x10) >> 4,
        'dual beacon': (data[4] & 0x40) >> 6,
        'dual CTS protection': (data[4] & 0x80) >> 7,
        'STBC beacon': data[5] & 0x1,
        'L-SIG TXOP Prot': (data[5] & 0x2) >> 1,
        'PCO active': (data[5] & 0x4) >> 2,
        'PCO phase': (data[5] & 0x8) >> 3,
    }
    return answers


CAPA = {
    0: 'HT Information Exchange Supported',
    1: 'reserved (On-demand Beacon)',
    2: 'Extended Channel Switching',
    3: 'reserved (Wave Indication)',
    4: 'PSMP Capability',
    5: 'reserved (Service Interval Granularity)',
    6: 'S-PSMP Capability',
    7: 'Event',
    8: 'Diagnostics',
    9: 'Multicast Diagnostics',
    10: 'Location Tracking',
    11: 'FMS',
    12: 'Proxy ARP Service',
    13: 'Collocated Interference Reporting',
    14: 'Civic Location',
    15: 'Geospatial Location',
    16: 'TFS',
    17: 'WNM-Sleep Mode',
    18: 'TIM Broadcast',
    19: 'BSS Transition',
    20: 'QoS Traffic Capability',
    21: 'AC Station Count',
    22: 'Multiple BSSID',
    23: 'Timing Measurement',
    24: 'Channel Usage',
    25: 'SSID List',
    26: 'DMS',
    27: 'UTC TSF Offset',
    28: 'TDLS Peer U-APSD Buffer STA Support',
    29: 'TDLS Peer PSM Support',
    30: 'TDLS channel switching',
    31: 'Interworking',
    32: 'QoS Map',
    33: 'EBR',
    34: 'SSPN Interface',
    35: 'Reserved',
    36: 'MSGCF Capability',
    37: 'TDLS Support',
    38: 'TDLS Prohibited',
    39: 'TDLS Channel Switching Prohibited',
    40: 'Reject Unadmitted Frame',
    44: 'Identifier Location',
    45: 'U-APSD Coexistence',
    46: 'WNM-Notification',
    47: 'Reserved',
    48: 'UTF-8 SSID',
}


def get_capabilities(_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n796

    Positional arguments:
    data -- bytearray data to read.

    Returns:
    List.
    """
    answers = list()
    for i in range(len(data)):
        base = i * 8
        for bit in range(8):
            if not data[i] & (1 << bit):
                continue
            answers.append(CAPA.get(bit + base, bit))
    return answers


def get_tim(_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n874

    Positional arguments:
    data -- bytearray data to read.

    Returns:
    Dict.
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


def get_obss_scan_params(_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n914

    Positional arguments:
    data -- bytearray data to read.

    Returns:
    Dict.
    """
    answers = {
        'passive dwell': (data[1] << 8) | data[0],
        'active dwell': (data[3] << 8) | data[2],
        'channel width trigger scan interval': (data[5] << 8) | data[4],
        'scan passive total per channel': (data[7] << 8) | data[6],
        'scan active total per channel': (data[9] << 8) | data[8],
        'BSS width channel transition delay factor': (data[11] << 8) | data[10],
        'OBSS Scan Activity Threshold': ((data[13] << 8) | data[12]) / 100.0
    }
    return answers


def get_secchan_offs(type_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n927

    Positional arguments:
    type_ -- corresponding `ieprinters` dictionary key for the instance.
    data -- bytearray data to read.
    """
    raise NotImplementedError


def get_bss_load(_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n935

    Positional arguments:
    data -- bytearray data to read.

    Returns:
    Dict.
    """
    answers = {
        'station count': (data[1] << 8) | data[0],
        'channel utilisation': data[2] / 255.0,
        'available admission capacity': (data[4] << 8) | data[3],
    }
    return answers


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
    32: ie_print('Power constraint', lambda _, d: '{0} dB'.format(d[0]), 1, 1, 1),
    35: ie_print('TPC report', lambda _, d: 'TX power: {0} dBm'.format(d[0]), 2, 2, 1),
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


def get_wifi_wmm_param(data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n1046

    Positional arguments:
    data -- bytearray data to read.

    Returns:
    Dict.
    """
    answers = dict()
    aci_tbl = ('BE', 'BK', 'VI', 'VO')
    if data[0] & 0x80:
        answers['u-APSD'] = True
    data = data[2:]

    for i in range(4):
        key = aci_tbl[(data[0] >> 5) & 3]
        value = dict()
        if data[0] & 0x10:
            value['acm'] = True
        value['CW'] = ((1 << (data[1] & 0xf)) - 1, (1 << (data[1] >> 4)) - 1)
        value['AIFSN'] = data[0] & 0xf
        if data[2] | data[3]:
            value['TXOP'] = (data[2] + (data[3] << 8)) * 32
        answers[key] = value
        data = data[4:]

    return {'Parameter version 1': answers}


def get_wifi_wmm(_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n1088

    Positional arguments:
    data -- bytearray data to read.

    Returns:
    Dict.
    """
    answers = dict()
    if data[0] == 0x01:
        if len(data) < 20:
            key = 'invalid'
        elif data[1] != 1:
            key = 'Parameter: not version 1'
        else:
            answers.update(get_wifi_wmm_param(data[2:]))
            return answers
    elif data[0] == 0x00:
        key = 'information'
    else:
        key = 'type {0}'.format(data[0])
    answers[key] = ' '.join(format(x, '02x') for x in data)
    return answers


def get_wifi_wps(_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/scan.c?id=v3.17#n1130

    Positional arguments:
    data -- bytearray data to read.

    Returns:
    Dict.
    """
    answers = dict()
    while len(data) >= 4:
        subtype = (data[0] << 8) + data[1]
        sublen = (data[2] << 8) + data[3]
        if sublen > len(data):
            break
        elif subtype == 0x104a:
            answers['Version'] = data[4] >> 4, data[4] & 0xF
        elif subtype == 0x1011:
            answers['Device name'] = data[4:sublen + 4]
        elif subtype == 0x1012:
            if sublen != 2:
                answers['Device Password ID'] = 'invalid length %d'.format(sublen)
            else:
                id_ = data[4] << 8 | data[5]
                answers['Device Password ID'] = (id_, wifi_wps_dev_passwd_id(id_))
        elif subtype == 0x1021:
            answers['Manufacturer'] = data[4:sublen + 4]
        elif subtype == 0x1023:
            answers['Model'] = data[4:sublen + 4]
        elif subtype == 0x1024:
            answers['Model Number'] = data[4:sublen + 4]
        elif subtype == 0x103b:
            val = data[4]
            answers['Response Type'] = (val, 'AP' if val == 3 else '')
        elif subtype == 0x103c:
            answers['RF Bands'] = data[4]
        elif subtype == 0x1041:
            answers['Selected Registrar'] = data[4]
        elif subtype == 0x1042:
            answers['Serial Number'] = data[4:sublen + 4]
        elif subtype == 0x1044:
            val = data[4]
            answers['Wi-Fi Protected Setup State'] = (val, {1: 'Unconfigured', 2: 'Configured'}.get(val, ''))
        elif subtype == 0x1047:
            if sublen != 16:
                answers['UUID'] = '(invalid, length={0})'.format(sublen)
            else:
                answers['UUID'] = bytearray(data[4:19])
        elif subtype == 0x1054:
            if sublen != 8:
                answers['Primary Device Type'] = '(invalid, length={0})'.format(sublen)
            else:
                answers['Primary Device Type'] = '{0}-{1}-{2}'.format(
                    data[4] << 8 | data[5],
                    ''.join(format(x, '02x') for x in data[6:9]),
                    data[10] << 8 | data[11]
                )
        elif subtype == 0x1057:
            answers['AP setup locked'] = data[4]
        elif subtype == 0x1008 or subtype == 0x1053:
            meth = (data[4] << 8) + data[5]
            key = 'Selected Registrar Config methods' if subtype == 0x1053 else 'Config methods'
            values = [s for i, s in enumerate(('USB', 'Ethernet', 'Label', 'Display', 'Ext. NFC', 'Int. NFC',
                                               'NFC Intf.', 'PBC', 'Keypad')) if meth & (1 << i)]
            answers[key] = values
        else:
            value = ' '.join(format(x, '02x') for x in data[4:])
            answers['Unknown TLV ({0:04x}, {1} bytes)'.format(subtype, sublen)] = value
        data = data[4:]
    if data:
        answers['bogus tail data'] = ' '.join(format(x, '02x') for x in data)
    return answers


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
        return dict(('Vendor specific: <too short> data', ' '.join(format(x, '02x'))) for x in data)
    key = data[3]

    if bytes(data[:3]) == ms_oui:
        if key in wifiprinters and wifiprinters[key].flags & 1:
            return get_ie(wifiprinters[key], key, data[4:])
        return dict(('MS/WiFi {0:02x}, data'.format(key), ' '.join(format(x, '02x'))) for x in data[4:])

    if bytes(data[:3]) == wfa_oui:
        if key in wfa_printers and wfa_printers[key].flags & 1:
            return get_ie(wfa_printers[key], key, data[4:])
        return dict(('WFA {0:02x}, data'.format(key), ' '.join(format(x, '02x'))) for x in data[4:])

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


bss_policy = dict((i, None) for i in range(nl80211.NL80211_BSS_MAX + 1))
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
