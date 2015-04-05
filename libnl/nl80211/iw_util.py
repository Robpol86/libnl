"""http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/util.c?id=v3.17.

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

import unicodedata


def get_ssid(_, data):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/util.c?id=v3.17#n313.

    Positional arguments:
    data -- bytearray data to read.

    Returns:
    String.
    """
    converted = list()
    for i in range(len(data)):
        try:
            c = unichr(data[i])
        except NameError:
            c = chr(data[i])
        if unicodedata.category(c) != 'Cc' and c not in (' ', '\\'):
            converted.append(c)
        elif c == '\0':
            converted.append(c)
        elif c == ' ' and i not in (0, len(data)):
            converted.append(' ')
        else:
            converted.append('\\{0:02x}'.format(data[i]))
    return ''.join(converted)


ampdu_space = {  # http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/util.c?id=v3.17#n504
    0: 'No restriction', 1: '1/4 usec', 2: '1/2 usec', 3: '1 usec', 4: '2 usec', 5: '4 usec', 6: '8 usec', 7: '16 usec'
}


def get_mcs_index(mcs):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/util.c?id=v3.17#n453.

    Positional arguments:
    mcs -- bytearray

    Returns:
    List.
    """
    answers = list()
    for mcs_bit in range(77):
        mcs_octet = int(mcs_bit / 8)
        mcs_rate_bit = 1 << mcs_bit % 8
        mcs_rate_idx_set = not not (mcs[mcs_octet] & mcs_rate_bit)
        if not mcs_rate_idx_set:
            continue
        answers.append(mcs_bit)
    return answers


def get_ht_capability(cap):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/util.c?id=v3.17#n541.

    Positional arguments:
    cap -- c_uint16

    Returns:
    List.
    """
    answers = list()
    if cap & 1:
        answers.append('RX LDPC')
    if cap & 2:
        answers.append('HT20/HT40')
    if not cap & 2:
        answers.append('HT20')
    if (cap >> 2) & 0x3 == 0:
        answers.append('Static SM Power Save')
    if (cap >> 2) & 0x3 == 1:
        answers.append('Dynamic SM Power Save')
    if (cap >> 2) & 0x3 == 3:
        answers.append('SM Power Save disabled')
    if cap & 16:
        answers.append('RX Greenfield')
    if cap & 32:
        answers.append('RX HT20 SGI')
    if cap & 64:
        answers.append('RX HT40 SGI')
    if cap & 128:
        answers.append('TX STBC')
    if (cap >> 8) & 0x3 == 0:
        answers.append('No RX STBC')
    if (cap >> 8) & 0x3 == 1:
        answers.append('RX STBC 1-stream')
    if (cap >> 8) & 0x3 == 2:
        answers.append('RX STBC 2-streams')
    if (cap >> 8) & 0x3 == 3:
        answers.append('RX STBC 3-streams')
    if cap & 1024:
        answers.append('HT Delayed Block Ack')
    if not cap & 2048:
        answers.append('Max AMSDU length: 3839 bytes')
    if cap & 2048:
        answers.append('Max AMSDU length: 7935 bytes')
    if cap & 4096:
        answers.append('DSSS/CCK HT40')
    if not cap & 4096:
        answers.append('No DSSS/CCK HT40')
    if cap & 16384:
        answers.append('40 MHz Intolerant')
    if cap & 32768:
        answers.append('L-SIG TXOP protection')
    return answers


def get_ht_mcs(mcs):
    """http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/util.c?id=v3.17#n591.

    Positional arguments:
    mcs -- bytearray.

    Returns:
    Dict.
    """
    answers = dict()
    max_rx_supp_data_rate = (mcs[10] & ((mcs[11] & 0x3) << 8))
    tx_mcs_set_defined = not not (mcs[12] & (1 << 0))
    tx_mcs_set_equal = not (mcs[12] & (1 << 1))
    tx_max_num_spatial_streams = ((mcs[12] >> 2) & 3) + 1
    tx_unequal_modulation = not not (mcs[12] & (1 << 4))

    if max_rx_supp_data_rate:
        answers['HT Max RX data rate (Mbps)'] = max_rx_supp_data_rate

    if tx_mcs_set_defined and tx_mcs_set_equal:
        answers['HT TX/RX MCS rate indexes supported'] = get_mcs_index(mcs)
    elif tx_mcs_set_defined:
        answers['HT RX MCS rate indexes supported'] = get_mcs_index(mcs)
        answers['TX unequal modulation supported'] = bool(tx_unequal_modulation)
        answers['HT TX Max spatial streams'] = tx_max_num_spatial_streams
    else:
        answers['HT RX MCS rate indexes supported'] = get_mcs_index(mcs)

    return answers
