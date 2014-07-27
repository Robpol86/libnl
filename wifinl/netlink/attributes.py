"""Generic Netlink attributes.

Inspired by http://git.sipsolutions.net/?p=pynl80211.git;a=blob;f=netlink.py and  http://lwn.net/Articles/208755/
"""
import struct


class NetlinkAttribute(object):
    def __init__(self, type_, data, *values):
        self.type_ = type_
        self.data = struct.pack(data, *values) if values else data

    def dump(self):
        hdr = struct.pack('HH', len(self.data) + 4, self.type_)
        pad = ((len(self.data) + 3) & ~3) - len(self.data)
        return hdr + self.data + ('\0' * pad)

    def u16(self):
        return struct.unpack('H', self.data)[0]

    def s16(self):
        return struct.unpack('h', self.data)[0]

    def u32(self):
        return struct.unpack('I', self.data)[0]

    def s32(self):
        return struct.unpack('i', self.data)[0]

    def str(self):
        return self.data

    def null_str(self):
        return self.data.split('\0')[0]

    def nested(self):
        return parse(self.data)


class NLAString(NetlinkAttribute):
    def __init__(self, type_, data):
        super(NLAString, self).__init__(type_, '{0}s'.format(len(data)), data)


class NLANullString(NetlinkAttribute):
    def __init__(self, type_, data):
        super(NLANullString, self).__init__(type_, '{0}sB'.format(len(data)), data, 0)


class NLAUnsigned32bitInt(NetlinkAttribute):
    def __init__(self, type_, data):
        super(NLAUnsigned32bitInt, self).__init__(type_, 'I', data)


class NLAUnsigned8bitInt(NetlinkAttribute):
    def __init__(self, type_, data):
        super(NLAUnsigned8bitInt, self).__init__(type_, 'B', data)


class NLANested(object):
    def __init__(self, type_, attributes):
        self.type_ = type_
        self.attributes = attributes

    def dump(self):
        contents = ''.join(a.dump() for a in self.attributes)
        hdr = struct.pack('HH', len(contents) + 4, self.type_)
        return hdr + contents


def parse(data):
    attributes = dict()
    while len(data):
        attr_len, attr_type = struct.unpack('HH', data[:4])
        attributes[attr_type] = NetlinkAttribute(attr_type, data[4:attr_len])
        data = data[((attr_len + 3) & ~3):]
    return attributes
