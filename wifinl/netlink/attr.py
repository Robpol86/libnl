import struct


class Attr(object):
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

    def nulstr(self):
        return self.data.split('\0')[0]

    def nested(self):
        return parse(self.data)


class StrAttr(Attr):
    def __init__(self, type_, data):
        super(StrAttr, self).__init__(type_, '{0}s'.format(len(data)), data)


class NulStrAttr(Attr):
    def __init__(self, type_, data):
        super(NulStrAttr, self).__init__(type_, '{0}sB'.format(len(data)), data, 0)


class U32Attr(Attr):
    def __init__(self, type_, data):
        super(U32Attr, self).__init__(type_, 'I', data)


class U8Attr(Attr):
    def __init__(self, type_, data):
        super(U8Attr, self).__init__(type_, 'B', data)


class Nested(object):
    def __init__(self, type_, attrs):
        self.type_ = type_
        self.attrs = attrs

    def dump(self):
        contents = ''.join(a.dump() for a in self.attrs)
        hdr = struct.pack('HH', len(contents) + 4, self.type_)
        return hdr + contents


def parse(data):
    attrs = dict()
    while len(data):
        attr_len, attr_type = struct.unpack('HH', data[:4])
        attrs[attr_type] = Attr(attr_type, data[4:attr_len])
        data = data[((attr_len + 3) & ~3):]
    return attrs
