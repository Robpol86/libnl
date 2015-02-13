import ctypes

from libnl.misc import split_bytearray


def test_split_bytearray():
    assert (bytearray(), ) == split_bytearray(bytearray())
    assert (bytearray(b'abc'), ) == split_bytearray(bytearray(b'abc'))

    buf = bytearray()
    buf += bytearray(ctypes.c_uint(12))
    buf += bytearray(ctypes.c_uint64(157295))
    buf += bytearray(ctypes.c_char(b'w'))
    buf += bytearray(b'\0' * 123)
    a, b, c, remainder = split_bytearray(buf, ctypes.c_uint, ctypes.c_uint64, ctypes.c_char)

    assert 12 == a.value
    assert isinstance(a, ctypes.c_uint)

    assert 157295 == b.value
    assert isinstance(b, ctypes.c_uint64)

    assert b'w' == c.value
    assert isinstance(c, ctypes.c_char)

    assert bytearray(b'\0' * 123) == remainder
