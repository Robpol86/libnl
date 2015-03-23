import sys

from libnl.misc import c_int, c_int8, c_ubyte, c_uint, c_uint16, c_uint32, c_uint64, c_uint8, c_ushort, c_void_p, sizeof


def test_sizes():
    assert 4 == sizeof(c_int)
    assert 1 == sizeof(c_int8)
    assert 2 == sizeof(c_uint16)
    assert 4 == sizeof(c_uint32)
    assert 8 == sizeof(c_uint64)
    assert 1 == sizeof(c_uint8)
    assert 4 == sizeof(c_uint)
    assert 2 == sizeof(c_ushort)
    assert 8 if sys.maxsize > 2**32 else 4 == sizeof(c_void_p)  # Platform dependant.
    assert 1 == sizeof(c_ubyte)


def test_integers():
    assert 1852 == c_int.from_buffer(bytearray(c_int(1852))).value
    assert 123 == c_int8.from_buffer(bytearray(c_int8(123))).value
