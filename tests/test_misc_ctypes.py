import sys

from libnl.misc import (c_int, c_int8, c_ubyte, c_uint, c_uint16, c_uint32, c_uint64, c_uint8, c_ulong, c_ushort,
                        sizeof)


def test_sizes():
    assert 4 == sizeof(c_int)
    assert 1 == sizeof(c_int8)
    assert 2 == sizeof(c_uint16)
    assert 4 == sizeof(c_uint32)
    assert 8 == sizeof(c_uint64)
    assert 1 == sizeof(c_uint8)
    assert 1 == sizeof(c_ubyte)
    assert 4 == sizeof(c_uint)
    assert 8 if sys.maxsize > 2**32 else 4 == sizeof(c_ulong)  # Platform dependant.
    assert 2 == sizeof(c_ushort)


def test_value():
    assert -2147483648 == c_int.from_buffer(bytearray(c_int(-2147483648))).value
    assert -128 == c_int8.from_buffer(bytearray(c_int8(-128))).value

    assert 0 == c_int.from_buffer(bytearray(c_int())).value
    assert 0 == c_int8.from_buffer(bytearray(c_int8())).value
    assert 0 == c_uint16.from_buffer(bytearray(c_uint16())).value
    assert 0 == c_uint32.from_buffer(bytearray(c_uint32())).value
    assert 0 == c_uint64.from_buffer(bytearray(c_uint64())).value
    assert 0 == c_uint8.from_buffer(bytearray(c_uint8())).value
    assert 0 == c_ubyte.from_buffer(bytearray(c_ubyte())).value
    assert 0 == c_uint.from_buffer(bytearray(c_uint())).value
    assert 0 == c_ulong.from_buffer(bytearray(c_ulong())).value
    assert 0 == c_ushort.from_buffer(bytearray(c_ushort())).value

    assert 1234567890 == c_int.from_buffer(bytearray(c_int(1234567890))).value
    assert 123 == c_int8.from_buffer(bytearray(c_int8(123))).value
    assert 12345 == c_uint16.from_buffer(bytearray(c_uint16(12345))).value
    assert 1234567890 == c_uint32.from_buffer(bytearray(c_uint32(1234567890))).value
    assert 12345678901234567890 == c_uint64.from_buffer(bytearray(c_uint64(12345678901234567890))).value
    assert 123 == c_uint8.from_buffer(bytearray(c_uint8(123))).value
    assert 123 == c_ubyte.from_buffer(bytearray(c_ubyte(123))).value
    assert 1234567890 == c_uint.from_buffer(bytearray(c_uint(1234567890))).value
    assert 1234567890 == c_ulong.from_buffer(bytearray(c_ulong(1234567890))).value
    assert 12345 == c_ushort.from_buffer(bytearray(c_ushort(12345))).value

    assert 2147483647 == c_int.from_buffer(bytearray(c_int(2147483647))).value
    assert 127 == c_int8.from_buffer(bytearray(c_int8(127))).value
    assert 65535 == c_uint16.from_buffer(bytearray(c_uint16(65535))).value
    assert 4294967295 == c_uint32.from_buffer(bytearray(c_uint32(4294967295))).value
    assert 18446744073709551615 == c_uint64.from_buffer(bytearray(c_uint64(18446744073709551615))).value
    assert 255 == c_uint8.from_buffer(bytearray(c_uint8(255))).value
    assert 255 == c_ubyte.from_buffer(bytearray(c_ubyte(255))).value
    assert 4294967295 == c_uint.from_buffer(bytearray(c_uint(4294967295))).value
    assert 65535 == c_ushort.from_buffer(bytearray(c_ushort(65535))).value
    if sys.maxsize > 2**32:  # 64-bit.
        assert 18446744073709551615 == c_ulong.from_buffer(bytearray(c_ulong(18446744073709551615))).value
    else:
        assert 4294967295 == c_ulong.from_buffer(bytearray(c_ulong(4294967295))).value


def test_overflow():
    assert 2147483647 == c_int(-2147483649).value
    assert 127 == c_int8(-129).value
    assert -2147483648 == c_int(2147483648).value
    assert -128 == c_int8(128).value
    assert 0 == c_uint16(65536).value
    assert 0 == c_uint32(4294967296).value
    assert 0 == c_uint64(18446744073709551616).value
    assert 0 == c_uint8(256).value
    assert 0 == c_ubyte(256).value
    assert 0 == c_uint(4294967296).value
    assert 0 == c_ushort(65536).value
    if sys.maxsize > 2**32:  # 64-bit.
        assert 4294967296 == c_ulong(4294967296).value
        assert 0 == c_ulong(18446744073709551616).value
    else:
        assert 0 == c_ulong(4294967296).value
