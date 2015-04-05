"""Tests for pseudo ctypes in libnl/misc."""

import sys

import pytest

from libnl.misc import (c_byte, c_int, c_int8, c_long, c_longlong, c_ubyte, c_uint, c_uint16, c_uint32, c_uint64,
                        c_uint8, c_ulong, c_ulonglong, c_ushort, sizeof)


def test_sizes():
    """Test sizeof()."""
    assert 1 == sizeof(c_byte)
    assert 4 == sizeof(c_int)
    assert 1 == sizeof(c_int8)
    assert 8 if sys.maxsize > 2 ** 32 else 4 == sizeof(c_long)  # Platform dependant.
    assert 8 == sizeof(c_longlong)
    assert 2 == sizeof(c_uint16)
    assert 4 == sizeof(c_uint32)
    assert 8 == sizeof(c_uint64)
    assert 1 == sizeof(c_uint8)
    assert 1 == sizeof(c_ubyte)
    assert 4 == sizeof(c_uint)
    assert 8 if sys.maxsize > 2 ** 32 else 4 == sizeof(c_ulong)  # Platform dependant.
    assert 8 == sizeof(c_ulonglong)
    assert 2 == sizeof(c_ushort)


def test_minimum():
    """Test minimum valid integer value."""
    assert -128 == c_byte.from_buffer(bytearray(c_byte(-128))).value
    assert -2147483648 == c_int.from_buffer(bytearray(c_int(-2147483648))).value
    assert -128 == c_int8.from_buffer(bytearray(c_int8(-128))).value
    if sys.maxsize > 2 ** 32:  # 64-bit.
        assert -9223372036854775808 == c_long.from_buffer(bytearray(c_long(-9223372036854775808))).value
    else:
        assert -2147483648 == c_long.from_buffer(bytearray(c_long(-2147483648))).value
    assert -9223372036854775808 == c_longlong.from_buffer(bytearray(c_longlong(-9223372036854775808))).value


def test_zero():
    """Test zero integer value."""
    assert 0 == c_byte.from_buffer(bytearray(c_byte())).value
    assert 0 == c_int.from_buffer(bytearray(c_int())).value
    assert 0 == c_int8.from_buffer(bytearray(c_int8())).value
    assert 0 == c_long.from_buffer(bytearray(c_long())).value
    assert 0 == c_longlong.from_buffer(bytearray(c_longlong())).value
    assert 0 == c_uint16.from_buffer(bytearray(c_uint16())).value
    assert 0 == c_uint32.from_buffer(bytearray(c_uint32())).value
    assert 0 == c_uint64.from_buffer(bytearray(c_uint64())).value
    assert 0 == c_uint8.from_buffer(bytearray(c_uint8())).value
    assert 0 == c_ubyte.from_buffer(bytearray(c_ubyte())).value
    assert 0 == c_uint.from_buffer(bytearray(c_uint())).value
    assert 0 == c_ulong.from_buffer(bytearray(c_ulong())).value
    assert 0 == c_ulonglong.from_buffer(bytearray(c_ulonglong())).value
    assert 0 == c_ushort.from_buffer(bytearray(c_ushort())).value


def test_middle():
    """Test with arbitrary positive value."""
    assert 123 == c_byte.from_buffer(bytearray(c_byte(123))).value
    assert 1234567890 == c_int.from_buffer(bytearray(c_int(1234567890))).value
    assert 123 == c_int8.from_buffer(bytearray(c_int8(123))).value
    assert 1234567890 == c_long.from_buffer(bytearray(c_long(1234567890))).value
    assert 1234567890123456789 == c_longlong.from_buffer(bytearray(c_longlong(1234567890123456789))).value
    assert 12345 == c_uint16.from_buffer(bytearray(c_uint16(12345))).value
    assert 1234567890 == c_uint32.from_buffer(bytearray(c_uint32(1234567890))).value
    assert 12345678901234567890 == c_uint64.from_buffer(bytearray(c_uint64(12345678901234567890))).value
    assert 123 == c_uint8.from_buffer(bytearray(c_uint8(123))).value
    assert 123 == c_ubyte.from_buffer(bytearray(c_ubyte(123))).value
    assert 1234567890 == c_uint.from_buffer(bytearray(c_uint(1234567890))).value
    assert 1234567890 == c_ulong.from_buffer(bytearray(c_ulong(1234567890))).value
    assert 12345678901234567890 == c_ulonglong.from_buffer(bytearray(c_ulonglong(12345678901234567890))).value
    assert 12345 == c_ushort.from_buffer(bytearray(c_ushort(12345))).value


def test_maximum():
    """Test maximum valid integer value."""
    assert 127 == c_byte.from_buffer(bytearray(c_byte(127))).value
    assert 2147483647 == c_int.from_buffer(bytearray(c_int(2147483647))).value
    assert 127 == c_int8.from_buffer(bytearray(c_int8(127))).value
    if sys.maxsize > 2 ** 32:  # 64-bit.
        assert 9223372036854775807 == c_long.from_buffer(bytearray(c_long(9223372036854775807))).value
    else:
        assert 2147483647 == c_long.from_buffer(bytearray(c_long(2147483647))).value
    assert 9223372036854775807 == c_longlong.from_buffer(bytearray(c_longlong(9223372036854775807))).value
    assert 65535 == c_uint16.from_buffer(bytearray(c_uint16(65535))).value
    assert 4294967295 == c_uint32.from_buffer(bytearray(c_uint32(4294967295))).value
    assert 18446744073709551615 == c_uint64.from_buffer(bytearray(c_uint64(18446744073709551615))).value
    assert 255 == c_uint8.from_buffer(bytearray(c_uint8(255))).value
    assert 255 == c_ubyte.from_buffer(bytearray(c_ubyte(255))).value
    assert 4294967295 == c_uint.from_buffer(bytearray(c_uint(4294967295))).value
    if sys.maxsize > 2 ** 32:  # 64-bit.
        assert 18446744073709551615 == c_ulong.from_buffer(bytearray(c_ulong(18446744073709551615))).value
    else:
        assert 4294967295 == c_ulong.from_buffer(bytearray(c_ulong(4294967295))).value
    assert 18446744073709551615 == c_ulonglong.from_buffer(bytearray(c_ulonglong(18446744073709551615))).value
    assert 65535 == c_ushort.from_buffer(bytearray(c_ushort(65535))).value


def test_minimum_overflow():
    """Test negative overflow value."""
    assert 127 == c_byte(-129).value
    assert 2147483647 == c_int(-2147483649).value
    assert 127 == c_int8(-129).value
    if sys.maxsize > 2 ** 32:  # 64-bit.
        assert 9223372036854775807 == c_long(-9223372036854775809).value
    else:
        assert 2147483647 == c_long(-2147483649).value
    assert 9223372036854775807 == c_longlong(-9223372036854775809).value
    assert 65535 == c_uint16(-1).value
    assert 4294967295 == c_uint32(-1).value
    assert 18446744073709551615 == c_uint64(-1).value
    assert 255 == c_uint8(-1).value
    assert 255 == c_ubyte(-1).value
    assert 4294967295 == c_uint(-1).value
    if sys.maxsize > 2 ** 32:  # 64-bit.
        assert 18446744073709551615 == c_ulong(-1).value
    else:
        assert 4294967295 == c_ulong(-1).value
    assert 18446744073709551615 == c_ulonglong(-1).value
    assert 65535 == c_ushort(-1).value


def test_minimum_overflow_more():
    """Test negative overflow value with even lower numbers."""
    assert 27 == c_byte(-229).value
    assert 2147383647 == c_int(-2147583649).value
    assert 117 == c_int8(-139).value
    if sys.maxsize > 2 ** 32:  # 64-bit.
        assert 9223372036814775807 == c_long(-9223372036894775809).value
    else:
        assert 2147483647 == c_long(-2147483649).value
    assert 9223372033854775807 == c_longlong(-9223372039854775809).value
    assert 65524 == c_uint16(-12).value
    assert 4294967283 == c_uint32(-13).value
    assert 18446744073709551602 == c_uint64(-14).value
    assert 241 == c_uint8(-15).value
    assert 240 == c_ubyte(-16).value
    assert 4294967279 == c_uint(-17).value
    if sys.maxsize > 2 ** 32:  # 64-bit.
        assert 18446744073709551598 == c_ulong(-18).value
    else:
        assert 4294967277 == c_ulong(-19).value
    assert 18446744073709551598 == c_ulonglong(-18).value
    assert 65515 == c_ushort(-21).value


def test_maximum_overflow():
    """Test positive overflow value."""
    assert -128 == c_byte(128).value
    assert -2147483648 == c_int(2147483648).value
    assert -128 == c_int8(128).value
    if sys.maxsize > 2 ** 32:  # 64-bit.
        assert -9223372036854775808 == c_long(9223372036854775808).value
    else:
        assert -2147483648 == c_long(2147483648).value
    assert -9223372036854775808 == c_longlong(9223372036854775808).value
    assert 0 == c_uint16(65536).value
    assert 0 == c_uint32(4294967296).value
    assert 0 == c_uint64(18446744073709551616).value
    assert 0 == c_uint8(256).value
    assert 0 == c_ubyte(256).value
    assert 0 == c_uint(4294967296).value
    if sys.maxsize > 2 ** 32:  # 64-bit.
        assert 0 == c_ulong(18446744073709551616).value
    else:
        assert 0 == c_ulong(4294967296).value
    assert 0 == c_ulonglong(18446744073709551616).value
    assert 0 == c_ushort(65536).value


def test_maximum_overflow_more():
    """Test positive overflow value with even greater numbers."""
    assert -118 == c_byte(138).value
    assert -2147482548 == c_int(2147484748).value
    assert -118 == c_int8(138).value
    if sys.maxsize > 2 ** 32:  # 64-bit.
        assert -9223372036854775708 == c_long(9223372036854775908).value
    else:
        assert -2147483548 == c_long(2147483748).value
    assert -9223372036854775708 == c_longlong(9223372036854775908).value
    assert 100 == c_uint16(65636).value
    assert 100 == c_uint32(4294967396).value
    assert 100 == c_uint64(18446744073709551716).value
    assert 100 == c_uint8(356).value
    assert 90 == c_ubyte(346).value
    assert 100 == c_uint(4294967396).value
    if sys.maxsize > 2 ** 32:  # 64-bit.
        assert 200 == c_ulong(18446744073709551816).value
    else:
        assert 1000 == c_ulong(4294968296).value
    assert 200 == c_ulonglong(18446744073709551816).value
    assert 10 == c_ushort(65546).value


def test_repr():
    """Test repr() of instances."""
    assert 'c_byte(123)' == repr(c_byte(123))
    if sys.maxsize > 2 ** 32:  # 64-bit.
        assert 'c_int(1234567890)' == repr(c_int(1234567890))
    else:
        assert 'c_long(1234567890)' == repr(c_int(1234567890)).replace('L)', ')')
    assert 'c_byte(123)' == repr(c_int8(123))
    assert 'c_long(1234567890)' == repr(c_long(1234567890)).replace('L)', ')')
    if sys.maxsize > 2 ** 32:  # 64-bit.
        assert 'c_long(1234567890123456789)' == repr(c_longlong(1234567890123456789)).replace('L)', ')')
    else:
        assert 'c_longlong(1234567890123456789)' == repr(c_longlong(1234567890123456789)).replace('L)', ')')
    assert 'c_ushort(12345)' == repr(c_uint16(12345))
    if sys.maxsize > 2 ** 32:  # 64-bit.
        assert 'c_uint(1234567890)' == repr(c_uint32(1234567890)).replace('L)', ')')
    else:
        assert 'c_ulong(1234567890)' == repr(c_uint32(1234567890)).replace('L)', ')')
    if sys.maxsize > 2 ** 32:  # 64-bit.
        assert 'c_ulong(12345678901234567890)' == repr(c_uint64(12345678901234567890)).replace('L)', ')')
    else:
        assert 'c_ulonglong(12345678901234567890)' == repr(c_uint64(12345678901234567890)).replace('L)', ')')
    assert 'c_ubyte(123)' == repr(c_uint8(123))
    assert 'c_ubyte(123)' == repr(c_ubyte(123))
    if sys.maxsize > 2 ** 32:  # 64-bit.
        assert 'c_uint(1234567890)' == repr(c_uint(1234567890)).replace('L)', ')')
    else:
        assert 'c_ulong(1234567890)' == repr(c_uint(1234567890)).replace('L)', ')')
    assert 'c_ulong(1234567890)' == repr(c_ulong(1234567890)).replace('L)', ')')
    if sys.maxsize > 2 ** 32:  # 64-bit.
        assert 'c_ulong(12345678901234567890)' == repr(c_ulonglong(12345678901234567890)).replace('L)', ')')
    else:
        assert 'c_ulonglong(12345678901234567890)' == repr(c_ulonglong(12345678901234567890)).replace('L)', ')')
    assert 'c_ushort(12345)' == repr(c_ushort(12345))


def test_from_buffer_large():
    """Test .from_buffer attribute."""
    data = b'\xb8~?./3\x02\x14\xb2\x89\xfc6A\xa4\x02\x05f\xdb\xb1\x04\xc3\x891\xad\x8cW\xcd\xda\x04A'
    assert -72 == c_byte.from_buffer(bytearray(data)).value
    assert 775913144 == c_int.from_buffer(bytearray(data)).value
    assert -72 == c_int8.from_buffer(bytearray(data)).value
    if sys.maxsize > 2 ** 32:  # 64-bit.
        assert 1441771108444372664 == c_long.from_buffer(bytearray(data)).value
    else:
        assert 775913144 == c_long.from_buffer(bytearray(data)).value
    assert 1441771108444372664 == c_longlong.from_buffer(bytearray(data)).value
    assert 32440 == c_uint16.from_buffer(bytearray(data)).value
    assert 775913144 == c_uint32.from_buffer(bytearray(data)).value
    assert 1441771108444372664 == c_uint64.from_buffer(bytearray(data)).value
    assert 184 == c_uint8.from_buffer(bytearray(data)).value
    assert 184 == c_ubyte.from_buffer(bytearray(data)).value
    assert 775913144 == c_uint.from_buffer(bytearray(data)).value
    if sys.maxsize > 2 ** 32:  # 64-bit.
        assert 1441771108444372664 == c_ulong.from_buffer(bytearray(data)).value
    else:
        assert 775913144 == c_ulong.from_buffer(bytearray(data)).value
    assert 1441771108444372664 == c_ulonglong.from_buffer(bytearray(data)).value
    assert 32440 == c_ushort.from_buffer(bytearray(data)).value


def test_from_buffer_error():
    """Test .from_buffer attribute with invalid arguments."""
    all_types = (c_byte, c_int, c_int8, c_long, c_longlong, c_uint16, c_uint32, c_uint64, c_uint8, c_ubyte, c_uint,
                 c_ulong, c_ulonglong, c_ushort)
    for ctype in all_types:
        with pytest.raises(ValueError):
            ctype.from_buffer(bytearray())
        with pytest.raises(TypeError):
            ctype.from_buffer(0)
        with pytest.raises(TypeError):
            ctype('')


def test_set_from_value():
    """Test .value attribute, read and write."""
    all_types = (c_byte, c_int, c_int8, c_long, c_longlong, c_uint16, c_uint32, c_uint64, c_uint8, c_ubyte, c_uint,
                 c_ulong, c_ulonglong, c_ushort)
    instances = list()
    for ctype in all_types:
        inst = ctype(9223372036854775908)
        for i in range(7759):
            inst.value += 1
        instances.append(repr(inst).replace('L)', ')'))

    expected = [
        'c_byte(-77)',
        'c_int(7859)' if sys.maxsize > 2 ** 32 else 'c_long(7859)',
        'c_byte(-77)',
        'c_long(-9223372036854767949)' if sys.maxsize > 2 ** 32 else 'c_long(7859)',
        'c_long(-9223372036854767949)' if sys.maxsize > 2 ** 32 else 'c_longlong(-9223372036854767949)',
        'c_ushort(7859)',
        'c_uint(7859)' if sys.maxsize > 2 ** 32 else 'c_ulong(7859)',
        'c_ulong(9223372036854783667)' if sys.maxsize > 2 ** 32 else 'c_ulonglong(9223372036854783667)',
        'c_ubyte(179)',
        'c_ubyte(179)',
        'c_uint(7859)' if sys.maxsize > 2 ** 32 else 'c_ulong(7859)',
        'c_ulong(9223372036854783667)' if sys.maxsize > 2 ** 32 else 'c_ulong(7859)',
        'c_ulong(9223372036854783667)' if sys.maxsize > 2 ** 32 else 'c_ulonglong(9223372036854783667)',
        'c_ushort(7859)',
    ]
    assert expected == instances
