from libnl.misc import bytearray_ptr

import pytest


@pytest.mark.parametrize('bytearray_obj', (bytearray, bytearray_ptr))
def test_one_dimension_allowed(bytearray_obj):
    ba = bytearray_obj(bytearray(b'The quick brown fox jumps over the lazy dog.'))
    assert bytearray(b'uick bro') == ba[5:13]

    ba[5:9] = bytearray(b'NULL')
    assert bytearray(b'The qNULL brown fox jumps over the lazy dog.') == bytearray(ba)

    ba[43] = 0
    assert bytearray(b'The qNULL brown fox jumps over the lazy dog\0') == bytearray(ba)
    ba[-2] = 0
    assert bytearray(b'The qNULL brown fox jumps over the lazy do\0\0') == bytearray(ba)
    ba[-4:] = bytearray(b'\0\0\0\0')
    assert bytearray(b'The qNULL brown fox jumps over the lazy \0\0\0\0') == bytearray(ba)
    ba[10:-30] = bytearray(b'\0\0\0\0')
    assert bytearray(b'The qNULL \0\0\0\0n fox jumps over the lazy \0\0\0\0') == bytearray(ba)
    ba[0:-41] = bytearray(b'\0\0\0')
    assert bytearray(b'\0\0\0 qNULL \0\0\0\0n fox jumps over the lazy \0\0\0\0') == bytearray(ba)

    assert 44 == len(ba)
    assert 78 == ba[5]
    assert 101 in ba
    assert 66 not in ba

    with pytest.raises(IndexError):
        ba[45]()

    with pytest.raises(IndexError):
        ba[45] = 100

    expected = [0, 0, 0, 32, 113, 78, 85, 76, 76, 32, 0, 0, 0, 0, 110, 32, 102, 111, 120, 32, 106, 117, 109, 112, 115,
                32, 111, 118, 101, 114, 32, 116, 104, 101, 32, 108, 97, 122, 121, 32, 0, 0, 0, 0]
    assert expected == list(ba)
    e_iter = iter(expected)
    for i in ba:
        assert next(e_iter) == i
    e_iter = iter(expected)
    for i in iter(ba):
        assert next(e_iter) == i
    e_iter = iter(reversed(expected))
    for i in reversed(ba):
        assert next(e_iter) == i


def test_one_dimension_forbidden():
    ba = bytearray_ptr(bytearray(b'The quick brown fox jumps over the lazy dog.'))
    ba[40:] = bytearray(b'\0\0\0\0')  # Allowed because same length.
    ba[:-40] = bytearray(b'\0\0\0\0')  # Allowed because same length.
    assert bytearray(b'\0\0\0\0quick brown fox jumps over the lazy \0\0\0\0') == bytearray(ba)

    with pytest.raises(AttributeError):
        ba.pop()
    with pytest.raises(AttributeError):
        ba.pop(40)

    with pytest.raises(TypeError):
        del ba[39]
    with pytest.raises(TypeError):
        del ba[37:]
    with pytest.raises(TypeError):
        del ba[31:35]
    with pytest.raises(TypeError):
        ba[40:] = bytearray(b'\0\0\0')
    with pytest.raises(TypeError):
        ba[:-40] = bytearray(b'\0\0\0\0\0')

    with pytest.raises(TypeError):
        ba += bytearray(b'more')
        ba.pop()  # PyCharm inspection.


def test_two_dimension():
    pointee = bytearray(b'The quick brown fox jumps over the lazy dog.')
    ba = bytearray_ptr(pointee, 4, 15)
    assert bytearray(b'quick brown') == bytearray(ba)
    assert bytearray(b'quick brown') == bytearray(ba[:100])
    assert bytearray(b'The quick brown fox jumps over the lazy dog.') == pointee

    ba[6:] = bytearray(b'apple')
    assert bytearray(b'quick apple') == bytearray(ba)
    assert bytearray(b'The quick apple fox jumps over the lazy dog.') == pointee

    ba[6:15] = bytearray(b'apple')
    assert bytearray(b'quick apple') == bytearray(ba)
    assert bytearray(b'The quick apple fox jumps over the lazy dog.') == pointee

    ba[6:11] = bytearray(b'green')
    assert bytearray(b'quick green') == bytearray(ba)
    assert bytearray(b'The quick green fox jumps over the lazy dog.') == pointee

    ba[5] = bytearray(b'_')[0]
    assert bytearray(b'quick_green') == bytearray(ba)
    assert bytearray(b'The quick_green fox jumps over the lazy dog.') == pointee

    ba[-2] = 0
    assert bytearray(b'quick_gre\0n') == bytearray(ba)
    assert bytearray(b'The quick_gre\0n fox jumps over the lazy dog.') == pointee

    ba[-4:] = bytearray(b'\0\0\0\0')
    assert bytearray(b'quick_g\0\0\0\0') == bytearray(ba)
    assert bytearray(b'The quick_g\0\0\0\0 fox jumps over the lazy dog.') == pointee
    ba[1:-7] = bytearray(b'\0\0\0')
    assert bytearray(b'q\0\0\0k_g\0\0\0\0') == bytearray(ba)
    assert bytearray(b'The q\0\0\0k_g\0\0\0\0 fox jumps over the lazy dog.') == pointee
    ba[0:-9] = bytearray(b'AA')
    assert bytearray(b'AA\0\0k_g\0\0\0\0') == bytearray(ba)
    assert bytearray(b'The AA\0\0k_g\0\0\0\0 fox jumps over the lazy dog.') == pointee

    assert 11 == len(ba)
    assert 95 == ba[5]
    assert 103 in ba
    assert 66 not in ba

    with pytest.raises(IndexError):
        ba[11]()

    with pytest.raises(IndexError):
        ba[11] = 100

    expected = [65, 65, 0, 0, 107, 95, 103, 0, 0, 0, 0]
    assert expected == list(ba)
    e_iter = iter(expected)
    for i in ba:
        assert next(e_iter) == i
    e_iter = iter(expected)
    for i in iter(ba):
        assert next(e_iter) == i
    e_iter = iter(reversed(expected))
    for i in reversed(ba):
        assert next(e_iter) == i


def test_three_dimension():
    origin = bytearray(b"All letters: The quick brown fox jumps over the lazy dog.\nIsn't it cool?")
    pointee = bytearray_ptr(origin, 13, -15)
    ba = bytearray_ptr(pointee, 4, 15)
    assert bytearray(b'quick brown') == bytearray(ba)
    assert bytearray(b'quick brown') == bytearray(ba[:100])
    assert bytearray(b'The quick brown fox jumps over the lazy dog.') == bytearray(pointee)
    assert bytearray(b"All letters: The quick brown fox jumps over the lazy dog.\nIsn't it cool?") == origin

    ba[6:] = bytearray(b'apple')
    assert bytearray(b'quick apple') == bytearray(ba)
    assert bytearray(b'The quick apple fox jumps over the lazy dog.') == bytearray(pointee)
    assert bytearray(b"All letters: The quick apple fox jumps over the lazy dog.\nIsn't it cool?") == origin

    ba[6:15] = bytearray(b'apple')
    assert bytearray(b'quick apple') == bytearray(ba)
    assert bytearray(b'The quick apple fox jumps over the lazy dog.') == bytearray(pointee)
    assert bytearray(b"All letters: The quick apple fox jumps over the lazy dog.\nIsn't it cool?") == origin

    ba[6:11] = bytearray(b'green')
    assert bytearray(b'quick green') == bytearray(ba)
    assert bytearray(b'The quick green fox jumps over the lazy dog.') == bytearray(pointee)
    assert bytearray(b"All letters: The quick green fox jumps over the lazy dog.\nIsn't it cool?") == origin

    ba[5] = bytearray(b'_')[0]
    assert bytearray(b'quick_green') == bytearray(ba)
    assert bytearray(b'The quick_green fox jumps over the lazy dog.') == bytearray(pointee)
    assert bytearray(b"All letters: The quick_green fox jumps over the lazy dog.\nIsn't it cool?") == origin

    ba[-2] = 0
    assert bytearray(b'quick_gre\0n') == bytearray(ba)
    assert bytearray(b'The quick_gre\0n fox jumps over the lazy dog.') == bytearray(pointee)
    assert bytearray(b"All letters: The quick_gre\0n fox jumps over the lazy dog.\nIsn't it cool?") == origin

    ba[-4:] = bytearray(b'\0\0\0\0')
    assert bytearray(b'quick_g\0\0\0\0') == bytearray(ba)
    assert bytearray(b'The quick_g\0\0\0\0 fox jumps over the lazy dog.') == bytearray(pointee)
    assert bytearray(b"All letters: The quick_g\0\0\0\0 fox jumps over the lazy dog.\nIsn't it cool?") == origin
    ba[1:-7] = bytearray(b'\0\0\0')
    assert bytearray(b'q\0\0\0k_g\0\0\0\0') == bytearray(ba)
    assert bytearray(b'The q\0\0\0k_g\0\0\0\0 fox jumps over the lazy dog.') == bytearray(pointee)
    assert bytearray(b"All letters: The q\0\0\0k_g\0\0\0\0 fox jumps over the lazy dog.\nIsn't it cool?") == origin
    ba[0:-9] = bytearray(b'AA')
    assert bytearray(b'AA\0\0k_g\0\0\0\0') == bytearray(ba)
    assert bytearray(b'The AA\0\0k_g\0\0\0\0 fox jumps over the lazy dog.') == bytearray(pointee)
    assert bytearray(b"All letters: The AA\0\0k_g\0\0\0\0 fox jumps over the lazy dog.\nIsn't it cool?") == origin

    assert 11 == len(ba)
    assert 95 == ba[5]
    assert 103 in ba
    assert 66 not in ba

    with pytest.raises(IndexError):
        ba[11]()

    with pytest.raises(IndexError):
        ba[11] = 100

    expected = [65, 65, 0, 0, 107, 95, 103, 0, 0, 0, 0]
    assert expected == list(ba)
    e_iter = iter(expected)
    for i in ba:
        assert next(e_iter) == i
    e_iter = iter(expected)
    for i in iter(ba):
        assert next(e_iter) == i
    e_iter = iter(reversed(expected))
    for i in reversed(ba):
        assert next(e_iter) == i
