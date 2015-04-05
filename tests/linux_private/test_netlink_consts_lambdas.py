"""Tests for libnl/linux_private/netlink."""

from libnl.linux_private.netlink import NLA_ALIGN, NLA_HDRLEN, NLMSG_ALIGN, NLMSG_HDRLEN, NLMSG_LENGTH, NLMSG_SPACE


def test_nlmsg_align():
    """Test NLMSG_ALIGN."""
    assert 0 == NLMSG_ALIGN(0)
    assert 4 == NLMSG_ALIGN(1)
    assert 4 == NLMSG_ALIGN(2)
    assert 20 == NLMSG_ALIGN(19)
    assert 20 == NLMSG_ALIGN(20)
    assert 52 == NLMSG_ALIGN(50)


def test_nlmsg_hdrlen():
    """Test NLMSG_HDRLEN."""
    assert 16 == NLMSG_HDRLEN


def test_nlmsg_length():
    """Test NLMSG_LENGTH."""
    assert 16 == NLMSG_LENGTH(0)
    assert 17 == NLMSG_LENGTH(1)
    assert 18 == NLMSG_LENGTH(2)
    assert 35 == NLMSG_LENGTH(19)
    assert 36 == NLMSG_LENGTH(20)
    assert 66 == NLMSG_LENGTH(50)


def test_nlmsg_space():
    """Test NLMSG_SPACE."""
    assert 16 == NLMSG_SPACE(0)
    assert 20 == NLMSG_SPACE(1)
    assert 20 == NLMSG_SPACE(2)
    assert 36 == NLMSG_SPACE(19)
    assert 36 == NLMSG_SPACE(20)
    assert 68 == NLMSG_SPACE(50)


def test_nla_align():
    """Test NLA_ALIGN."""
    assert 0 == NLA_ALIGN(0)
    assert 4 == NLA_ALIGN(1)
    assert 4 == NLA_ALIGN(2)
    assert 20 == NLA_ALIGN(19)
    assert 20 == NLA_ALIGN(20)
    assert 52 == NLA_ALIGN(50)


def test_nla_hdrlen():
    """Test NLA_HDRLEN."""
    assert 4 == NLA_HDRLEN
