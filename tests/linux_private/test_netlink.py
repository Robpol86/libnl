from ctypes import cast, pointer, POINTER, resize, sizeof

import pytest

from libnl.handlers import NL_CB_VALID
from libnl.linux_private.netlink import (
    NLMSG_ALIGN, NLMSG_ALIGNTO, NLM_F_DUMP,
    NLMSG_OK, nlattr, nlmsghdr, NLA_ALIGN
)


def test_nlmsg_align():
    assert 0 == NLMSG_ALIGN(0)
    assert 4 == NLMSG_ALIGN(1)
    assert 4 == NLMSG_ALIGN(2)
    assert 20 == NLMSG_ALIGN(19)
    assert 20 == NLMSG_ALIGN(20)
    assert 52 == NLMSG_ALIGN(50)


@pytest.mark.skipif('True')
def test_nlmsg_hdrlen():
    assert 16 == NLMSG_HDRLEN


@pytest.mark.skipif('True')
def test_nlmsg_length():
    assert 16 == NLMSG_LENGTH(0)
    assert 17 == NLMSG_LENGTH(1)
    assert 18 == NLMSG_LENGTH(2)
    assert 35 == NLMSG_LENGTH(19)
    assert 36 == NLMSG_LENGTH(20)
    assert 66 == NLMSG_LENGTH(50)


@pytest.mark.skipif('True')
def test_nlmsg_space():
    assert 16 == NLMSG_SPACE(0)
    assert 20 == NLMSG_SPACE(1)
    assert 20 == NLMSG_SPACE(2)
    assert 36 == NLMSG_SPACE(19)
    assert 36 == NLMSG_SPACE(20)
    assert 68 == NLMSG_SPACE(50)


@pytest.mark.skipif('True')
def test_nlmsg_data(correct_answers):
    nlh = pointer(nlmsghdr(nlmsg_len=20, nlmsg_type=NL_CB_VALID, nlmsg_flags=NLM_F_DUMP))
    _nlmsg_data = NLMSG_DATA(nlh)
    _size_to = sizeof(_nlmsg_data) + NLMSG_LENGTH(sizeof(nlmsghdr)) - NLMSG_ALIGNTO.value
    resize(_nlmsg_data, _size_to)
    head = pointer(cast(_nlmsg_data, POINTER(nlattr)))
    assert correct_answers['NLMSG_DATA(sizeof)'] == sizeof(head)
    #assert 0 == int(head.nla_len)  # TODO fix this later.
    #assert 0 == int(head.nla_type)


@pytest.mark.skipif('True')
def test_nlmsg_ok():
    nlh = pointer(nlmsghdr(nlmsg_len=20, nlmsg_type=NL_CB_VALID, nlmsg_flags=NLM_F_DUMP))
    assert False == NLMSG_OK(nlh, 0)
    assert False == NLMSG_OK(nlh, 1)
    assert False == NLMSG_OK(nlh, 2)
    assert False == NLMSG_OK(nlh, 19)
    assert True == NLMSG_OK(nlh, 20)
    assert True == NLMSG_OK(nlh, 50)


@pytest.mark.skipif('True')
def test_nlmsg_payload():
    nlh = pointer(nlmsghdr(nlmsg_len=20, nlmsg_type=NL_CB_VALID, nlmsg_flags=NLM_F_DUMP))
    assert 4 == NLMSG_PAYLOAD(nlh, 0)
    assert 0 == NLMSG_PAYLOAD(nlh, 1)
    assert 0 == NLMSG_PAYLOAD(nlh, 2)
    assert -16 == NLMSG_PAYLOAD(nlh, 19)
    assert -16 == NLMSG_PAYLOAD(nlh, 20)
    assert -48 == NLMSG_PAYLOAD(nlh, 50)


def test_nla_align():
    assert 0 == NLA_ALIGN(0)
    assert 4 == NLA_ALIGN(1)
    assert 4 == NLA_ALIGN(2)
    assert 20 == NLA_ALIGN(19)
    assert 20 == NLA_ALIGN(20)
    assert 52 == NLA_ALIGN(50)


@pytest.mark.skipif('True')
def test_nla_hdrlen():
    assert 4 == NLA_HDRLEN
