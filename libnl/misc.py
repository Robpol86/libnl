"""Misc code not defined in Netlink but used by it."""

from ctypes import c_int32, c_uint32, POINTER, Structure


class ucred(Structure):
    """Ancillary message for passing credentials.
    http://linux.die.net/man/7/unix
    http://stackoverflow.com/questions/1922761/size-of-pid-t-uid-t-gid-t-on-linux
    """
    _fields_ = [
        ('pid', c_int32),  # Process ID of the sending process.
        ('uid', c_uint32),  # User ID of the sending process.
        ('gid', c_uint32),  # Group ID of the sending process.
    ]


def define_struct(type_, maxlen, fields):
    """Shorthand for `type my_struct[maxlen] = { [ATTR1] = value, [ATTR2] = value };`.

    :param type_:
    :param maxlen:
    :param fields:
    :return:
    """
    array_type = type_ * maxlen
    null_ptr = POINTER(type_)
    padded_fields = list()
    for i in range(maxlen):
        padded_fields.append(fields.get(i, null_ptr))
    array = array_type(*padded_fields)
    return array


class msghdr(object):
    """msghdr struct from sys/socket.h
    http://pubs.opengroup.org/onlinepubs/7908799/xns/syssocket.h.html

    Instance variables:
    msg_name -- optional address.
    msg_iov -- bytes() instance to send (payload data).
    msg_control -- ancillary data.
    msg_flags -- flags on received message.
    """

    def __init__(self, msg_name=None, msg_iov=None, msg_control=None, msg_flags=0):
        self.msg_name = msg_name
        self.msg_iov = msg_iov
        self.msg_control = msg_control
        self.msg_flags = msg_flags
