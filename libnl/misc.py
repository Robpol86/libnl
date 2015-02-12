"""Misc code not defined in Netlink but used by it."""

import ctypes


class ucred(object):
    """Ancillary message for passing credentials.
    http://linux.die.net/man/7/unix
    http://stackoverflow.com/questions/1922761/size-of-pid-t-uid-t-gid-t-on-linux

    Instance variables:
    pid -- process ID of the sending process.
    uid -- user ID of the sending process.
    gid -- group ID of the sending process.
    """

    def __init__(self, pid=0, uid=0, gid=0):
        self._pid, self._uid, self._gid = None, None, None
        self.pid = pid
        self.uid = uid
        self.gid = gid

    @property
    def pid(self):
        """c_int32 process ID of the sending process."""
        return self._pid.value

    @pid.setter
    def pid(self, value):
        if value is None:
            self._pid = ctypes.c_int32()
            return
        self._pid = value if isinstance(value, ctypes.c_int32) else ctypes.c_int32(value)

    @property
    def uid(self):
        """c_uint32 user ID of the sending process."""
        return self._uid.value

    @uid.setter
    def uid(self, value):
        if value is None:
            self._uid = ctypes.c_uint32()
            return
        self._uid = value if isinstance(value, ctypes.c_uint32) else ctypes.c_uint32(value)

    @property
    def gid(self):
        """c_uint32 group ID of the sending process."""
        return self._gid.value

    @gid.setter
    def gid(self, value):
        if value is None:
            self._gid = ctypes.c_uint32()
            return
        self._gid = value if isinstance(value, ctypes.c_uint32) else ctypes.c_uint32(value)


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


def __init(func):
    """Implements the equivalent of the GNU C __init initializer function.

    https://gcc.gnu.org/onlinedocs/gccint/Initialization.html

    Decorator used to call functions upon importing the module.

    Positional arguments:
    func -- the decorated function object.

    Returns:
    The same function.
    """
    func()
    return func
