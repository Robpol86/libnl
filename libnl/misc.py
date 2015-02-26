"""Misc code not defined in Netlink but used by it."""

import ctypes
import random

SIZEOF_INT = ctypes.sizeof(ctypes.c_int)
SIZEOF_POINTER = ctypes.sizeof(ctypes.c_void_p)  # Platform dependant.
SIZEOF_U16 = ctypes.sizeof(ctypes.c_uint16)
SIZEOF_U32 = ctypes.sizeof(ctypes.c_uint32)
SIZEOF_U64 = ctypes.sizeof(ctypes.c_uint64)
SIZEOF_U8 = ctypes.sizeof(ctypes.c_uint8)
SIZEOF_UINT = ctypes.sizeof(ctypes.c_uint)
SIZEOF_USHORT = ctypes.sizeof(ctypes.c_ushort)


class _DynamicDict(dict):
    """A dict to be used in str.format() in StructNoPointers and StructWithPointers subclasses."""

    def __init__(self, instance):
        super().__init__()
        self._instance = instance

    def __missing__(self, key):
        return getattr(self._instance, key)


class _StructBase(object):
    """Holds common properties/methods for StructNoPointers and StructWithPointers."""
    _REPR = '<{0}.{1}>'
    SIGNATURE = ()
    SIZEOF = 0

    def __repr__(self):
        """Returns a repr of the subclass instance with property values."""
        dynamic_dict = _DynamicDict(self)
        answer = self._REPR.format(self.__class__.__module__, self.__class__.__name__, dynamic_dict)
        return answer


class StructNoPointers(_StructBase):
    """A base class equivalent to a C struct of a fixed size, holding no pointers in the struct definition."""

    def __init__(self, maxlen):
        """Creates a bytearray() object of a fixed initial size. Pads it with \0 * maxlen."""
        self.bytearray = bytearray(b'\0') * maxlen

    def __bool__(self):
        """Returns True if self.bytearray is more than just null bytes."""
        return not not self.bytearray.strip(b'\0')

    def __bytes__(self):
        """Returns a bytes object."""
        return bytes(self.bytearray)

    def __str__(self):
        """Returns a hex dump (space delimited per byte) of the data."""
        return ' '.join(format(c, '02x') for c in self.bytearray)

    def _get_slicers(self, index):
        """Returns a 2-item tuple to slice a list/bytearray by.

        Positional arguments:
        index -- index of self.SIGNATURE to target self.bytearray by.

        Returns:
        2-item tuple of integers.
        """
        if not index:  # first item.
            return 0, self.SIGNATURE[0]
        if index >= len(self.SIGNATURE):
            raise IndexError('index out of self.SIGNATURE range')
        pad_head = sum(self.SIGNATURE[:index])
        pad_tail = pad_head + self.SIGNATURE[index]
        return pad_head, pad_tail


class StructWithPointers(_StructBase):
    """A base class equivalent to a C struct that contains pointers."""

    def __init__(self, var_count):
        """Creates a list of 0-length bytearray() instances."""
        self.bytearrays = [bytearray() for _ in range(var_count)]
        self.pointers = dict()  # Keys are unique (to this dict) bytearray() uints, values are bytearray() payloads.

    def __bool__(self):
        """Returns True if any bytearray is more than just null bytes."""
        return not not (c for a in self.bytearrays if a for c in a if c)

    def __bytes__(self):
        """Returns a bytes object without resolving pointers."""
        return bytes(c for a in self.bytearrays for c in a)

    def __str__(self):
        """Returns a hex dump (space delimited per byte) of the data without resolving pointers."""
        return ' '.join(format(c, '02x') for a in self.bytearrays for c in a)

    @property
    def bytearray(self):
        """Returns self.bytearrays merged into a single bytearray with pointers resolved."""
        resolved = bytearray()
        for array in self.bytearrays:
            if array in self.pointers:
                resolved.extend(self.pointers[array])
            else:
                resolved.extend(array)
        return resolved

    def new_pointer(self):
        """Picks a random integer from 1 to the maximum pointer size depending on the platform.

        SIZEOF_POINTER is 4 bytes on 32bit systems, and 8bytes on 64bit.

        Returns:
        Bytearray encoded unsigned integer not in self.pointers.
        """
        while True:
            candidate_int = random.randint(1, 2 ** (8 * SIZEOF_POINTER))
            candidate_ba = bytearray(bytes(ctypes.c_uint64(candidate_int)))[:SIZEOF_POINTER]
            if candidate_ba not in self.pointers:
                return candidate_ba


class ucred(StructNoPointers):
    """Ancillary message for passing credentials.
    http://linux.die.net/man/7/unix
    http://stackoverflow.com/questions/1922761/size-of-pid-t-uid-t-gid-t-on-linux

    Instance variables:
    pid -- process ID of the sending process (c_uint32).
    uid -- user ID of the sending process (c_uint32).
    gid -- group ID of the sending process (c_uint32).
    """
    _REPR = '<{0}.{1} pid={2[pid]} uid={2[uid]} gid={2[uid]}>'
    SIGNATURE = (SIZEOF_U32, SIZEOF_U32, SIZEOF_U32)
    SIZEOF = sum(SIGNATURE)

    def __init__(self, pid=0, uid=0, gid=0):
        super().__init__(self.SIZEOF)
        self.pid = pid
        self.uid = uid
        self.gid = gid

    @property
    def pid(self):
        """Process ID of the sending process."""
        head, tail = self._get_slicers(0)
        return ctypes.c_uint32.from_buffer(self.bytearray[head:tail]).value

    @pid.setter
    def pid(self, value):
        head, tail = self._get_slicers(0)
        self.bytearray[head:tail] = bytearray(ctypes.c_int32(value or 0))

    @property
    def uid(self):
        """User ID of the sending process."""
        head, tail = self._get_slicers(1)
        return ctypes.c_uint32.from_buffer(self.bytearray[head:tail]).value

    @uid.setter
    def uid(self, value):
        head, tail = self._get_slicers(1)
        self.bytearray[head:tail] = bytearray(ctypes.c_int32(value or 0))

    @property
    def gid(self):
        """Group ID of the sending process."""
        head, tail = self._get_slicers(2)
        return ctypes.c_uint32.from_buffer(self.bytearray[head:tail]).value

    @gid.setter
    def gid(self, value):
        head, tail = self._get_slicers(2)
        self.bytearray[head:tail] = bytearray(ctypes.c_int32(value or 0))


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


def split_bytearray(buf, *expected_c_types):
    """Splits and parses bytearray() buffer into expected c_types.

    Positional arguments:
    buf -- bytearray() object to parse.

    Keyword arguments:
    expected_c_types -- one or more c_types object (not instance).

    Returns:
    Tuple of c_types.<type>.from_buffer() values. Last item is remainder of buf if too long or empty bytearray().
    """
    buf_remaining = buf.copy()
    parsed = []
    for type_ in expected_c_types:
        size = ctypes.sizeof(type_)
        chunk = buf_remaining[:size]
        restored = type_.from_buffer(chunk)
        parsed.append(restored)
        buf_remaining = buf_remaining[size:]
    parsed.append(buf_remaining)
    return tuple(parsed)
