"""Misc code not defined in Netlink but used by it."""

import ctypes
import struct


def _class_factory(base):
    """Create subclasses of ctypes.

    Positional arguments:
    base -- base class to subclass.

    Returns:
    New class definition.
    """
    class ClsPyPy(base):
        def __repr__(self):
            return repr(base(super(ClsPyPy, self).value))

        @classmethod
        def from_buffer(cls, ba):
            try:
                integer = struct.unpack_from(getattr(cls, '_type_'), ba)[0]
            except struct.error:
                len_ = len(ba)
                size = struct.calcsize(getattr(cls, '_type_'))
                if len_ < size:
                    raise ValueError('Buffer size too small ({0} instead of at least {1} bytes)'.format(len_, size))
                raise
            return cls(integer)

    class ClsPy26(base):
        def __repr__(self):
            return repr(base(super(ClsPy26, self).value))

        def __iter__(self):
            return iter(struct.pack(getattr(super(ClsPy26, self), '_type_'), super(ClsPy26, self).value))

    try:
        base.from_buffer(bytearray(base()))
    except TypeError:
        # Python2.6, ctypes cannot be converted to bytearrays.
        return ClsPy26
    except AttributeError:
        # PyPy on my Raspberry Pi, ctypes don't have from_buffer attribute.
        return ClsPyPy
    except ValueError:
        # PyPy on Travis CI, from_buffer cannot handle non-buffer() bytearrays.
        return ClsPyPy
    return base


c_byte = _class_factory(ctypes.c_byte)
c_int = _class_factory(ctypes.c_int)
c_int32 = _class_factory(ctypes.c_int32)
c_int8 = _class_factory(ctypes.c_int8)
c_long = _class_factory(ctypes.c_long)
c_longlong = _class_factory(ctypes.c_longlong)
c_ubyte = _class_factory(ctypes.c_ubyte)
c_uint = _class_factory(ctypes.c_uint)
c_uint16 = _class_factory(ctypes.c_uint16)
c_uint32 = _class_factory(ctypes.c_uint32)
c_uint64 = _class_factory(ctypes.c_uint64)
c_uint8 = _class_factory(ctypes.c_uint8)
c_ulong = _class_factory(ctypes.c_ulong)
c_ulonglong = _class_factory(ctypes.c_ulonglong)
c_ushort = _class_factory(ctypes.c_ushort)
sizeof = ctypes.sizeof

SIZEOF_BYTE = sizeof(c_byte)
SIZEOF_INT = sizeof(c_int)
SIZEOF_LONG = sizeof(c_long)  # Platform dependant.
SIZEOF_LONGLONG = sizeof(c_longlong)
SIZEOF_S8 = sizeof(c_int8)
SIZEOF_U16 = sizeof(c_uint16)
SIZEOF_U32 = sizeof(c_uint32)
SIZEOF_U64 = sizeof(c_uint64)
SIZEOF_U8 = sizeof(c_uint8)
SIZEOF_UBYTE = sizeof(c_ubyte)
SIZEOF_UINT = sizeof(c_uint)
SIZEOF_ULONG = SIZEOF_POINTER = sizeof(c_ulong)  # Platform dependant.
SIZEOF_ULONGLONG = sizeof(c_ulonglong)
SIZEOF_USHORT = sizeof(c_ushort)


class _DynamicDict(dict):
    """A dict to be used in str.format() in Struct."""

    def __init__(self, instance):
        super(_DynamicDict, self).__init__()
        self._instance = instance

    def __missing__(self, key):
        value = getattr(self._instance, key)
        if key == 'payload':
            value = len(value)
            return '{0}byte{1}'.format(value, '' if value == 1 else 's')
        return value


class Struct(object):
    """A base class equivalent to a C struct of a fixed size, holding no pointers in the struct definition."""

    _REPR = '<{0}.{1}>'
    SIGNATURE = ()
    SIZEOF = 0

    def __init__(self, ba=None):
        self.bytearray = ba or (bytearray(b'\0') * self.SIZEOF)

    def __bool__(self):
        """Returns True if self.bytearray is more than just null bytes."""
        return not not bytearray(self.bytearray).strip(b'\0')

    def __bytes__(self):
        """Returns a bytes object."""
        return bytes(self.bytearray)

    def __nonzero__(self):
        """Python 2.x compatibility."""
        return self.__bool__()

    def __repr__(self):
        """Returns a repr of the subclass instance with property values."""
        dynamic_dict = _DynamicDict(self)
        answer = self._REPR.format(self.__class__.__module__, self.__class__.__name__, dynamic_dict)
        return answer

    def __str__(self):
        """Returns a hex dump (space delimited per byte) of the data."""
        return ' '.join(format(c, '02x') for c in self.bytearray)

    def _get_slicers(self, index):
        """Returns a slice object to slice a list/bytearray by.

        Positional arguments:
        index -- index of self.SIGNATURE to target self.bytearray by.

        Returns:
        slice() object. E.g. `x = _get_slicers(0); ba_instance[x]`
        """
        if not index:  # first item.
            return slice(0, self.SIGNATURE[0])
        if index >= len(self.SIGNATURE):
            raise IndexError('index out of self.SIGNATURE range')
        pad_start = sum(self.SIGNATURE[:index])
        pad_stop = pad_start + self.SIGNATURE[index]
        return slice(pad_start, pad_stop)


class ucred(Struct):
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
        super(ucred, self).__init__()
        self.pid = pid
        self.uid = uid
        self.gid = gid

    @property
    def pid(self):
        """Process ID of the sending process."""
        return c_uint32.from_buffer(self.bytearray[self._get_slicers(0)]).value

    @pid.setter
    def pid(self, value):
        self.bytearray[self._get_slicers(0)] = bytearray(c_int32(value or 0))

    @property
    def uid(self):
        """User ID of the sending process."""
        return c_uint32.from_buffer(self.bytearray[self._get_slicers(1)]).value

    @uid.setter
    def uid(self, value):
        self.bytearray[self._get_slicers(1)] = bytearray(c_int32(value or 0))

    @property
    def gid(self):
        """Group ID of the sending process."""
        return c_uint32.from_buffer(self.bytearray[self._get_slicers(2)]).value

    @gid.setter
    def gid(self, value):
        self.bytearray[self._get_slicers(2)] = bytearray(c_int32(value or 0))


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


class bytearray_ptr(object):
    """Pseudo bytearray that references a sliced bytearray.

    Edits allowed, changes to length forbidden.
    Pointee/actual bytearray can be increased on the right only.

    Use `oob` to access nested bytearray_ptr instances to reference data
    in a pointee's pointee.

    Instance variables:
    pointee -- actual bytearray to operate on.
    start -- index of the actual bytearray to start this pseudo bytearray.
    stop -- index of the actual bytearray to end this pseudo bytearray.
    oob -- go out of bounds with negative start/stop values.
    """

    def __init__(self, pointee, start=None, stop=None, oob=False):
        # Hard-code borders.
        start = start or 0
        stop = stop or (start if stop == 0 else len(pointee))
        if not oob and start < 0:
            start += len(pointee)
        if stop < 0:
            stop += len(pointee)

        # Resolve nested references.
        if hasattr(pointee, 'pointee'):
            start += pointee.slice.start
            stop += pointee.slice.start
            pointee = pointee.pointee

        self.pointee = pointee
        self.slice = slice(start, stop)

    def __repr__(self):
        return "{0}(b'{1}')".format(self.__class__.__name__, ''.join(r'\x{0:02x}'.format(c) for c in bytearray(self)))

    def __delitem__(self, key):
        raise TypeError("'{0}' object doesn't support item deletion".format(self.__class__.__name__))

    def __getitem__(self, item):
        return self.pointee[self.slice][item]

    def __len__(self):
        return len(self.pointee[self.slice])

    def __setitem__(self, key, value):
        # Handle integer keys (lookup).
        try:
            int(key)
        except TypeError:
            key_is_int = False
        else:
            key_is_int = True
            if key < 0:
                key += len(self)
            key = slice(key, key + 1)

        # Calculate slices.
        start = key.start or 0
        if start < 0:
            start += len(self)
        if start >= len(self):
            raise IndexError('{0} index out of range'.format(self.__class__.__name__))
        stop = key.stop or (start if key.stop == 0 else len(self))
        if stop < 0:
            stop += len(self)
        start += self.slice.start
        stop += self.slice.start
        stop = min(stop, self.slice.stop)

        # Catch invalid length.
        original_length = len(self.pointee)
        if not key_is_int and len(self.pointee[start:stop]) != len(value):
            raise TypeError("length of '{0}' object cannot be changed".format(self.__class__.__name__))

        # Handle slices.
        if key_is_int:
            self.pointee[start] = value
        else:
            self.pointee[start:stop] = value

        # Catch bugs.
        if len(self.pointee) != original_length:
            raise RuntimeError('Bug in {0} found! Please report this.'.format(self.__class__.__name__))

    def copy(self):
        return bytearray(self.pointee[self.slice])


def get_string(stream):
    """Use this to grab a "string" from a bytearray() stream.

    C's printf() prints until it encounters a null byte (b'\0'). This function behaves the same.

    Positional arguments:
    stream -- bytearray stream of data.

    Returns:
    bytes() instance of any characters from the start of the stream until before the first null byte.
    """
    ba = bytearray()
    for c in stream:
        if not c:
            break
        ba.append(c)
    return bytes(ba)
