"""Linux Netlink interfacing classes."""

import os
import socket
import struct

from wifinl.netlink.attributes import NLANullString, parse
from wifinl.netlink.enums import ControllerAttr, ControllerCmd, NetlinkFlags, NetlinkMessages

CTRL_ATTR_FAMILY_ID = ControllerAttr.CTRL_ATTR_FAMILY_ID
CTRL_ATTR_FAMILY_NAME = ControllerAttr.CTRL_ATTR_FAMILY_NAME
CTRL_CMD_GETFAMILY = ControllerCmd.CTRL_CMD_GETFAMILY
NLM_F_REQUEST = NetlinkFlags.NLM_F_REQUEST
NLMSG_ERROR = NetlinkMessages.NLMSG_ERROR
NLMSG_MIN_TYPE = NetlinkMessages.NLMSG_MIN_TYPE


class Message(object):
    def __init__(self, type_, flags=0, seq=-1, payload=None):
        self.type_, self.flags, self.seq, self.pid, payload = type_, flags, seq, -1, (payload or list())
        if hasattr(payload, '__iter__') and hasattr(iter(payload).next(), 'dump'):
            self.payload = ''.join(a.dump() for a in payload)
        else:
            self.payload = payload

    def send(self, connection):
        self.pid = connection.pid
        if self.seq == -1:
            self.seq = connection.seq

        hdr = struct.pack('IHHII', len(self.payload) + 16, self.type_, self.flags, self.seq, self.pid)
        connection.send(hdr + self.payload)


class Connection(object):
    def __init__(self, netlink_type, groups=0, unexpected=None):
        self.descriptor = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, netlink_type)
        self.descriptor.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
        self.descriptor.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        self.descriptor.bind((0, groups))

        self.pid, self.groups = self.descriptor.getsockname()
        self.unexpected = unexpected
        self._seq_counter = 0

    @property
    def seq(self):
        self._seq_counter += 1
        return self._seq_counter

    def send(self, message):
        self.descriptor.send(message)

    def recv(self):
        contents = self.descriptor.recvfrom(16384)[0]
        _, message_type, flags, seq, pid = struct.unpack('IHHII', contents[:16])
        message = Message(message_type, flags, seq, contents[16:])
        message.pid = pid

        if message.type_ == NLMSG_ERROR:
            error_number = -struct.unpack('i', message.payload[:4])[0]
            if error_number:
                raise OSError(error_number, 'Netlink error: {0} ({1})'.format(os.strerror(error_number), error_number))

        return message


class GenericNetlinkHeader(object):
    def __init__(self, command, version=0):
        self.command = command
        self.version = version

    def dump(self):
        return struct.pack('BBxx', self.command, self.version)


class GenericNetlinkMessage(Message):
    def __init__(self, family, command, attributes=None, flags=0):
        self.family = family
        self.command = command
        self.attributes = attributes
        payload = [GenericNetlinkHeader(self.command)] + attributes
        super(GenericNetlinkMessage, self).__init__(family, flags, payload=payload)


class Controller(object):
    def __init__(self, connection):
        self.connection = connection

    def get_family_id(self, family):
        attribute = NLANullString(CTRL_ATTR_FAMILY_NAME, family)
        message = GenericNetlinkMessage(NLMSG_MIN_TYPE, CTRL_CMD_GETFAMILY, [attribute], NLM_F_REQUEST)
        message.send(self.connection)
        message_recv = self.connection.recv()
        #gnlh = GenericNetlinkHeader(*struct.unpack('BBxx', message_recv.payload[:4]))
        attributes = parse(message_recv.payload[4:])
        return attributes[CTRL_ATTR_FAMILY_ID].u16()
