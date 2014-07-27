"""Linux Netlink enums for the 3.4 kernel. Obtained values from C header files."""


class Netlink(object):
    """Netlink constants.

    From: http://lxr.free-electrons.com/source/include/uapi/linux/netlink.h#L8
    """
    NETLINK_ROUTE = 0  # Routing/device hook.
    NETLINK_UNUSED = 1  # Unused number.
    NETLINK_USERSOCK = 2  # Reserved for user mode socket protocols.
    NETLINK_FIREWALL = 3  # Unused number, formerly ip_queue.
    NETLINK_SOCK_DIAG = 4  # Socket monitoring.
    NETLINK_NFLOG = 5  # netfilter/iptables ULOG.
    NETLINK_XFRM = 6  # ipsec
    NETLINK_SELINUX = 7  # SELinux event notifications.
    NETLINK_ISCSI = 8  # Open-iSCSI
    NETLINK_AUDIT = 9  # auditing
    NETLINK_FIB_LOOKUP = 10
    NETLINK_CONNECTOR = 11
    NETLINK_NETFILTER = 12  # netfilter subsystem.
    NETLINK_IP6_FW = 13
    NETLINK_DNRTMSG = 14  # DECnet routing messages.
    NETLINK_KOBJECT_UEVENT = 15  # Kernel messages to userspace.
    NETLINK_GENERIC = 16


class NetlinkFlags(object):
    """Netlink flags values.

    From: http://lxr.free-electrons.com/source/include/uapi/linux/netlink.h#L50
    """
    NLM_F_REQUEST = 1  # It is request message.
    NLM_F_MULTI = 2  # Multipart message, terminated by NLMSG_DONE.
    NLM_F_ACK = 4  # Reply with ack, with zero or error code.
    NLM_F_ECHO = 8  # Echo this request.
    NLM_F_DUMP_INTR = 16  # Dump was inconsistent due to sequence change.


class NetlinkMessages(object):
    """Netlink messages.

    From: http://lxr.free-electrons.com/source/include/uapi/linux/netlink.h#L92
    """
    NLMSG_NOOP = 0x1  # Nothing
    NLMSG_ERROR = 0x2  # Error
    NLMSG_DONE = 0x3  # End of a dump.
    NLMSG_OVERRUN = 0x4  # Data lost.
    NLMSG_MIN_TYPE = 0x10  # < = 0x10: reserved control messages.


class ControllerCmd(object):
    """Generic Netlink controller commands.

    From: http://lxr.free-electrons.com/source/include/linux/genetlink.h?v=3.4#L36
    """
    CTRL_CMD_UNSPEC = 0
    CTRL_CMD_NEWFAMILY = 1
    CTRL_CMD_DELFAMILY = 2
    CTRL_CMD_GETFAMILY = 3
    CTRL_CMD_NEWOPS = 4
    CTRL_CMD_DELOPS = 5
    CTRL_CMD_GETOPS = 6
    CTRL_CMD_NEWMCAST_GRP = 7
    CTRL_CMD_DELMCAST_GRP = 8


class ControllerAttr(object):
    """Generic Netlink controller attributes.

    From: http://lxr.free-electrons.com/source/include/linux/genetlink.h?v=3.4#L52
    """
    CTRL_ATTR_UNSPEC = 0
    CTRL_ATTR_FAMILY_ID = 1
    CTRL_ATTR_FAMILY_NAME = 2
    CTRL_ATTR_VERSION = 3
    CTRL_ATTR_HDRSIZE = 4
    CTRL_ATTR_MAXATTR = 5
    CTRL_ATTR_OPS = 6
    CTRL_ATTR_MCAST_GROUPS = 7
