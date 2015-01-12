"""Linux Netlink enums/constants. Obtained values from C header files.

Not all of these may be used.
"""


class NetlinkProtocols(object):
    """Netlink protocol names to numbers.

    http://www.carisma.slowglass.com/~tgr/libnl/doc/core.html#core_netlink_fundamentals
    http://lxr.free-electrons.com/source/include/uapi/linux/netlink.h#L8
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


class MessageFlags(object):
    """Netlink message flags.

    http://www.carisma.slowglass.com/~tgr/libnl/doc/core.html#core_msg_flags
    http://lxr.free-electrons.com/source/include/uapi/linux/netlink.h#L50
    """
    NLM_F_REQUEST = 1  # It is request message.
    NLM_F_MULTI = 2  # Multipart message, terminated by NLMSG_DONE.
    NLM_F_ACK = 4  # Reply with ack, with zero or error code.
    NLM_F_ECHO = 8  # Echo this request.
    NLM_F_DUMP_INTR = 16  # Dump was inconsistent due to sequence change.
    NLM_F_ROOT = 0x100  # Specify tree root.
    NLM_F_MATCH = 0x200  # Return all matching.
    NLM_F_DUMP = NLM_F_ROOT | NLM_F_MATCH  # Return a list of all objects.
    NLM_F_REPLACE = 0x100  # Override existing.
    NLM_F_EXCL = 0x200  # Do not touch, if it exists.
    NLM_F_CREATE = 0x400  # Create, if it does not exist.
    NLM_F_APPEND = 0x800  # Add to end of list.


class MessageTypes(object):
    """Netlink message types.

    http://www.carisma.slowglass.com/~tgr/libnl/doc/core.html#core_msg_types
    http://lxr.free-electrons.com/source/include/uapi/linux/netlink.h#L92
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


class NL80211Cmd(object):
    """Netlink wireless library (nl80211) commands.

    From: http://lxr.free-electrons.com/source/include/uapi/linux/nl80211.h#L725
    """
    NL80211_CMD_UNSPEC = 0
    NL80211_CMD_GET_WIPHY = 1  # Can dump.
    NL80211_CMD_SET_WIPHY = 2
    NL80211_CMD_NEW_WIPHY = 3
    NL80211_CMD_DEL_WIPHY = 4
    NL80211_CMD_GET_INTERFACE = 5  # Can dump.
    NL80211_CMD_SET_INTERFACE = 6
    NL80211_CMD_NEW_INTERFACE = 7
    NL80211_CMD_DEL_INTERFACE = 8
    NL80211_CMD_GET_KEY = 9
    NL80211_CMD_SET_KEY = 10
    NL80211_CMD_NEW_KEY = 11
    NL80211_CMD_DEL_KEY = 12
    NL80211_CMD_GET_BEACON = 13
    NL80211_CMD_SET_BEACON = 14
    NL80211_CMD_START_AP = 15
    NL80211_CMD_NEW_BEACON = NL80211_CMD_START_AP
    NL80211_CMD_STOP_AP = 16
    NL80211_CMD_DEL_BEACON = NL80211_CMD_STOP_AP
    NL80211_CMD_GET_STATION = 17
    NL80211_CMD_SET_STATION = 18
    NL80211_CMD_NEW_STATION = 19
    NL80211_CMD_DEL_STATION = 20
    NL80211_CMD_GET_MPATH = 21
    NL80211_CMD_SET_MPATH = 22
    NL80211_CMD_NEW_MPATH = 23
    NL80211_CMD_DEL_MPATH = 24
    NL80211_CMD_SET_BSS = 25
    NL80211_CMD_SET_REG = 26
    NL80211_CMD_REQ_SET_REG = 27
    NL80211_CMD_GET_MESH_CONFIG = 28
    NL80211_CMD_SET_MESH_CONFIG = 29
    NL80211_CMD_SET_MGMT_EXTRA_IE = 30  # Reserved; not used.
    NL80211_CMD_GET_REG = 31
    NL80211_CMD_GET_SCAN = 32
    NL80211_CMD_TRIGGER_SCAN = 33
    NL80211_CMD_NEW_SCAN_RESULTS = 34
    NL80211_CMD_SCAN_ABORTED = 35
    NL80211_CMD_REG_CHANGE = 36
    NL80211_CMD_AUTHENTICATE = 37
    NL80211_CMD_ASSOCIATE = 38
    NL80211_CMD_DEAUTHENTICATE = 39
    NL80211_CMD_DISASSOCIATE = 40
    NL80211_CMD_MICHAEL_MIC_FAILURE = 41
    NL80211_CMD_REG_BEACON_HINT = 42
    NL80211_CMD_JOIN_IBSS = 43
    NL80211_CMD_LEAVE_IBSS = 44
    NL80211_CMD_TESTMODE = 45
    NL80211_CMD_CONNECT = 46
    NL80211_CMD_ROAM = 47
    NL80211_CMD_DISCONNECT = 48
    NL80211_CMD_SET_WIPHY_NETNS = 49
    NL80211_CMD_GET_SURVEY = 50
    NL80211_CMD_NEW_SURVEY_RESULTS = 51
    NL80211_CMD_SET_PMKSA = 52
    NL80211_CMD_DEL_PMKSA = 53
    NL80211_CMD_FLUSH_PMKSA = 54
    NL80211_CMD_REMAIN_ON_CHANNEL = 55
    NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL = 56
    NL80211_CMD_SET_TX_BITRATE_MASK = 57
    NL80211_CMD_REGISTER_FRAME = 58
    NL80211_CMD_REGISTER_ACTION = NL80211_CMD_REGISTER_FRAME
    NL80211_CMD_FRAME = 59
    NL80211_CMD_ACTION = NL80211_CMD_FRAME
    NL80211_CMD_FRAME_TX_STATUS = 60
    NL80211_CMD_ACTION_TX_STATUS = NL80211_CMD_FRAME_TX_STATUS
    NL80211_CMD_SET_POWER_SAVE = 61
    NL80211_CMD_GET_POWER_SAVE = 62
    NL80211_CMD_SET_CQM = 63
    NL80211_CMD_NOTIFY_CQM = 64
    NL80211_CMD_SET_CHANNEL = 65
    NL80211_CMD_SET_WDS_PEER = 66
    NL80211_CMD_FRAME_WAIT_CANCEL = 67
    NL80211_CMD_JOIN_MESH = 68
    NL80211_CMD_LEAVE_MESH = 69
    NL80211_CMD_UNPROT_DEAUTHENTICATE = 70
    NL80211_CMD_UNPROT_DISASSOCIATE = 71
    NL80211_CMD_NEW_PEER_CANDIDATE = 72
    NL80211_CMD_GET_WOWLAN = 73
    NL80211_CMD_SET_WOWLAN = 74
    NL80211_CMD_START_SCHED_SCAN = 75
    NL80211_CMD_STOP_SCHED_SCAN = 76
    NL80211_CMD_SCHED_SCAN_RESULTS = 77
    NL80211_CMD_SCHED_SCAN_STOPPED = 78
    NL80211_CMD_SET_REKEY_OFFLOAD = 79
    NL80211_CMD_PMKSA_CANDIDATE = 80
    NL80211_CMD_TDLS_OPER = 81
    NL80211_CMD_TDLS_MGMT = 82
    NL80211_CMD_UNEXPECTED_FRAME = 83
    NL80211_CMD_PROBE_CLIENT = 84
    NL80211_CMD_REGISTER_BEACONS = 85
    NL80211_CMD_UNEXPECTED_4ADDR_FRAME = 86
    NL80211_CMD_SET_NOACK_MAP = 87
    NL80211_CMD_CH_SWITCH_NOTIFY = 88
    NL80211_CMD_START_P2P_DEVICE = 89
    NL80211_CMD_STOP_P2P_DEVICE = 90
    NL80211_CMD_CONN_FAILED = 91
    NL80211_CMD_SET_MCAST_RATE = 92
    NL80211_CMD_SET_MAC_ACL = 93
    NL80211_CMD_RADAR_DETECT = 94
    NL80211_CMD_GET_PROTOCOL_FEATURES = 95
    NL80211_CMD_UPDATE_FT_IES = 96
    NL80211_CMD_FT_EVENT = 97
    NL80211_CMD_CRIT_PROTOCOL_START = 98
    NL80211_CMD_CRIT_PROTOCOL_STOP = 99
    NL80211_CMD_GET_COALESCE = 100
    NL80211_CMD_SET_COALESCE = 101
    NL80211_CMD_CHANNEL_SWITCH = 102
    NL80211_CMD_VENDOR = 103
    NL80211_CMD_SET_QOS_MAP = 104
