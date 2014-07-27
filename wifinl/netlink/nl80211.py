"""Issue nl80211 commands to the wireless device."""

from wifinl.netlink.enums import Netlink, NetlinkFlags, NL80211Cmd
from wifinl.netlink.interfaces import Connection, Controller, GenericNetlinkMessage

CONNECTION = Connection(Netlink.NETLINK_GENERIC)
CONTROLLER = Controller(CONNECTION)
FAMILY = CONTROLLER.get_family_id('nl80211')


def devices():
    flags = NetlinkFlags.NLM_F_REQUEST | NetlinkFlags.NLM_F_ACK
    message = GenericNetlinkMessage(FAMILY, NL80211Cmd.NL80211_CMD_GET_WIPHY, [], flags)
    message.send(CONNECTION)
    reply = CONNECTION.recv()  # TODO: raises exception.
