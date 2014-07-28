"""Issue nl80211 commands to the wireless device."""

from wifinl.netlink.enums import NetlinkProtocols, MessageFlags, NL80211Cmd
from wifinl.netlink.interfaces import Connection, Controller, GenericNetlinkMessage

CONNECTION = Connection(NetlinkProtocols.NETLINK_GENERIC)
CONTROLLER = Controller(CONNECTION)
FAMILY = CONTROLLER.get_family_id('nl80211')


def devices():
    flags = MessageFlags.NLM_F_REQUEST | MessageFlags.NLM_F_ACK
    message = GenericNetlinkMessage(FAMILY, NL80211Cmd.NL80211_CMD_GET_WIPHY, [], flags)
    message.send(CONNECTION)
    reply = CONNECTION.recv()  # TODO: raises exception.


def execute_command(arguments=None, flags=None):
    pass
