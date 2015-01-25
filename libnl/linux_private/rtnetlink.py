"""rtnetlink.h.
https://github.com/thom311/libnl/blob/master/include/linux-private/linux/rtnetlink.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

RTNL_FAMILY_IPMR = 128
RTNL_FAMILY_IP6MR = 129
RTNL_FAMILY_MAX = 129

RTM_BASE = 16
RTM_NEWLINK = 16
RTM_DELLINK = 17
RTM_GETLINK = 18
RTM_SETLINK = 19
RTM_NEWADDR = 20
RTM_DELADDR = 21
RTM_GETADDR = 22
RTM_NEWROUTE = 24
RTM_DELROUTE = 25
RTM_GETROUTE = 26
RTM_NEWNEIGH = 28
RTM_DELNEIGH = 29
RTM_GETNEIGH = 30
RTM_NEWRULE = 32
RTM_DELRULE = 33
RTM_GETRULE = 34
RTM_NEWQDISC = 36
RTM_DELQDISC = 37
RTM_GETQDISC = 38
RTM_NEWTCLASS = 40
RTM_DELTCLASS = 41
RTM_GETTCLASS = 42
RTM_NEWTFILTER = 44
RTM_DELTFILTER = 45
RTM_GETTFILTER = 46
RTM_NEWACTION = 48
RTM_DELACTION = 49
RTM_GETACTION = 50
RTM_NEWPREFIX = 52
RTM_GETMULTICAST = 58
RTM_GETANYCAST = 62
RTM_NEWNEIGHTBL = 64
RTM_GETNEIGHTBL = 66
RTM_SETNEIGHTBL = 67
RTM_NEWNDUSEROPT = 68
RTM_NEWADDRLABEL = 72
RTM_DELADDRLABEL = 73
RTM_GETADDRLABEL = 74
RTM_GETDCB = 78
RTM_SETDCB = 79
RTM_MAX = RTM_SETDCB

RTM_NR_MSGTYPES = RTM_MAX + 1 - RTM_BASE
RTM_NR_FAMILIES = RTM_NR_MSGTYPES >> 2
RTM_FAM = lambda cmd: (cmd - RTM_BASE) >> 2


class rtattr(object):
    """https://github.com/thom311/libnl/blob/master/include/linux-private/linux/rtnetlink.h#L137"""

    def __init__(self, rta_type):
        self.rta_type = int(rta_type)


class rtgenmsg(object):
    """https://github.com/thom311/libnl/blob/master/include/linux-private/linux/rtnetlink.h#L410"""

    def __init__(self, rtgen_family):
        self.rtgen_family = str(rtgen_family)
