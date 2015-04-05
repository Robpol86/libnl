"""Caching API (netlink-private/cache-api.h).

https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink-private/cache-api.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""


class nl_msgtype(object):
    """Message type to cache action association.

    https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink-private/cache-api.h#L117

    Positional arguments:
    mt_id -- Netlink message type (c_int).
    mt_act -- cache action to take (c_int).
    mt_name -- name of operation for human-readable printing (string).
    """

    def __init__(self, mt_id, mt_act, mt_name):
        """Constructor."""
        self.mt_id = mt_id
        self.mt_act = mt_act
        self.mt_name = mt_name

    def __repr__(self):
        """repr() handler."""
        answer = "<{0}.{1} mt_id={2} mt_act={3} mt_name='{4}'>".format(
            self.__class__.__module__,
            self.__class__.__name__,
            self.mt_id, self.mt_act, self.mt_name,
        )
        return answer


class nl_cache_ops(object):
    """Cache Operations.

    https://github.com/thom311/libnl/blob/libnl3_2_25/include/netlink-private/cache-api.h#L165

    This class defines the characteristics of a cache type. It contains references to functions which implement the
    specifics of the object type the cache can hold.

    Instance variables:
    co_name -- name of cache type (must be unique) (c_bytes).
    co_hdrsize -- size of family specific Netlink header (c_int).
    co_protocol -- Netlink protocol (c_int).
    co_hash_size -- cache object hash size (c_int).
    co_flags -- cache flags (c_uint).
    co_groups -- group definition (nl_af_group class instance).
    co_request_update -- function, called whenever an update of the cache is required. Must send a request message to
        the kernel requesting a complete dump.
    co_msg_parser -- function, called whenever a message was received that needs to be parsed. Must parse the message
        and call the parser callback function (nl_parser_param) provided via the argument.
    co_event_filter -- function, the function registered under this callback is called after a Netlink notification
        associated with this cache type has been parsed into an object and is being considered for inclusion into the
        specified cache. The purpose of this function is to filter out notifications which should be ignored when
        updating caches. The function must return NL_SKIP to prevent the object from being included, or NL_OK to include
        it.
    co_include_event -- function, is called when an object formed from a notification event needs to be included in a
        cache. For each modified object, the change callback `change_cb` must be called with the `data` argument
        provided. If no function is registered, the function nl_cache_include() will be used for this purpose.
    reserved_1 -- function.
    reserved_2 -- function.
    reserved_3 -- function.
    reserved_4 -- function.
    reserved_5 -- function.
    reserved_6 -- function.
    reserved_7 -- function.
    reserved_8 -- function.
    co_obj_ops -- object operations (nl_object_ops class instance).
    co_next -- internal, do not touch, linked list (nl_cache_ops class instance).
    co_major_cache -- nl_cache class instance.
    co_genl -- genl_ops class instance.
    co_msgtypes -- list of nl_msgtype class instances, message type definition.
    """

    def __init__(self, co_name='', co_hdrsize=0, co_protocol=0, co_request_update=None, co_obj_ops=None, co_genl=None,
                 co_msgtypes=None):
        """Constructor."""
        self.co_name = co_name
        self.co_hdrsize = co_hdrsize
        self.co_protocol = co_protocol
        self.co_hash_size = 0
        self.co_flags = 0
        self.co_groups = None
        self.co_request_update = co_request_update
        self.co_msg_parser = None
        self.co_event_filter = None
        self.co_include_event = None
        self.reserved_1 = None
        self.reserved_2 = None
        self.reserved_3 = None
        self.reserved_4 = None
        self.reserved_5 = None
        self.reserved_6 = None
        self.reserved_7 = None
        self.reserved_8 = None
        self.co_obj_ops = co_obj_ops
        self.co_next = None
        self.co_major_cache = None
        self.co_genl = co_genl
        self.co_msgtypes = co_msgtypes or list()

    def __repr__(self):
        """repr() handler."""
        answer_base = ("<{0}.{1} co_name='{2}' co_hdrsize={3} co_protocol={4} co_hash_size={5} co_flags={6} "
                       "co_groups='{7}' co_request_update='{8}' co_msg_parser='{9}' co_event_filter='{10}' "
                       "co_include_event='{11}' reserved_#={12} co_obj_ops='{13}' co_next='{14}' "
                       "co_major_cache='{15}' co_genl='{16}' co_msgtypes='{17}'>")
        answer = answer_base.format(
            self.__class__.__module__,
            self.__class__.__name__,
            self.co_name, self.co_hdrsize, self.co_protocol, self.co_hash_size, self.co_flags, self.co_groups,
            self.co_request_update, self.co_msg_parser, self.co_event_filter, self.co_include_event,
            'yes' if any(getattr(self, 'reserved_{0}'.format(i)) for i in range(1, 9)) else 'no',
            self.co_obj_ops, self.co_next, self.co_major_cache, self.co_genl, self.co_msgtypes,
        )
        return answer
