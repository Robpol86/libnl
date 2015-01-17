"""Default Netlink Message Handlers (netlink/handlers.h).
https://github.com/thom311/libnl/blob/master/include/netlink/handlers.h

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation version 2.1
of the License.
"""

NL_OK = 0  # Proceed with whatever would come next.
NL_SKIP = 1  # Skip this message.
NL_STOP = 2  # Stop parsing altogether and discard remaining messages.

NL_CB_DEFAULT = 0  # Default handlers (quiet).
NL_CB_VERBOSE = 1  # Verbose default handlers (error messages printed).
NL_CB_DEBUG = 2  # Debug handlers for debugging.
NL_CB_CUSTOM = 3  # Customized handler specified by the user.

NL_CB_VALID = 0  # Message is valid.
NL_CB_FINISH = 1  # Last message in a series of multi part messages received.
NL_CB_OVERRUN = 2  # Report received that data was lost.
NL_CB_SKIPPED = 3  # Message wants to be skipped.
NL_CB_ACK = 4  # Message is an acknowledge.
NL_CB_MSG_IN = 5  # Called for every message received.
NL_CB_MSG_OUT = 6  # Called for every message sent out except for nl_sendto().
NL_CB_INVALID = 7  # Message is malformed and invalid.
NL_CB_SEQ_CHECK = 8  # Called instead of internal sequence number checking.
NL_CB_SEND_ACK = 9  # Sending of an acknowledge message has been requested.
NL_CB_DUMP_INTR = 10  # Flag NLM_F_DUMP_INTR is set in message.
