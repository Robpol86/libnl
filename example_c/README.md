# Netlink/NL80211 C Examples

Source code in this directory compiles into C programs that are independent from this Python library. These are programs
I wrote as exercises for understanding C and libnl in general (I haven't ever written C before).

These all work, and I use these programs as starting points for Python examples using the `libnl` library. Since these
programs are dependent on libnl, which is only available on Linux, they will not work on OS X or Windows. I've tested
them on a `Raspberry Pi` running Raspbian.

To get some debug information from these programs, set these environment variables:
    * NLDBG=4
    * NLCB=debug
