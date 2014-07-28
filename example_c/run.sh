#!/bin/bash
set -e

gcc -o /tmp/list_wifi_interfaces list_wifi_interfaces.c /usr/lib/libnl.so
NLDBG=2 /tmp/list_wifi_interfaces

