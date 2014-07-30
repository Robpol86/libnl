#!/bin/bash
set -e
#export NLDBG=2

gcc -o /tmp/program list_network_interfaces.c /usr/lib/libnl.so

/tmp/program

