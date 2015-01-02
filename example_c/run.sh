#!/bin/bash
set -e
#export NLDBG=2

gcc $(pkg-config --cflags --libs libnl-3.0) -o /tmp/program list_network_interfaces.c

/tmp/program
