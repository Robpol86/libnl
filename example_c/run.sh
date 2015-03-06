#!/bin/bash
set -e
#export NLDBG=2
#export NLCB=debug

for f in list_network_interfaces.c show_wifi_interface.c; do
    echo "Building $f..."
    gcc -o /tmp/program $f $(pkg-config --cflags --libs libnl-genl-3.0)
    echo "Executing..."
    /tmp/program
    echo
done

for f in scan_access_points.c; do
    echo "Building $f..."
    gcc -o /tmp/program $f $(pkg-config --cflags --libs libnl-genl-3.0)
    echo "Executing..."
    sudo /tmp/program
    echo
done
