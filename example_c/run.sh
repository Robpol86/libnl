#!/bin/bash
set -e
#export NLDBG=2

for f in *.c; do
    echo "Building $f..."
    gcc $(pkg-config --cflags --libs libnl-genl-3.0) -o /tmp/program $f
    echo "Executing..."
    /tmp/program
    echo
done
