#!/usr/bin/env bash

script_dir="$(dirname -- "$(readlink -f "${BASH_SOURCE}")")"
decompiler_path="$GHIDRA_BUILD/Ghidra/Features/Decompiler/os/linux_x86_64/decompile"
init_gdb_script="$script_dir/init.gdb"
tries=10

echo "Attempting to connect GDB to 'decompile' process..."
while [ $tries -gt 0 ]; do
    pid=$(pgrep -fn "$decompiler_path")
    if [ -z $pid ]; then
        echo "No 'decompile' process found. Retrying..."
        sleep 2
    fi
    tries=$(( $tries - 1 ))
done

if [ -z $pid ]; then
    echo "No 'decompile' process found. Exiting."
    exit 1
fi

echo "Attaching to 'decompile' process with pid $pid"
# launch GDB on the process and run the 'init.gdb' script
gdb -q -x "$init_gdb_script" "$decompiler_path" $pid