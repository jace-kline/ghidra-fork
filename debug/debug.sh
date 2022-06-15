#!/bin/bash

decompiler_path="$GHIDRA_BUILD/Ghidra/Features/Decompiler/os/linux_x86_64/decompile"

pid=$(pgrep -fn "$decompiler_path")
if [ -z $pid ]
then
    echo "No decompiler process found"
    exit 1
fi

echo "Attaching to decompiler process with pid $pid"
# launch GDB on the process and run the 'init.gdb' script
gdb -q -x init.gdb "$decompiler_path" $pid