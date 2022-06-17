#!/usr/bin/env bash

function usage() {
    echo "USAGE: $BASH_SOURCE <bin> <fname> [--debug]"
}

scriptDir="$(dirname -- "$(readlink -f "${BASH_SOURCE}")")"
projectDir="$GHIDRA_BUILD/myproject"
decompileScript="${scriptDir}/../ghidra-scripts/decompile.py"
debugScript="${scriptDir}/../decomp-debug/debug.sh"
bin="$1" # 1st arg: executable to import to Ghidra
fname="$2" # 2nd arg: function name to decompile
debug="$3" # 3rd arg (optional): if eq to "--debug", then set GHIDRA_DEBUG=1 and start GDB

if [ -z "$bin" ] || [ -z "$fname" ]; then
    usage
    exit 1
fi

if [ "$debug" = "--debug" ]; then
    export GHIDRA_DEBUG=1
fi

function decompile() {
    # run the decompile script via analyzeHeadless
    $GHIDRA_BUILD/support/analyzeHeadless \
        $GHIDRA_BUILD \
        myproject \
        -import $bin \
        -postScript $decompileScript $fname \
        -deleteProject
}

function clean() {
    rm -rf "$projectDir/*.rep" "$projectDir/*.gpr" "$projectDir/*.lock" "$projectDir/*.lock~"
}

clean
if [ -z "$GHIDRA_DEBUG" ]; then
    decompile
else
    echo "debug mode"
    decompile &
    sleep 10
    $debugScript
fi
clean