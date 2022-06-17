#!/usr/bin/env bash

scriptDir="$(dirname -- "$(readlink -f "${BASH_SOURCE}")")"

${scriptDir}/decompile.sh \
    ~/dev/research/scratchwork/ghidra_decomp_test/stackarray_trivial \
    main \
    --debug
