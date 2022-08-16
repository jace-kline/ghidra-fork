# This Makefile definition is a general Makefile intended to be copied into each directory
# housing a test program (.c files).
# It facilitates compilation, dump information, program info gathering, etc. over different optimization levels and options.

# The directory path where this Makefile resides, once placed with its source code
THISDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
# The parent directory name is assumed to be the program/binary base name
# /path/to/myprogram => myprogram_<qualifiers>.bin
PROGNAME := $(notdir $(patsubst %/,%,$(THISDIR)))
# The C file holding the main() function definition used as program entrypoint
MAINSRC := main.c
PYTHON_LIB := $(THISDIR)/../../evaluate

CC := gcc
FLAGS :=


SRCS := $(wildcard *.c)
BASENAMES := $(basename $(SRCS))
OBJS := $(patsubst %.c,%.o,$(SRCS))

OBJS_O0 := $(patsubst %.c,%_O0.o,$(SRCS))
OBJS_O1 := $(patsubst %.c,%_O1.o,$(SRCS))
OBJS_O2 := $(patsubst %.c,%_O2.o,$(SRCS))
OBJS_O3 := $(patsubst %.c,%_O3.o,$(SRCS))
OBJS_O0_DEBUG := $(patsubst %.c,%_O0_debug.o,$(SRCS))
OBJS_O1_DEBUG := $(patsubst %.c,%_O1_debug.o,$(SRCS))
OBJS_O2_DEBUG := $(patsubst %.c,%_O2_debug.o,$(SRCS))
OBJS_O3_DEBUG := $(patsubst %.c,%_O3_debug.o,$(SRCS))

EXE_BASE := $(PROGNAME)
EXE_O0 := $(EXE_BASE)_O0.bin
EXE_O1 := $(EXE_BASE)_O1.bin
EXE_O2 := $(EXE_BASE)_O2.bin
EXE_O3 := $(EXE_BASE)_O3.bin
EXE_O0_DEBUG := $(EXE_BASE)_O0_debug.bin
EXE_O1_DEBUG := $(EXE_BASE)_O1_debug.bin
EXE_O2_DEBUG := $(EXE_BASE)_O2_debug.bin
EXE_O3_DEBUG := $(EXE_BASE)_O3_debug.bin
EXES := $(EXE_O0) $(EXE_O1) $(EXE_O2) $(EXE_O3) $(EXE_O0_DEBUG) $(EXE_O1_DEBUG) $(EXE_O2_DEBUG) $(EXE_O3_DEBUG)

.PHONY: all clean

clean:
	rm -rf *.bin *.o *.dwarfdump *.objdump *.pickle *.gpr *.rep

%.dwarf.pickle: %.bin $(PYTHON_LIB)/parse_dwarf_exec.py
	python3 $(PYTHON_LIB)/parse_dwarf_exec.py $< pickle $@

%.ghidra.pickle: %.bin $(PYTHON_LIB)/parse_ghidra_exec.py
	$(GHIDRA_BUILD)/support/analyzeHeadless \
		$(THISDIR) \
		tempproject \
		-import $< \
		-scriptpath "$(PYTHON_LIB)" \
		-postscript parse_ghidra_exec.py pickle $@ \
		-deleteproject

# dump the DWARF debugging info for a compiled binary
%.bin.dwarfdump: %.bin
	objdump -g $< > $@

# dump the DWARF disassembly for a compiled binary
%.bin.objdump: %.bin
	objdump -D $< > $@

# dump the DWARF debugging info for an object file
%.o.dwarfdump: %.o
	objdump -g $< > $@

# dump the DWARF disassembly for an object file
%.o.objdump: %.o
	objdump -D $< > $@

# Strip a binary file
%_strip.bin: %.bin
	strip $< -o $@

# Strip an object file
%_strip.o: %.o
	strip $< -o $@

%_O0.o: %.c
	$(CC) $(FLAGS) -O0 -c -o $@ $<

%_O1.o: %.c
	$(CC) $(FLAGS) -O1 -c -o $@ $<

%_O2.o: %.c
	$(CC) $(FLAGS) -O2 -c -o $@ $<

%_O3.o: %.c
	$(CC) $(FLAGS) -O3 -c -o $@ $<

%_O0_debug.o: %.c
	$(CC) $(FLAGS) -g -O0 -c -o $@ $<

%_O1_debug.o: %.c
	$(CC) $(FLAGS) -g -O1 -c -o $@ $<

%_O2_debug.o: %.c
	$(CC) $(FLAGS) -g -O2 -c -o $@ $<

%_O3_debug.o: %.c
	$(CC) $(FLAGS) -g -O3 -c -o $@ $<

$(EXE_O0): $(OBJS_O0)
	$(CC) $(FLAGS) -O0 -o $@ $^

$(EXE_O1): $(OBJS_O1)
	$(CC) $(FLAGS) -O1 -o $@ $^

$(EXE_O2): $(OBJS_O2)
	$(CC) $(FLAGS) -O2 -o $@ $^

$(EXE_O3): $(OBJS_O3)
	$(CC) $(FLAGS) -O3 -o $@ $^

$(EXE_O0_DEBUG): $(OBJS_O0_DEBUG)
	$(CC) $(FLAGS) -g -O0 -o $@ $^

$(EXE_O1_DEBUG): $(OBJS_O1_DEBUG)
	$(CC) $(FLAGS) -g -O1 -o $@ $^

$(EXE_O2_DEBUG): $(OBJS_O2_DEBUG)
	$(CC) $(FLAGS) -g -O2 -o $@ $^

$(EXE_O3_DEBUG): $(OBJS_O3_DEBUG)
	$(CC) $(FLAGS) -g -O3 -o $@ $^
