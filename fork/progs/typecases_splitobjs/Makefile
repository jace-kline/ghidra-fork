CC := gcc
FLAGS :=

SRCS := $(wildcard *.c)
BASENAMES := $(basename $(SRCS))
OBJS := $(patsubst %.c,%.o,$(SRCS))
MAINSRC := main.c

OBJS_O0 := $(patsubst %.c,%_O0.o,$(SRCS))
OBJS_O1 := $(patsubst %.c,%_O1.o,$(SRCS))
OBJS_O2 := $(patsubst %.c,%_O2.o,$(SRCS))
OBJS_O3 := $(patsubst %.c,%_O3.o,$(SRCS))
OBJS_DEBUG_O0 := $(patsubst %.c,%_debug_O0.o,$(SRCS))
OBJS_DEBUG_O1 := $(patsubst %.c,%_debug_O1.o,$(SRCS))
OBJS_DEBUG_O2 := $(patsubst %.c,%_debug_O2.o,$(SRCS))
OBJS_DEBUG_O3 := $(patsubst %.c,%_debug_O3.o,$(SRCS))

EXE_BASE := $(basename $(MAINSRC))
EXE_O0 := $(EXE_BASE)_O0.bin
EXE_O1 := $(EXE_BASE)_O1.bin
EXE_O2 := $(EXE_BASE)_O2.bin
EXE_O3 := $(EXE_BASE)_O3.bin
EXE_DEBUG_O0 := $(EXE_BASE)_debug_O0.bin
EXE_DEBUG_O1 := $(EXE_BASE)_debug_O1.bin
EXE_DEBUG_O2 := $(EXE_BASE)_debug_O2.bin
EXE_DEBUG_O3 := $(EXE_BASE)_debug_O3.bin
EXES := $(EXE_O0) $(EXE_O1) $(EXE_O2) $(EXE_O3) $(EXE_DEBUG_O0) $(EXE_DEBUG_O1) $(EXE_DEBUG_O2) $(EXE_DEBUG_O3)

.PHONY: all clean

clean:
	rm -rf *.bin *.o *.dwarfdump *.objdump

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

%_debug_O0.o: %.c
	$(CC) $(FLAGS) -g -O0 -c -o $@ $<

%_debug_O1.o: %.c
	$(CC) $(FLAGS) -g -O1 -c -o $@ $<

%_debug_O2.o: %.c
	$(CC) $(FLAGS) -g -O2 -c -o $@ $<

%_debug_O3.o: %.c
	$(CC) $(FLAGS) -g -O3 -c -o $@ $<

%_O0.o: %.c
	$(CC) $(FLAGS) -O0 -c -o $@ $<

%_O1.o: %.c
	$(CC) $(FLAGS) -O1 -c -o $@ $<

%_O2.o: %.c
	$(CC) $(FLAGS) -O2 -c -o $@ $<

%_O3.o: %.c
	$(CC) $(FLAGS) -O3 -c -o $@ $<

$(EXE_DEBUG_O0): $(OBJS_DEBUG_O0)
	$(CC) $(FLAGS) -g -O0 -o $@ $^

$(EXE_DEBUG_O1): $(OBJS_DEBUG_O1)
	$(CC) $(FLAGS) -g -O1 -o $@ $^

$(EXE_DEBUG_O2): $(OBJS_DEBUG_O2)
	$(CC) $(FLAGS) -g -O2 -o $@ $^

$(EXE_DEBUG_O3): $(OBJS_DEBUG_O3)
	$(CC) $(FLAGS) -g -O3 -o $@ $^

$(EXE_O0): $(OBJS_O0)
	$(CC) $(FLAGS) -O0 -o $@ $^

$(EXE_O1): $(OBJS_O1)
	$(CC) $(FLAGS) -O1 -o $@ $^

$(EXE_O2): $(OBJS_O2)
	$(CC) $(FLAGS) -O2 -o $@ $^

$(EXE_O3): $(OBJS_O3)
	$(CC) $(FLAGS) -O3 -o $@ $^

