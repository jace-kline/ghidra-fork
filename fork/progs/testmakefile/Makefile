# The directory path where this Makefile resides
THIS_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
# The parent directory name is assumed to be the program/binary base name
# /path/to/myprogram => myprogram_<qualifiers>.bin
PROGNAME := $(notdir $(THIS_DIR))

%_*.out: %_*.txt
	echo $@ > $<