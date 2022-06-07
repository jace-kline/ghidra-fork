# The path to the decompiler source code (C++)
DECOMP_SRC_DIR=Ghidra/Features/Decompiler/src/decompile/cpp

# build zip file, stored at 'build/dist/'
build:
	gradle buildGhidra

# clean development artifacts
clean:
	gradle clean

# clean all zip builds at 'build/dist/'
cleanzip:
	rm -f build/dist/*.zip

# unzip the built .zip archive at 'build/dist/' to the $GHIDRA_BUILD path
install:
	@ zips=$$(ls build/dist/*.zip) ;\
	zipcount=$$(echo $$zips | wc -w) ;\
	if [ $$zipcount -ne 1 ]; then \
		echo Error: More than one zip build present ;\
		exit 1 ;\
	fi ;\
	unzip $$zips -d $(GHIDRA_BUILD) ;\
	mv $$GHIDRA_BUILD/ghidra*/* $$GHIDRA_BUILD

# build everything and extract it to $GHIDRA_BUILD directory
buildinstall: build install

# clean the $GHIDRA_BUILD installation directory
cleaninstall:
	rm -rf $(GHIDRA_BUILD)

# build the decompiler C++ code (with debugging symbols)
builddecomp:
	make -C $(DECOMP_SRC_DIR) ghidra_dbg

# install the built decompiler binary directly to installation directory
# prevents us from rebuilding entire project at top level
installdecomp:
	make -C $(DECOMP_SRC_DIR) install_ghidradbg

# run `make clean` on the decompiler source directory
cleandecomp:
	make -C $(DECOMP_SRC_DIR) clean

reallycleandecomp:
	make -C $(DECOMP_SRC_DIR) reallyclean
	