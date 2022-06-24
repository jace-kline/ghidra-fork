# The path to the decompiler source code (C++)
DECOMP_SRC_DIR=Ghidra/Features/Decompiler/src/decompile/cpp
BUILD_ZIP_DIR=build/dist

.PHONY: build clean cleanbuild cleaninstall install buildinstall builddecomp installdecomp cleandecomp reallycleandecomp launch launchdebug kill reallykill

# build zip file, stored at 'build/dist/'
build:
	gradle buildGhidra

# clean development artifacts
clean:
	gradle clean

# clean all zip builds at 'build/dist/'
cleanbuild:
	rm -rf $(BUILD_ZIP_DIR)/*.zip

# clean the built & extracted project located in $GHIDRA_BUILD directory
cleaninstall:
	rm -rf $(GHIDRA_BUILD)

# unzip the built .zip archive at 'build/dist/' to the $GHIDRA_BUILD path
install:
	@ zips=$$(ls $(BUILD_ZIP_DIR)) ;\
	zipcount=$$(echo $$zips | wc -w) ;\
	if [ $$zipcount -ne 1 ]; then \
		echo Error: 0 or more than 1 zip build present in build/dist directory ;\
		exit 1 ;\
	fi ;\
	unzip $(BUILD_ZIP_DIR)/$$zips -d $(GHIDRA_BUILD) ;\
	mv $$GHIDRA_BUILD/ghidra*/* $$GHIDRA_BUILD

# build everything and extract it to $GHIDRA_BUILD directory
buildinstall: cleanbuild build cleaninstall install

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

launch:
	$$GHIDRA_BUILD/ghidraRun

launchdebug:
	GHIDRA_DEBUG=1 $$GHIDRA_BUILD/ghidraRun

kill:
	python3 ./fork/scripts/kill.py

reallykill:
	kill $$(pidof java)
	kill $$(pidof decompile)
	