buildDir = build
CC = clang

# Paths for lzfse
LZFSE_DIR = libNeoAppleArchive/compression/lzfse
# The installation prefix (where the lzfse library will be built to)
BUILD_DIR = ../../../build/lzfse

output: $(buildDir)
	@ # Build liblzfse submodule
	@echo "building liblzfse..."
	$(MAKE) -C $(LZFSE_DIR) install INSTALL_PREFIX=$(BUILD_DIR)
	@ # Build libNeoAppleArchive.a
	@echo "building libNeoAppleArchive..."
	@$(CC) -c libNeoAppleArchive/*.c -Os
	@mv neo_aa_header.o build/obj/neo_aa_header.o
	@mv libNeoAppleArchive_internal.o build/obj/libNeoAppleArchive_internal.o
	@mv libNeoAppleArchive.o build/obj/libNeoAppleArchive.o
	@ar rcs build/usr/lib/libNeoAppleArchive.a build/obj/*.o

$(buildDir):
	@echo "Creating Build Directory"
	mkdir -p build/usr/lib
	mkdir build/usr/bin
	mkdir build/obj
	mkdir build/lzfse