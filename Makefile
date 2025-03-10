buildDir = build
CC = clang
CFLAGS += -fPIC -Os

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
	@$(CC) -c libNeoAppleArchive/neo_aa_header.c -o build/obj/neo_aa_header.o $(CFLAGS)
	@$(CC) -c libNeoAppleArchive/libNeoAppleArchive_internal.c -o build/obj/libNeoAppleArchive_internal.o $(CFLAGS)
	@$(CC) -c libNeoAppleArchive/libNeoAppleArchive.c -o build/obj/libNeoAppleArchive.o $(CFLAGS)
	@$(CC) -c libNeoAppleArchive/neo_aea_archive.c -o build/obj/neo_aea_archive.o $(CFLAGS)
	@ar rcs build/usr/lib/libNeoAppleArchive.a build/obj/*.o

$(buildDir):
	@echo "Creating Build Directory"
	mkdir -p build/usr/lib
	mkdir build/usr/bin
	mkdir build/obj
	mkdir build/lzfse