buildDir = build
CC = clang
CFLAGS += -fPIC -Os -Wall -pedantic -Wextra -Ibuild/lzfse/include -Ibuild/libzbitmap/include

# Paths for lzfse
LZFSE_DIR = libNeoAppleArchive/compression/lzfse
# The installation prefix (where the lzfse library will be built to)
BUILD_DIR = ../../../build/lzfse
# Paths for libzbitmap
LIBZBITMAP_DIR = libNeoAppleArchive/compression/libzbitmap
libzbitmapBuildDir = build/libzbitmap/lib/

EXCLUDE_AEA_SUPPORT ?= 0

ifeq ($(EXCLUDE_AEA_SUPPORT), 1)
  CFLAGS += -DEXCLUDE_AEA_SUPPORT=1
endif

output: $(buildDir) $(libzbitmapBuildDir)
	@ # Build liblzfse submodule
	@echo "building liblzfse..."
	$(MAKE) -C $(LZFSE_DIR) install INSTALL_PREFIX=$(BUILD_DIR)
	@ # Build libzbitmap submodule
	@echo "building libzbitmap..."
	$(MAKE) -C $(LIBZBITMAP_DIR)
	mv $(LIBZBITMAP_DIR)/libzbitmap.a build/libzbitmap/lib/
	cp $(LIBZBITMAP_DIR)/libzbitmap.h build/libzbitmap/include/
	@ # Build libNeoAppleArchive.a
	@echo "building libNeoAppleArchive..."
	@$(CC) -c libNeoAppleArchive/neo_aa_header.c -o build/obj/neo_aa_header.o $(CFLAGS)
	@$(CC) -c libNeoAppleArchive/libNeoAppleArchive_internal.c -o build/obj/libNeoAppleArchive_internal.o $(CFLAGS)
	@$(CC) -c libNeoAppleArchive/libNeoAppleArchive.c -o build/obj/libNeoAppleArchive.o $(CFLAGS)
	@if [ "$(EXCLUDE_AEA_SUPPORT)" != "1" ]; then \
		$(CC) -c libNeoAppleArchive/neo_aea_archive.c -o build/obj/neo_aea_archive.o $(CFLAGS); \
		$(CC) -c libNeoAppleArchive/asn1parse.c -o build/obj/asn1parse.o $(CFLAGS); \
	fi
	@ar rcs build/usr/lib/libNeoAppleArchive.a build/obj/*.o

$(libzbitmapBuildDir):
	@echo "Creating libzbitmap Directory"
	mkdir -p build/libzbitmap/lib/ build/libzbitmap/include/

$(buildDir):
	@echo "Creating Build Directory"
	mkdir -p build/usr/lib
	mkdir -p build/usr/bin
	mkdir -p build/obj
	mkdir -p build/lzfse
	mkdir -p build/libzbitmap/lib/ build/libzbitmap/include/