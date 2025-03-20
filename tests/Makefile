buildDir = build
CC = clang
CFLAGS += -fPIC -Os -Wall -pedantic -Wextra -I../libNeoAppleArchive

NEOAPPLEARCHIVE_DIR = ../

output: $(buildDir)
	@ # Build libNeoAppleArchive submodule
	@echo "building libNeoAppleArchive..."
	$(MAKE) -C $(NEOAPPLEARCHIVE_DIR)

	@ # Build tests
	@echo "building tests..."
	@$(CC) *.c -L../build/usr/lib -L../build/lzfse/lib -L../build/libzbitmap/lib -o build/tests -llzfse -lzbitmap -lNeoAppleArchive -lz -Os $(CFLAGS)

$(buildDir):
	@echo "Creating Build Directory"
	mkdir -p build/obj