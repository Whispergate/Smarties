# Smarties BOF - Makefile
#
# Cross-compile with mingw-w64 on Linux/WSL/MSYS2.
# Produces a COFF object file loadable by EmeraldStrike, Cobalt Strike,
# or any CS-compatible BOF loader.

CC_x64 = x86_64-w64-mingw32-gcc

# COFF object flags: compile-only (-c), no standard lib, no default libs
CFLAGS = -c -Os -fno-asynchronous-unwind-tables -fno-ident \
         -fpack-struct=8 -fno-builtin -std=c99 -Wall -Wno-unused-function \
         -masm=intel

# Output naming follows EmeraldStrike convention: name.x64.o
OUTPUT_x64 = smarties.x64.o

.PHONY: all clean

all: $(OUTPUT_x64)

$(OUTPUT_x64): smarties.c beacon.h
	$(CC_x64) $(CFLAGS) -o $@ smarties.c

clean:
	rm -f $(OUTPUT_x64)

# Verify the COFF object has the expected symbols
check: $(OUTPUT_x64)
	@echo "=== COFF Header ==="
	x86_64-w64-mingw32-objdump -f $(OUTPUT_x64)
	@echo ""
	@echo "=== Entry point (go) ==="
	x86_64-w64-mingw32-nm $(OUTPUT_x64) | grep -i " go$$"
	@echo ""
	@echo "=== External symbols (DFR + Beacon API) ==="
	x86_64-w64-mingw32-nm $(OUTPUT_x64) | grep " U " | head -40
	@echo ""
	@echo "=== Sections ==="
	x86_64-w64-mingw32-objdump -h $(OUTPUT_x64)
