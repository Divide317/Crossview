# libcrossview — build
#   make            release build: build/libcrossview.so
#   make asan       sanitizer build (ASan + UBSan): build-asan/libcrossview.so
#   make test       build + run C unit tests under ASan/UBSan
#   make pytest     run Python tests against the release .so
#   make tidy       clang-tidy over src/
#   make valgrind   run the C tests under valgrind (release build)
#   make bpf        build the eBPF sensor (needs clang, bpftool, libbpf; run on the VM)
#   make clean

CC      ?= cc
CSTD    := -std=c11
WARN    := -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion \
           -Wstrict-prototypes -Wmissing-prototypes -Wformat=2 -Wundef
DEFS    := -D_GNU_SOURCE
INC     := -Iinclude -Isrc
PIC     := -fPIC -fvisibility=hidden
LIBS    := -ldl

SRCS    := src/util.c src/views.c src/classify.c src/report.c src/crossview.c
TESTS   := tests/test_main.c

REL_CFLAGS  := $(CSTD) $(WARN) $(DEFS) $(INC) $(PIC) -O2 -g -fstack-protector-strong -D_FORTIFY_SOURCE=2
ASAN_CFLAGS := $(CSTD) $(WARN) $(DEFS) $(INC) $(PIC) -O1 -g -fno-omit-frame-pointer \
               -fsanitize=address,undefined -fno-sanitize-recover=undefined

.PHONY: all asan test pytest tidy valgrind bpf clean

all: build/libcrossview.so

build/libcrossview.so: $(SRCS) include/libcrossview.h src/internal.h
	@mkdir -p build
	$(CC) $(REL_CFLAGS) -shared -Wl,-z,relro,-z,now -o $@ $(SRCS) $(LIBS)

build-asan/libcrossview.so: $(SRCS) include/libcrossview.h src/internal.h
	@mkdir -p build-asan
	$(CC) $(ASAN_CFLAGS) -shared -o $@ $(SRCS) $(LIBS)

asan: build-asan/libcrossview.so

# Tests compile the library sources directly (not via the .so) so they can
# reach the internal diff engine in src/internal.h.
build-asan/test_main: $(TESTS) $(SRCS) include/libcrossview.h src/internal.h
	@mkdir -p build-asan
	$(CC) $(ASAN_CFLAGS) -o $@ $(TESTS) $(SRCS) $(LIBS)

build/test_main: $(TESTS) $(SRCS) include/libcrossview.h src/internal.h
	@mkdir -p build
	$(CC) $(REL_CFLAGS) -o $@ $(TESTS) $(SRCS) $(LIBS)

test: build-asan/test_main
	./build-asan/test_main

valgrind: build/test_main
	valgrind --error-exitcode=1 --leak-check=full --errors-for-leak-kinds=all ./build/test_main

pytest: build/libcrossview.so
	CROSSVIEW_LIB=$(CURDIR)/build/libcrossview.so python3 -m pytest -q python/tests

tidy:
	clang-tidy $(SRCS) -- $(CSTD) $(DEFS) $(INC)

bpf:
	$(MAKE) -C bpf

clean:
	rm -rf build build-asan
	-$(MAKE) -C bpf clean
