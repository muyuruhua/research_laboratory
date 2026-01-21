#
# ChatAFL-Enhanced Makefile (Lightweight - No unused modules)
#
# This version DOES NOT include verifier/cegar/scheduler
# to isolate performance issues
#

PROGNAME    = afl
VERSION     = 2.52b

PREFIX     ?= /usr/local
BIN_PATH    = $(PREFIX)/bin
HELPER_PATH = $(PREFIX)/lib/afl
DOC_PATH    = $(PREFIX)/share/doc/afl
MISC_PATH   = $(PREFIX)/share/afl

PROGS       = afl-gcc afl-fuzz afl-replay aflnet-replay aflnet-client afl-showmap afl-tmin afl-gotcpu afl-analyze
SH_PROGS    = afl-plot afl-cmin afl-whatsup

# Match ChatAFL optimization level EXACTLY
CFLAGS     ?= -O3 -funroll-loops
CFLAGS     += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign -Wno-unused-result \
              -DAFL_PATH=\"$(HELPER_PATH)\" -DDOC_PATH=\"$(DOC_PATH)\" \
              -DBIN_PATH=\"$(BIN_PATH)\"

# Enable Enhanced modules if CHATAFL_ENHANCED=1
ifdef CHATAFL_ENHANCED
  CFLAGS += -DCHATAFL_ENHANCED=1
  ENHANCED_OBJS = verifier.o cegar-refinement.o state-scheduler.o verifier_extended.o cegar-optimized.o
else
  ENHANCED_OBJS =
endif

ifneq "$(filter Linux GNU%,$(shell uname))" ""
  LDFLAGS  += -ldl -lgvc -lcgraph -lm -lcap
endif

ifeq "$(findstring clang, $(shell $(CC) --version 2>/dev/null))" ""
  TEST_CC   = afl-gcc
else
  TEST_CC   = afl-clang
endif

COMM_HDR    = alloc-inl.h config.h debug.h types.h

all: test_x86 $(PROGS) afl-as test_build all_done

ifndef AFL_NO_X86
test_x86:
	@echo "[*] Checking for the ability to compile x86 code..."
	@echo 'main() { __asm__("xorb %al, %al"); }' | $(CC) -w -x c - -o .test || ( echo; echo "Oops, looks like your compiler can't generate x86 code."; echo; echo "Don't panic! You can use the LLVM or QEMU mode, but see docs/INSTALL first."; echo "(To ignore this error, set AFL_NO_X86=1 and try again.)"; echo; exit 1 )
	@rm -f .test
	@echo "[+] All right, the instrumentation seems to be working!"
else
test_x86:
	@echo "[!] Note: skipping x86 compilation checks (AFL_NO_X86 set)."
endif

afl-gcc: afl-gcc.c $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $@.c -o $@ $(LDFLAGS)
	ln -sf afl-gcc afl-g++

# Link Enhanced modules if CHATAFL_ENHANCED=1
afl-fuzz: afl-fuzz.c aflnet.o chat-llm.o $(ENHANCED_OBJS) $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $@.c aflnet.o chat-llm.o $(ENHANCED_OBJS) -o $@ $(LDFLAGS) -lcurl -ljson-c -lpcre2-8

afl-showmap: afl-showmap.c $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $@.c aflnet.o -o $@ $(LDFLAGS)

afl-tmin: afl-tmin.c $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $@.c aflnet.o -o $@ $(LDFLAGS)

afl-replay: afl-replay.c $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $@.c aflnet.o -o $@ $(LDFLAGS)

aflnet-replay: aflnet-replay.c $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $@.c aflnet.o -o $@ $(LDFLAGS)

aflnet-client: aflnet-client.c aflnet.o $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $@.c aflnet.o -o $@ $(LDFLAGS)

afl-gotcpu: afl-gotcpu.c $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $@.c -o $@ $(LDFLAGS)

afl-analyze: afl-analyze.c $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $@.c -o $@ $(LDFLAGS)

aflnet.o: aflnet.c aflnet.h
	$(CC) $(CFLAGS) -c aflnet.c -o aflnet.o

chat-llm.o: chat-llm.c chat-llm.h
	$(CC) $(CFLAGS) -c chat-llm.c -o chat-llm.o -lcurl -ljson-c

# Enhanced module object files
verifier.o: verifier.c verifier.h
	$(CC) $(CFLAGS) -c verifier.c -o verifier.o

cegar-refinement.o: cegar-refinement.c cegar-refinement.h verifier.h
	$(CC) $(CFLAGS) -c cegar-refinement.c -o cegar-refinement.o

state-scheduler.o: state-scheduler.c state-scheduler.h verifier.h
	$(CC) $(CFLAGS) -c state-scheduler.c -o state-scheduler.o

verifier_extended.o: verifier_extended.c verifier.h state-graph.h
	$(CC) $(CFLAGS) -c verifier_extended.c -o verifier_extended.o

cegar-optimized.o: cegar-optimized.c cegar-optimized.h
	$(CC) $(CFLAGS) -c cegar-optimized.c -o cegar-optimized.o

afl-as: afl-as.c afl-as.h $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $@.c -o $@ $(LDFLAGS)
	ln -sf afl-as as

test_build: afl-gcc afl-as afl-showmap
	@echo "[*] Testing the CC wrapper and instrumentation output..."
	unset AFL_USE_ASAN AFL_USE_MSAN; AFL_QUIET=1 AFL_INST_RATIO=100 AFL_PATH=. ./$(TEST_CC) $(CFLAGS) test-instr.c -o test-instr $(LDFLAGS)
	./afl-showmap -m none -q -o .test-instr0 ./test-instr < /dev/null
	echo 1 | ./afl-showmap -m none -q -o .test-instr1 ./test-instr
	@rm -f test-instr
	@cmp -s .test-instr0 .test-instr1; DR="$$?"; rm -f .test-instr0 .test-instr1; if [ "$$DR" = "0" ]; then echo; echo "Oops, the instrumentation does not seem to be behaving correctly!"; echo; echo "Please ping <lcamtuf@google.com> to troubleshoot the issue."; echo; exit 1; fi
	@echo "[+] All right, the instrumentation seems to be working!"

all_done: test_build
	@echo "[+] All done! Be sure to review README - it's pretty short and useful."
	@echo "[!] LIGHTWEIGHT BUILD - No Enhanced modules"

.NOTPARALLEL: clean

clean:
	rm -f $(PROGS) afl-as as afl-g++ *.o *~ a.out core core.[1-9][0-9]* *.stackdump test .test test-instr .test-instr0 .test-instr1 qemu_mode/qemu-2.10.0.tar.bz2 afl-qemu-trace
	rm -rf out_dir qemu_mode/qemu-2.10.0
	$(MAKE) -C llvm_mode clean
	$(MAKE) -C libdislocator clean
	$(MAKE) -C libtokencap clean

install: all
	install -m 755 $(PROGS) $(SH_PROGS) $DESTDIR/$(BIN_PATH)
	rm -f $DESTDIR/$(BIN_PATH)/afl-g++ 2>/dev/null
	ln -sf afl-gcc $DESTDIR/$(BIN_PATH)/afl-g++
	install -m 755 afl-as $DESTDIR/$(HELPER_PATH)
	ln -sf afl-as $DESTDIR/$(HELPER_PATH)/as
	install -m 644 dictionaries/*.dict $DESTDIR/$(MISC_PATH)/dictionaries
	install -m 644 docs/*.txt $DESTDIR/$(DOC_PATH)
	cp -r testcases/ $DESTDIR/$(MISC_PATH)
	cp -r experimental/ $DESTDIR/$(MISC_PATH)
