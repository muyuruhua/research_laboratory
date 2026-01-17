#!/bin/bash
# fix_enhanced_performance.sh - 修复ChatAFL-Enhanced性能问题

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHATAFL_DIR="$SCRIPT_DIR/ChatAFL"
ENHANCED_DIR="$SCRIPT_DIR/ChatAFL-Enhanced"

echo "========================================"
echo " ChatAFL-Enhanced 性能修复脚本"
echo "========================================"
echo ""

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 步骤1：备份原始文件
echo -e "${YELLOW}[1/5]${NC} 备份原始文件..."
cd "$ENHANCED_DIR"
if [ ! -f "Makefile.enhanced.backup" ]; then
    cp Makefile.enhanced Makefile.enhanced.backup
    echo "  ✓ 已备份 Makefile.enhanced"
fi

if [ ! -f "Makefile.backup" ]; then
    if [ -f "Makefile" ]; then
        cp Makefile Makefile.backup
        echo "  ✓ 已备份 Makefile"
    fi
fi

# 步骤2：修复编译优化级别
echo -e "${YELLOW}[2/5]${NC} 修复编译优化级别..."
echo "  修改前: CFLAGS = -Wall -O2 -g -fPIC -I."
echo "  修改后: CFLAGS = -Wall -O3 -funroll-loops -march=native -fPIC -I."

# 修改Makefile.enhanced
sed -i 's/CFLAGS = -Wall -O2 -g -fPIC -I\./CFLAGS = -Wall -O3 -funroll-loops -march=native -fPIC -I./' Makefile.enhanced

echo "  ✓ 优化级别已提升到 -O3"

# 步骤3：创建轻量级Makefile（不链接未使用的模块）
echo -e "${YELLOW}[3/5]${NC} 创建轻量级Makefile..."

cat > Makefile.lite << 'EOF'
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

# LIGHTWEIGHT: No enhanced modules linked
afl-fuzz: afl-fuzz.c aflnet.o chat-llm.o $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $@.c aflnet.o chat-llm.o -o $@ $(LDFLAGS) -lcurl -ljson-c -lpcre2-8

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
EOF

echo "  ✓ 已创建 Makefile.lite（不包含未使用的模块）"

# 步骤4：清理并重新编译
echo -e "${YELLOW}[4/5]${NC} 清理并重新编译..."
make clean > /dev/null 2>&1 || true

echo "  → 使用轻量级Makefile编译..."
cp Makefile.lite Makefile
make -j$(nproc) > /tmp/enhanced_compile.log 2>&1

if [ $? -eq 0 ]; then
    echo -e "  ${GREEN}✓${NC} 编译成功（轻量级版本）"
    ls -lh afl-fuzz | awk '{print "    Binary size: " $5}'
else
    echo -e "  ${RED}✗${NC} 编译失败，查看日志: /tmp/enhanced_compile.log"
    tail -20 /tmp/enhanced_compile.log
    exit 1
fi

# 步骤5：对比二进制大小
echo -e "${YELLOW}[5/5]${NC} 对比二进制大小..."
CHATAFL_SIZE=$(stat -c%s "$CHATAFL_DIR/afl-fuzz" 2>/dev/null || echo "0")
ENHANCED_SIZE=$(stat -c%s "$ENHANCED_DIR/afl-fuzz" 2>/dev/null || echo "0")

echo "  ChatAFL:          $(numfmt --to=iec-i --suffix=B $CHATAFL_SIZE)"
echo "  Enhanced (lite):  $(numfmt --to=iec-i --suffix=B $ENHANCED_SIZE)"

SIZE_DIFF=$(( ENHANCED_SIZE - CHATAFL_SIZE ))
if [ $SIZE_DIFF -gt 100000 ]; then
    echo -e "  ${YELLOW}⚠${NC}  差异: +$(numfmt --to=iec-i --suffix=B $SIZE_DIFF) (仍偏大)"
else
    echo -e "  ${GREEN}✓${NC}  差异: +$(numfmt --to=iec-i --suffix=B $SIZE_DIFF) (合理范围)"
fi

echo ""
echo "========================================"
echo -e "${GREEN}修复完成！${NC}"
echo "========================================"
echo ""
echo "下一步："
echo "  1. 运行快速测试验证性能："
echo "     ./compare_fuzzers_docker.sh LightFTP FTP 60"
echo ""
echo "  2. 查看详细分析报告："
echo "     cat ENHANCED_PERFORMANCE_ANALYSIS.md"
echo ""
echo "  3. 如果性能恢复，开始集成State-Aware Scheduler"
echo ""

# 创建验证脚本
cat > "$SCRIPT_DIR/verify_fix.sh" << 'EOF'
#!/bin/bash
# 快速验证修复效果

echo "运行快速验证测试（30秒）..."
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master

# 运行短时间测试
./compare_fuzzers_docker.sh LightFTP FTP 0.5

# 检查结果
RESULT_DIR=$(ls -t comparison_results/ | head -1)
echo ""
echo "========== 验证结果 =========="

CHATAFL_PATHS=$(grep "paths_total" "comparison_results/$RESULT_DIR/chatafl/fuzzer_stats" | awk '{print $NF}')
ENHANCED_PATHS=$(grep "paths_total" "comparison_results/$RESULT_DIR/chatafl-enhanced/fuzzer_stats" | awk '{print $NF}')

echo "ChatAFL paths: $CHATAFL_PATHS"
echo "Enhanced paths: $ENHANCED_PATHS"

if [ "$ENHANCED_PATHS" -ge "$(echo "$CHATAFL_PATHS * 0.95" | bc | cut -d. -f1)" ]; then
    echo "✓ 修复成功：Enhanced性能已恢复到ChatAFL的95%以上"
    exit 0
else
    echo "✗ 修复不完整：Enhanced仍低于ChatAFL的95%"
    exit 1
fi
EOF

chmod +x "$SCRIPT_DIR/verify_fix.sh"
echo "  ✓ 已创建验证脚本: ./verify_fix.sh"
