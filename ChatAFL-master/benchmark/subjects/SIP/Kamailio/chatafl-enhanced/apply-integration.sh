#!/bin/bash
# 文件: apply-integration.sh
# 描述: 自动集成verifier/cegar/state-scheduler到afl-fuzz.c
# 用法: ./apply-integration.sh

set -e

echo "[+] ChatAFL-Enhanced 集成脚本"
echo "[+] 将验证器/CEGAR/状态调度器集成到afl-fuzz.c"
echo ""

# 检查是否在正确目录
if [ ! -f "afl-fuzz.c" ]; then
    echo "[!] 错误: 请在ChatAFL-Enhanced目录下运行此脚本"
    exit 1
fi

# 备份原文件
if [ ! -f "afl-fuzz.c.original" ]; then
    echo "[+] 备份 afl-fuzz.c -> afl-fuzz.c.original"
    cp afl-fuzz.c afl-fuzz.c.original
fi

echo "[+] 应用集成补丁..."

# ============================================
# 步骤1: 添加头文件引用（在line 45之后）
# ============================================
grep -q "verifier.h" afl-fuzz.c || {
    echo "[+] 添加头文件引用..."
    sed -i '/^#include "chat-llm.h"$/a\
#include "verifier.h"\
#include "cegar.h"\
#include "state-scheduler.h"\
#include "protocol-spec.h"' afl-fuzz.c
}

# ============================================
# 步骤2: 添加全局变量声明（在全局变量区）
# ============================================
grep -q "g_protocol_spec" afl-fuzz.c || {
    echo "[+] 添加全局变量..."
    # 在 "static u8 *in_dir" 附近添加
    sed -i '/^static u8 \*in_dir,/a\
\
/* ChatAFL-Enhanced 全局变量 */\
static ProtocolSpec g_protocol_spec;       // 协议规范\
static char g_current_state[256] = "";     // 当前状态\
static int g_verifier_rejects = 0;         // 验证器拒绝计数\
static int g_cegar_refinements = 0;        // CEGAR修正计数\
static int g_new_states_discovered = 0;    // 新状态发现数' afl-fuzz.c
}

# ============================================
# 步骤3: 初始化协议规范函数
# ============================================
grep -q "setup_protocol_spec" afl-fuzz.c || {
    echo "[+] 添加协议规范初始化函数..."
    # 在 setup_shm() 函数之前添加
    sed -i '/^static void setup_shm/i\
/* 初始化协议规范 */\
static void setup_protocol_spec(void) {\
  const char* proto_name = getenv("FUZZER_PROTOCOL");\
  if (!proto_name) proto_name = "FTP";\
  \
  strncpy(g_protocol_spec.name, proto_name, sizeof(g_protocol_spec.name) - 1);\
  g_protocol_spec.default_port = 21;\
  strcpy(g_protocol_spec.mandatory_fields[0], "command");\
  strcpy(g_protocol_spec.mandatory_fields[1], "args");\
  strcpy(g_protocol_spec.mandatory_fields[2], "");\
  g_protocol_spec.type = PROTO_TEXT;\
  \
  ACTF("Protocol spec initialized: %s", g_protocol_spec.name);\
}\
' afl-fuzz.c
}

# ============================================
# 步骤4: 在main()中调用初始化函数
# ============================================
grep -q "setup_protocol_spec()" afl-fuzz.c || {
    echo "[+] 在main()中添加初始化调用..."
    # 在 setup_shm() 调用之后添加
    sed -i '/setup_shm();/a\
  setup_protocol_spec();  /* ChatAFL-Enhanced: 初始化协议 */' afl-fuzz.c
}

# ============================================
# 步骤5: 在fuzz_one()中添加验证器检查
# ============================================
echo "[+] 修改 fuzz_one() 函数（这需要手动编辑）..."
echo ""
echo "请手动编辑 afl-fuzz.c 的 fuzz_one() 函数："
echo "1. 在执行测试用例前添加验证器检查"
echo "2. 在执行后添加状态追踪"
echo "3. 在失败时触发CEGAR"
echo ""
echo "参考代码片段已保存到: integration-snippets.c"

# 创建代码片段文件
cat > integration-snippets.c << 'EOF'
/*
 * 文件: integration-snippets.c
 * 描述: 需要手动添加到 afl-fuzz.c::fuzz_one() 的代码片段
 * 位置: 约在 line 7000-8000 的 fuzz_one() 函数内部
 */

// ===== 片段1: 验证器检查（在执行前添加） =====
// 位置: 在 write_to_testcase() 之后, common_fuzz_stuff() 之前

#ifdef USE_VERIFIER  // 添加编译条件
  if (g_protocol_spec.name[0] != '\0' && len > 0 && len < MAX_PAYLOAD_LEN) {
    u8 json_buf[MAX_PAYLOAD_LEN];
    memcpy(json_buf, out_buf, len);
    json_buf[len] = '\0';
    
    if (!verify_json_grammar((char*)json_buf, &g_protocol_spec)) {
      g_verifier_rejects++;
      
      if (!(stage_cur % 100)) {  // 每100次打印一次
        ACTF("Verifier reject: %s", verifier_reason_str(get_last_verifier_reason()));
      }
      
      goto abandon_entry;  // 跳过无效测试用例
    }
  }
#endif

// ===== 片段2: 状态追踪（在执行后添加） =====
// 位置: 在 common_fuzz_stuff() 之后

#ifdef USE_STATE_TRACKING
  // 从aflnet获取响应码（需要确认aflnet.c中的全局变量名）
  extern int aflnet_response_code;
  extern char aflnet_response_buf[];
  
  if (aflnet_response_code > 0) {
    char state_hash[256];
    snprintf(state_hash, sizeof(state_hash), "S_%d", aflnet_response_code);
    
    int prev_count = get_state_count(state_hash);
    increment_state_count(state_hash);
    
    if (prev_count == 0) {
      g_new_states_discovered++;
      ACTF("New state: %s (total: %d)", state_hash, g_new_states_discovered);
      
      // 保存到corpus
      if (len > 0 && len < MAX_PAYLOAD_LEN) {
        char edge_info[512];
        snprintf(edge_info, sizeof(edge_info), "%s -> %s", 
                 g_current_state, state_hash);
        save_to_corpus((char*)out_buf, edge_info);
      }
    }
    
    strncpy(g_current_state, state_hash, sizeof(g_current_state) - 1);
  }
#endif

// ===== 片段3: CEGAR修正（在检测到失败响应时） =====
// 位置: 在状态追踪之后

#ifdef USE_CEGAR
  if (aflnet_response_code >= 400 && len > 0 && len < MAX_PAYLOAD_LEN) {
    if (is_rejection_response(aflnet_response_code, aflnet_response_buf, 
                              g_protocol_spec.name)) {
      RealResponse failure;
      failure.status_code = aflnet_response_code;
      strncpy(failure.body, aflnet_response_buf, sizeof(failure.body) - 1);
      
      u8 json_buf[MAX_PAYLOAD_LEN];
      memcpy(json_buf, out_buf, len);
      json_buf[len] = '\0';
      
      char* refined = refine_hypothesis_with_cegar((char*)json_buf, 
                                                   &failure, 
                                                   &g_protocol_spec);
      if (refined) {
        g_cegar_refinements++;
        
        if (!(g_cegar_refinements % 10)) {
          ACTF("CEGAR refinements: %d", g_cegar_refinements);
        }
        
        // 将修正后的测试用例写入队列
        s32 refined_len = strlen(refined);
        s32 fd = open(alloc_printf("%s/.state/auto_extra/cegar_%06d", 
                                    out_dir, g_cegar_refinements), 
                      O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) {
          ck_write(fd, refined, refined_len, "cegar");
          close(fd);
        }
        
        free(refined);
      }
    }
  }
#endif

EOF

echo "[+] 集成代码片段已生成: integration-snippets.c"
echo ""
echo "[+] 编译选项说明："
echo "    make CFLAGS=\"-DUSE_VERIFIER -DUSE_STATE_TRACKING -DUSE_CEGAR\""
echo ""
echo "[+] 下一步："
echo "    1. 手动将 integration-snippets.c 中的代码添加到 afl-fuzz.c::fuzz_one()"
echo "    2. 或者使用简化版本（见下方）"
echo ""
echo "[!] 简化建议: 先只启用验证器（最小改动）"
echo "    只需在 fuzz_one() 开头添加片段1即可"

exit 0
