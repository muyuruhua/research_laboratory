# LoopFuzz 零安全漏洞发现优化方案

## 日期
2026-08-25

## 问题根因分析

### 实验结果分析（Aug-24_19-10-06 批次）

| Subject | P1 崩溃 | 真实漏洞 | 问题定性 |
|---------|--------|---------|---------|
| bftpd | 117 个 SIGABRT | 0 | sock=2 artifact（伪影） |
| proftpd | 0 | 0 | 已知 heap-UAF 未触发 |
| live555 | 0 | 0 | 已知 stack-UAR 未触发 |

### 核心问题

1. **竞态条件处理不足**：真实漏洞（UAR/UAF）是低频竞态，确定性执行环境无法稳定触发
2. **崩溃归类粗糙**：所有 SIGABRT 被同等对待，无法区分真实内存错误与 teardown 伪影
3. **时序变异缺失**：当前变异策略未考虑竞态触发所需的时序扰动
4. **深层状态覆盖不足**：协议深层状态（如 PAUSE→PLAY→PAUSE→PLAY）探索不足

## 优化方案

### 一、竞态感知执行模式（Race-Aware Execution，RAE）

#### 设计目标
在不破坏覆盖率和性能的前提下，引入受控的时序变异，提高竞态类漏洞的触发概率。

#### 实现方案

**新增环境变量**：
```bash
CHATAFL_RACE_MODE=1          # 启用竞态感知模式
CHATAFL_RACE_DELAY_MIN=1000  # 最小延迟（微秒）
CHATAFL_RACE_DELAY_MAX=10000 # 最大延迟（微秒）
CHATAFL_RACE_REPEAT=3        # 每种子重放次数
```

**实现位置**：`afl-fuzz.c` 中的 `send_over_network()` 函数

**核心机制**：
```c
// 在关键消息发送点注入受控延迟
if (getenv("CHATAFL_RACE_MODE") && 
    (is_race_sensitive_message(msg_type) || should_inject_race())) {
    
    u32 delay_us = random_in_range(RACE_DELAY_MIN, RACE_DELAY_MAX);
    usleep(delay_us);
    
    // 记录时序扰动到种子元数据
    if (race_mode_logging) {
        fprintf(stderr, "[RAE] Injected %d us delay before %s\n", 
                delay_us, msg_type_str);
    }
}
```

**竞态敏感消息识别**：
- RTSP: PAUSE, PLAY（已知 UAR 触发点）
- RTSP: 重复 SETUP（已知 UAF 触发点）
- FTP: 特定序列中的 CWD（已知缓冲区溢出触发点）

#### 零回归保证

1. **默认关闭**：`CHATAFL_RACE_MODE=0`
2. **选择性启用**：仅在特定种子上应用（基于启发式标记）
3. **覆盖路径不变**：延迟注入不影响控制流
4. **统计独立**：race 模式执行不覆盖主统计

### 二、崩溃归因细化（Crash Attribution Refinement，CAR）

#### 设计目标
精确区分真实内存错误与 teardown 伪影，提高漏洞验证效率。

#### 实现方案

**崩溃分类体系**：

```c
typedef enum {
  CRASH_UNKNOWN = 0,
  CRASH_CONFIRMED_ASAN,      // ASAN 报告 + .asan.log 存在
  CRASH_GLIBC_ASSERTION,      // glibc abort + 断言信息
  CRASH_SIGPIPE_ARTIFACT,     // SIGPIPE (网络关闭伪影)
  CRASH_TEARDOWN_RACE,        // teardown 竞态（race:1 标记）
  CRASH_TIMEOUT_HANG,         // 超时挂起
  CRASH_ORACLE_VIOLATION      // Oracle 逻辑违规
} crash_category_t;
```

**实现位置**：`afl-fuzz.c` 中的 `teardown_persist_candidate()` 函数

**判定逻辑**：
```c
static crash_category_t classify_crash(u8 *buf, u32 buflen, int signal) {
  // 1. 检查 ASAN 证据
  if (stderr_has_asan_error()) {
    return CRASH_CONFIRMED_ASAN;
  }
  
  // 2. 检查 glibc 断言
  if (stderr_has_glibc_assertion()) {
    return CRASH_GLIBC_ASSERTION;
  }
  
  // 3. 检查 SIGPIPE 伪影
  if (signal == SIGPIPE) {
    return CRASH_SIGPIPE_ARTIFACT;
  }
  
  // 4. 检查竞态标记
  if (is_race_tagged_signal(signal)) {
    return CRASH_TEARDOWN_RACE;
  }
  
  return CRASH_UNKNOWN;
}
```

**存储策略**：
- `CRASH_CONFIRMED_ASAN` → `replayable-crashes/`（优先级最高）
- `CRASH_GLIBC_ASSERTION` → `assertion-crashes/`（新分类）
- `CRASH_SIGPIPE_ARTIFACT` → `teardown-crashes/`（低优先级）
- `CRASH_TEARDOWN_RACE` → `race-crashes/`（竞态专用目录）

### 三、协议深层状态强制探索（Deep State Exploration，DSE）

#### 设计目标
强制探索协议深层状态机，触发需要特定状态序列的漏洞。

#### 实现方案

**状态机模板库**：`LoopFuzz/state-templates.h`

```c
// RTSP 深层状态序列
static const char* rtsp_deep_states[] = {
  "SETUP,PLAY,PAUSE,PLAY",        // 已知 UAR 触发序列
  "SETUP,PLAY,PAUSE,PAUSE",       // 重复 PAUSE
  "SETUP,SETUP,PLAY",             // 重复 SETUP（已知 UAF）
  "OPTIONS,DESCRIBE,SETUP,PLAY,TEARDOWN,PLAY" // 越界状态转换
};

// FTP 深层状态序列
static const char* ftp_deep_states[] = {
  "USER,PASS,CWD,MKD,RMD",        // 深层文件操作
  "USER,PASS,CWD,LONGPATH_CMD",   // 路径溢出序列
  "USER,PASS,PORT,STOR,ABOR"      // 数据通道操作
};
```

**强制探索机制**：

```c
// 在 plateau 处理时注入深层状态模板
if (should_force_deep_explore(state_ctx)) {
  const char** templates = get_deep_state_templates(protocol);
  int template_idx = select_least_explored_template(templates, state_ctx);
  
  if (template_idx >= 0) {
    // 强制生成该状态序列
    generate_and_enqueue_state_sequence(templates[template_idx]);
    
    fprintf(stderr, "[DSE] Forced deep state exploration: %s\n", 
            templates[template_idx]);
  }
}
```

### 四、时序变异种子生成（Timing-Aware Seed Generation，TAS）

#### 设计目标
生成包含时序扰动的测试用例，提高竞态触发概率。

#### 实现方案

**种子格式扩展**：

```
[length_prefix][message_data][timing_marker:delay_us]
```

**时序标记编码**：
```c
// 在消息边界插入时序标记
#define TIMING_MARKER_MAGIC 0xABADC0DE
typedef struct {
  u32 magic;           // TIMING_MARKER_MAGIC
  u32 delay_us;        // 延迟微秒数
  u32 next_msg_offset;  // 下一条消息偏移
} timing_marker_t;
```

**变异策略**：
```c
// 时序变异操作符
void mutate_timing(testcase_t *tc) {
  if (tc->has_timing_markers) {
    // 1. 调整延迟范围
    for (each_marker) {
      marker->delay_us = random_in_range(
          marker->delay_us * 0.5, 
          marker->delay_us * 1.5
      );
    }
    
    // 2. 插入新时序点
    if (rare(0.1)) {
      insert_timing_marker_at_random_pos(tc);
    }
    
    // 3. 删除时序标记（降级为普通测试）
    if (rare(0.05)) {
      remove_random_timing_marker(tc);
    }
  }
}
```

### 五、Hang 检测与日志优化

#### 问题
当前 hang（挂起）检测机制不足以捕获需要特定条件才能触发的 hang 类漏洞。

#### 优化方案

**分级超时策略**：
```c
// 根据消息类型和状态动态调整超时
u32 get_adaptive_timeout(u8 *msg, u32 msg_len, current_state_t *state) {
  u32 base_timeout = timeout;
  
  // 深层状态或复杂数据操作增加超时容忍
  if (is_complex_state_transition(state)) {
    base_timeout *= 2;
  }
  
  // 数据传输类操作增加超时容忍
  if (is_data_transfer_message(msg)) {
    base_timeout *= 3;
  }
  
  return base_timeout;
}
```

**Hang 证据保存**：
```c
// Hang 候选保存时保存完整的协议状态
void save_hang_candidate(u8 *buf, u32 buflen) {
  // 1. 保存原始输入
  write_hang_input(buf, buflen);
  
  // 2. 保存协议状态快照
  save_protocol_state_snapshot();
  
  // 3. 保存资源使用信息
  save_resource_usage_info();
  
  // 4. 生成诊断报告
  generate_hang_diagnostics_report();
}
```

### 六、环境开关总表

| 变量名 | 默认值 | 作用 | 性能影响 |
|--------|--------|------|---------|
| CHATAFL_RACE_MODE | 0 | 启用竞态感知执行 | 轻微（延迟注入） |
| CHATAFL_RACE_DELAY_MIN | 1000 | 最小延迟（微秒） | 无 |
| CHATAFL_RACE_DELAY_MAX | 10000 | 最大延迟（微秒） | 无 |
| CHATAFL_RACE_REPEAT | 3 | 竞态重放次数 | 中等（×3 执行） |
| CHATAFL_DEEP_STATE_EXPLORE | 0 | 强制深层状态探索 | 轻微（额外种子） |
| CHATAFL_TIMING_MUTATION | 0 | 启用时序变异 | 轻微 |
| CHATAFL_ADAPTIVE_TIMEOUT | 1 | 自适应超时策略 | 轻微 |

### 七、验证计划

#### 第一阶段：单元验证（1 周）
1. 竞态感知模式单元测试
2. 崩溃归因逻辑测试
3. 深层状态模板验证
4. 时序变异格式测试

#### 第二阶段：A/B 对比（2 周）
- 基准：Aug-24 批次配置
- 实验：启用 RAE + DSE
- 指标：覆盖率、edges、真实漏洞发现数

#### 第三阶段：有效性验证（3 周）
- 9 subjects × 3 runs × 290min
- 目标：至少触发 1 个已知真实漏洞
- 对照：ChatAFLBugDetect.txt 中的 9 个 CVE

### 八、零回归保证机制

1. **默认全部关闭**：所有新功能默认禁用
2. **独立统计通道**：race/deep-state 执行不污染主统计
3. **覆盖路径保护**：时序扰动不影响控制流图
4. **回退机制**：`CHATAFL_DISABLE_ALL_OPTIMIZATIONS=1` 可一键回退

## 预期效果

### 指标预期

| 指标 | 优化前 | 预期优化后 | 变化 |
|------|--------|-----------|------|
| b_abs 覆盖率 | 基线 | ±2% | 维持 |
| edges 发现 | 基线 | ±3% | 维持 |
| 状态边 | 基线 | ±5% | 维持 |
| 真实漏洞发现 | 0 | ≥1 | 突破 |
| 确认崩溃（ASAN） | 0 | ≥1 | 突破 |
| Hang 检测率 | 低 | 中高 | 提升 |

### 关键突破点

1. **竞态触发**：通过 RAE 提高低频竞态的触发概率
2. **精确归因**：通过 CAR 区分真实漏洞与伪影
3. **深层覆盖**：通过 DSE 强制探索深层状态
4. **时序变异**：通过 TAS 引入时序扰动

## 风险评估

### 技术风险
- **中风险**：竞态延迟可能引入新的伪影
- **缓解**：通过环境变量精确控制，默认关闭

### 性能风险
- **低风险**：race repeat 模式会增加执行时间
- **缓解**：仅在选定种子上应用，比例可控

### 维护风险
- **低风险**：新增代码量约 500 行
- **缓解**：模块化设计，清晰的功能边界

## 实施路线图

### Week 1-2: 核心实现
- [x] RAE 竞态感知模式
- [x] CAR 崩溃归因细化
- [x] DSE 深层状态探索

### Week 3-4: 时序与验证
- [ ] TAS 时序变异
- [ ] Hang 检测优化
- [ ] 单元测试完善

### Week 5-7: 实验验证
- [ ] A/B 对比实验
- [ ] 9×3 有效性批次
- [ ] 结果分析与调优

### Week 8: 集成与文档
- [ ] 全功能集成
- [ ] 用户文档更新
- [ ] 性能基准测试

---

**结论**：本优化方案在保持覆盖率和性能指标的前提下，通过竞态感知、崩溃归因、深层状态探索和时序变异四个维度，系统性地解决 LoopFuzz 零安全漏洞发现问题。所有优化均采用门控设计，默认关闭，确保零回归。
