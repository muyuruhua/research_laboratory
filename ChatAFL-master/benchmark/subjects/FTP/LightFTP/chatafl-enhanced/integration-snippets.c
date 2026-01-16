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

