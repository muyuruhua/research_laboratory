/*
 * llm-cost-tracker.c - LLM成本统计模块实现
 */

#include "llm-cost-tracker.h"
#include "alloc-inl.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

/* 全局成本报告 */
static LLMCostReport g_cost_report = {0};

void llm_cost_init(float cost_per_1k) {
  memset(&g_cost_report, 0, sizeof(LLMCostReport));
  g_cost_report.cost_per_1k_tokens = cost_per_1k;
  g_cost_report.start_time = time(NULL);
}

void llm_cost_record(const char* call_type, 
                     uint32_t prompt_tokens,
                     uint32_t response_tokens,
                     bool is_cached) {
  if (is_cached) {
    g_cost_report.cached_hits++;
    return;  /* 缓存命中不计费 */
  }
  
  g_cost_report.total_calls++;
  g_cost_report.total_prompt_tokens += prompt_tokens;
  g_cost_report.total_response_tokens += response_tokens;
  g_cost_report.total_tokens += (prompt_tokens + response_tokens);
  
  /* 分类统计 */
  if (call_type && strcmp(call_type, "grammar") == 0) {
    g_cost_report.grammar_gen_calls++;
  } else if (call_type && strcmp(call_type, "cegar") == 0) {
    g_cost_report.cegar_calls++;
  } else if (call_type && strcmp(call_type, "plateau") == 0) {
    g_cost_report.plateau_calls++;
  }
  
  /* 更新成本估算 */
  g_cost_report.estimated_cost_usd = 
    (g_cost_report.total_tokens / 1000.0f) * g_cost_report.cost_per_1k_tokens;
  
  g_cost_report.last_update_time = time(NULL);
}

const LLMCostReport* llm_cost_get_report() {
  return &g_cost_report;
}

void llm_cost_export(const char* out_dir) {
  if (!out_dir) return;
  
  char path[512];
  snprintf(path, sizeof(path), "%s/llm-cost-report.txt", out_dir);
  
  FILE *f = fopen(path, "w");
  if (!f) return;
  
  uint64_t runtime = time(NULL) - g_cost_report.start_time;
  
  fprintf(f, "=== LLM Cost Report ===\n\n");
  fprintf(f, "Runtime: %llu seconds (%.2f hours)\n", 
          (unsigned long long)runtime, runtime / 3600.0);
  fprintf(f, "Total LLM calls: %llu\n", (unsigned long long)g_cost_report.total_calls);
  fprintf(f, "Cached hits: %llu (%.1f%%)\n", 
          (unsigned long long)g_cost_report.cached_hits,
          g_cost_report.total_calls > 0 ? 
            100.0 * g_cost_report.cached_hits / (g_cost_report.total_calls + g_cost_report.cached_hits) : 0.0);
  fprintf(f, "\n");
  
  fprintf(f, "Call breakdown:\n");
  fprintf(f, "  Grammar generation: %llu\n", (unsigned long long)g_cost_report.grammar_gen_calls);
  fprintf(f, "  CEGAR refinement: %llu\n", (unsigned long long)g_cost_report.cegar_calls);
  fprintf(f, "  Plateau breakthrough: %llu\n", (unsigned long long)g_cost_report.plateau_calls);
  fprintf(f, "\n");
  
  fprintf(f, "Token usage:\n");
  fprintf(f, "  Prompt tokens: %llu\n", (unsigned long long)g_cost_report.total_prompt_tokens);
  fprintf(f, "  Response tokens: %llu\n", (unsigned long long)g_cost_report.total_response_tokens);
  fprintf(f, "  Total tokens: %llu\n", (unsigned long long)g_cost_report.total_tokens);
  fprintf(f, "\n");
  
  fprintf(f, "Cost estimate:\n");
  fprintf(f, "  Rate: $%.4f per 1K tokens\n", g_cost_report.cost_per_1k_tokens);
  fprintf(f, "  Total cost: $%.4f USD\n", g_cost_report.estimated_cost_usd);
  fprintf(f, "  Cost per hour: $%.4f USD/hr\n", 
          runtime > 0 ? g_cost_report.estimated_cost_usd / (runtime / 3600.0) : 0.0);
  
  fclose(f);
}

bool llm_cost_exceeds_budget(float budget_usd) {
  return g_cost_report.estimated_cost_usd > budget_usd;
}

void llm_cost_reset() {
  float cost_per_1k = g_cost_report.cost_per_1k_tokens;
  memset(&g_cost_report, 0, sizeof(LLMCostReport));
  g_cost_report.cost_per_1k_tokens = cost_per_1k;
  g_cost_report.start_time = time(NULL);
}
