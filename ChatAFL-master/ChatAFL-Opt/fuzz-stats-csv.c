#include "fuzz-stats-csv.h"

#include <string.h>

int fuzz_stats_csv_init(fuzz_stats_csv_writer_t *writer, const char *out_dir) {
  if (!writer || !out_dir) return -1;

  memset(writer, 0, sizeof(*writer));
  snprintf(writer->timeline_path, sizeof(writer->timeline_path),
           "%s/fuzz_stats_timeline.csv", out_dir);
  snprintf(writer->summary_path, sizeof(writer->summary_path),
           "%s/run_summary_live.csv", out_dir);

  writer->timeline = fopen(writer->timeline_path, "w");
  if (!writer->timeline) return -1;

  fprintf(writer->timeline,
          "unix_time,runtime_min,execs_done,paths_total,unique_crashes,nodes,edges,execs_per_sec,bitmap_cvg,mqtt_diff_avg,mqtt_diff_last,mqtt_o8_outliers,mqtt_o8_probe_period\n");
  fflush(writer->timeline);
  return 0;
}

void fuzz_stats_csv_append(fuzz_stats_csv_writer_t *writer,
                           u64 unix_time,
                           u64 start_time_ms,
                           u64 total_execs,
                           u32 queued_paths,
                           u64 unique_crashes,
                           u32 nodes,
                           u32 edges,
                           double execs_per_sec,
                           double bitmap_cvg,
                           double mqtt_diff_avg,
                           double mqtt_diff_last,
                           u64 o8_outliers,
                           u32 o8_probe_period) {
  double runtime_min;

  if (!writer || !writer->timeline) return;

  runtime_min = 0.0;
  if (unix_time * 1000ULL > start_time_ms)
    runtime_min = ((double)(unix_time * 1000ULL - start_time_ms)) / 60000.0;

  fprintf(writer->timeline,
          "%llu,%.2f,%llu,%u,%llu,%u,%u,%.2f,%.4f,%.6f,%.6f,%llu,%u\n",
          (unsigned long long)unix_time,
          runtime_min,
          (unsigned long long)total_execs,
          queued_paths,
          (unsigned long long)unique_crashes,
          nodes,
          edges,
          execs_per_sec,
          bitmap_cvg,
          mqtt_diff_avg,
          mqtt_diff_last,
          (unsigned long long)o8_outliers,
          o8_probe_period);
  fflush(writer->timeline);
}

void fuzz_stats_csv_write_summary(fuzz_stats_csv_writer_t *writer,
                                  const char *subject,
                                  const char *fuzzer_name,
                                  u64 start_time_ms,
                                  u64 last_update_ms,
                                  u32 run_id,
                                  u64 total_execs,
                                  u32 queued_paths,
                                  u64 unique_crashes,
                                  u32 nodes,
                                  u32 edges,
                                  double bitmap_cvg,
                                  double execs_per_sec,
                                  double mqtt_diff_avg,
                                  u64 o8_noncompliance_reports) {
  FILE *summary;
  double runtime_min = 0.0;
  const char *safe_subject = subject ? subject : "unknown";
  const char *safe_fuzzer = fuzzer_name ? fuzzer_name : "afl";

  if (!writer || !writer->summary_path[0]) return;

  if (last_update_ms > start_time_ms)
    runtime_min = ((double)(last_update_ms - start_time_ms)) / 60000.0;

  summary = fopen(writer->summary_path, "w");
  if (!summary) return;

  fprintf(summary,
          "subject,fuzzer,run,runtime_min,execs_done,paths_total,unique_crashes,nodes,edges,bitmap_cvg,execs_per_sec,mqtt_diff_avg,mqtt_o8_noncompliance\n");
  fprintf(summary,
          "%s,%s,%u,%.2f,%llu,%u,%llu,%u,%u,%.4f,%.2f,%.6f,%llu\n",
          safe_subject,
          safe_fuzzer,
          run_id,
          runtime_min,
          (unsigned long long)total_execs,
          queued_paths,
          (unsigned long long)unique_crashes,
          nodes,
          edges,
          bitmap_cvg,
          execs_per_sec,
          mqtt_diff_avg,
          (unsigned long long)o8_noncompliance_reports);
  fclose(summary);
}

void fuzz_stats_csv_close(fuzz_stats_csv_writer_t *writer) {
  if (!writer) return;
  if (writer->timeline) {
    fclose(writer->timeline);
    writer->timeline = NULL;
  }
}
