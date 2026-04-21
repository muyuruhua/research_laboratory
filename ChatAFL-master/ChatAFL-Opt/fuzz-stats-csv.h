#ifndef __FUZZ_STATS_CSV_H
#define __FUZZ_STATS_CSV_H

#include <stdio.h>
#include "types.h"

typedef struct {
  FILE *timeline;
  char timeline_path[4096];
  char summary_path[4096];
} fuzz_stats_csv_writer_t;

int fuzz_stats_csv_init(fuzz_stats_csv_writer_t *writer, const char *out_dir);
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
                           u32 o8_probe_period);
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
                                  u64 o8_noncompliance_reports);
void fuzz_stats_csv_close(fuzz_stats_csv_writer_t *writer);

#endif
