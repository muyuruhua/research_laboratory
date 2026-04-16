/*
  Copyright 2013 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - fuzzer code
   --------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

*/

#define AFL_MAIN
#include "android-ashmem.h"
#define MESSAGES_TO_STDOUT

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define _FILE_OFFSET_BITS 64

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"
#include "chat-llm.h"
#include "grammar-hypothesis.h"
#include "hypothesis-adapter.h"
#include "mqtt-builder.h"
#include "mqtt-generate.h"
#include "mqtt-scheduler.h"
#include "mp-driver.h"
#include "mqtt-differential.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>    /* strcasecmp */
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>
#include <termios.h>
#include <dlfcn.h>
#include <sched.h>

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/capability.h>
#include <netdb.h>
#include <netinet/tcp.h>   /* A3: TCP_NODELAY */
#include <pthread.h>

#include "aflnet.h"
#include <graphviz/gvc.h>
#include <math.h>

#include "chat-llm.h"

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#include <sys/sysctl.h>
#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

/* For systems that have sched_setaffinity; right now just Linux, but one
   can hope... */

#ifdef __linux__
#define HAVE_AFFINITY 1
#endif /* __linux__ */

/* A toggle to export some variables when building as a library. Not very
   useful for the general public. */

#ifdef AFL_LIB
#define EXP_ST
#else
#define EXP_ST static
#endif /* ^AFL_LIB */

/* Lots of globals, but mostly for the status UI and other things where it
   really makes no sense to haul them around as function parameters. */

EXP_ST u8 *in_dir, /* Input directory with test cases  */
    *out_file,     /* File to fuzz, if any             */
    *out_dir,      /* Working & output directory       */
    *sync_dir,     /* Synchronization directory        */
    *sync_id,      /* Fuzzer ID                        */
    *use_banner,   /* Display banner                   */
    *in_bitmap,    /* Input bitmap                     */
    *doc_path,     /* Path to documentation dir        */
    *target_path,  /* Path to target binary            */
    *orig_cmdline; /* Original command line            */

EXP_ST u32 exec_tmout = EXEC_TIMEOUT; /* Configurable exec timeout (ms)   */
static u32 hang_tmout = EXEC_TIMEOUT; /* Timeout used for hang det (ms)   */

EXP_ST u64 mem_limit = MEM_LIMIT; /* Memory cap for child (MB)        */

static u32 stats_update_freq = 1; /* Stats update frequency (execs)   */

EXP_ST u8 skip_deterministic, /* Skip deterministic stages?       */
    force_deterministic,      /* Force deterministic stages?      */
    use_splicing,             /* Recombine input files?           */
    dumb_mode,                /* Run in non-instrumented mode?    */
    score_changed,            /* Scoring for favorites changed?   */
    kill_signal,              /* Signal that killed the child     */
    resuming_fuzz,            /* Resuming an older fuzzing job?   */
    timeout_given,            /* Specific timeout given?          */
    not_on_tty,               /* stdout is not a tty              */
    term_too_small,           /* terminal dimensions too small    */
    uses_asan,                /* Target uses ASAN?                */
    no_forkserver,            /* Disable forkserver?              */
    crash_mode,               /* Crash mode! Yeah!                */
    in_place_resume,          /* Attempt in-place resume?         */
    auto_changed,             /* Auto-generated tokens changed?   */
    no_cpu_meter_red,         /* Feng shui on the status screen   */
    no_arith,                 /* Skip most arithmetic ops         */
    shuffle_queue,            /* Shuffle input queue?             */
    bitmap_changed = 1,       /* Time to update bitmap?           */
    qemu_mode,                /* Running in QEMU mode?            */
    skip_requested,           /* Skip request, via SIGUSR1        */
    run_over10m,              /* Run time over 10 minutes?        */
    persistent_mode,          /* Running in persistent mode?      */
    deferred_mode,            /* Deferred forkserver mode?        */
    fast_cal;                 /* Try to calibrate faster?         */

static s32 out_fd,       /* Persistent fd for out_file       */
    dev_urandom_fd = -1, /* Persistent fd for /dev/urandom   */
    dev_null_fd = -1,    /* Persistent fd for /dev/null      */
    fsrv_ctl_fd,         /* Fork server control pipe (write) */
    fsrv_st_fd;          /* Fork server status pipe (read)   */

static s32 forksrv_pid, /* PID of the fork server           */
    child_pid = -1,     /* PID of the fuzzed program        */
    out_dir_fd = -1;    /* FD of the lock file              */

EXP_ST u8 *trace_bits; /* SHM with instrumentation bitmap  */

EXP_ST u8 virgin_bits[MAP_SIZE], /* Regions yet untouched by fuzzing */
    virgin_tmout[MAP_SIZE],      /* Bits we haven't seen in tmouts   */
    virgin_crash[MAP_SIZE];      /* Bits we haven't seen in crashes  */

static u8 var_bytes[MAP_SIZE]; /* Bytes that appear to be variable */

static s32 shm_id; /* ID of the SHM region             */

static volatile u8 stop_soon, /* Ctrl-C pressed?                  */
    clear_screen = 1,         /* Window resized?                  */
    child_timed_out;          /* Traced process timed out?        */

EXP_ST u32 queued_paths, /* Total number of queued testcases */
    queued_variable,     /* Testcases with variable behavior */
    queued_at_start,     /* Total number of initial inputs   */
    queued_discovered,   /* Items discovered during this run */
    queued_imported,     /* Items imported via -S            */
    queued_favored,      /* Paths deemed favorable           */
    queued_with_cov,     /* Paths with new coverage bytes    */
    pending_not_fuzzed,  /* Queued but not done yet          */
    pending_favored,     /* Pending favored paths            */
    cur_skipped_paths,   /* Abandoned inputs in cur cycle    */
    cur_depth,           /* Current path depth               */
    max_depth,           /* Max path depth                   */
    useless_at_start,    /* Number of useless starting paths */
    var_byte_count,      /* Bitmap bytes with var behavior   */
    current_entry,       /* Current queue entry ID           */
    havoc_div = 1;       /* Cycle count divisor for havoc    */

EXP_ST u64 total_crashes, /* Total number of crashes          */
    unique_crashes,       /* Crashes with unique signatures   */
    total_tmouts,         /* Total number of timeouts         */
    unique_tmouts,        /* Timeouts with unique signatures  */
    unique_hangs,         /* Hangs with unique signatures     */
    total_execs,          /* Total execve() calls             */
    slowest_exec_ms,      /* Slowest testcase non hang in ms  */
    start_time,           /* Unix start time (ms)             */
    last_path_time,       /* Time for most recent path (ms)   */
    last_crash_time,      /* Time for most recent crash (ms)  */
    last_hang_time,       /* Time for most recent hang (ms)   */
    last_crash_execs,     /* Exec counter at last crash       */
    queue_cycle,          /* Queue round counter              */
    cycles_wo_finds,      /* Cycles without any new paths     */
    trim_execs,           /* Execs done to trim input files   */
    bytes_trim_in,        /* Bytes coming into the trimmer    */
    bytes_trim_out,       /* Bytes coming outa the trimmer    */
    blocks_eff_total,     /* Blocks subject to effector maps  */
    blocks_eff_select;    /* Blocks selected as fuzzable      */

static u32 subseq_tmouts; /* Number of timeouts in a row      */

static u32 forced_kills;  /* Fix-14c: send_over_network() SIGKILL escalations */

static u32 mp_multi_ok,          /* multi-fd path completed successfully     */
           mp_multi_fallback,    /* open_connections failed → single-fd      */
           mp_multi_hshake_fail; /* handshake failed → cleanup & MP_MULTI_DONE */

static u8 *stage_name = "init", /* Name of the current fuzz stage   */
    *stage_short,               /* Short stage name                 */
    *syncing_party;             /* Currently syncing with...        */

static s32 stage_cur, stage_max; /* Stage progression                */
static s32 splicing_with = -1;   /* Splicing with which test case?   */

static u32 master_id, master_max; /* Master instance job splitting    */

static u32 syncing_case; /* Syncing with case #...           */

static s32 stage_cur_byte, /* Byte offset of current stage op  */
    stage_cur_val;         /* Value used for stage op          */

static u8 stage_val_type; /* Value type (STAGE_VAL_*)         */

static u64 stage_finds[32], /* Patterns found per fuzz stage    */
    stage_cycles[32];       /* Execs per fuzz stage             */

static u32 rand_cnt; /* Random number counter            */

static u64 total_cal_us, /* Total calibration time (us)      */
    total_cal_cycles;    /* Total calibration cycles         */

static u64 total_bitmap_size, /* Total bit count for all bitmaps  */
    total_bitmap_entries;     /* Number of bitmaps counted        */

static s32 cpu_core_count; /* CPU core count                   */

#ifdef HAVE_AFFINITY

static s32 cpu_aff = -1; /* Selected CPU core                */

#endif /* HAVE_AFFINITY */

static FILE *plot_file; /* Gnuplot output file              */

/* ============================================
 * ChatAFL-Opt: Grammar Hypothesis Globals
 * ============================================ */
static hypothesis_context_t *hypothesis_ctx = NULL;  /* Global hypothesis context */
static u8 hypothesis_mode = 0;                        /* Enable hypothesis-driven mode */
static u32 hypothesis_validation_count = 0;          /* Validation counter */

/* Fix-15: Two-tier hypothesis validation.
 *
 * Tier-1 (sampled validation): runs inside common_fuzz_stuff() every
 * HYPOTHESIS_VALIDATION_SAMPLE_RATE-th execution.  It RE-USES the
 * regions already parsed by extract_requests() — NO double-parse.
 * Cost: ~1 µs per sampled execution (constraint checks only).
 *
 * Tier-2 (periodic refinement): runs inside the plateau handler
 * every HYPOTHESIS_REFINEMENT_CHECK_INTERVAL validations.  If any
 * hypothesis has fitness < FITNESS_THRESHOLD and ≥3 counterexamples,
 * it issues ONE LLM refinement call.
 *
 * Performance budget at exec_speed ≈ 25 K/s:
 *   Tier-1: 25000/500 = 50 validations/s × 1 µs = 50 µs/s (<0.01%)
 *   Tier-2: 1 LLM call per ~10 s ≈ same as existing plateau handler
 */
#define HYPOTHESIS_VALIDATION_SAMPLE_RATE  500   /* Validate every N-th exec  */
#define HYPOTHESIS_REFINEMENT_CHECK_INTERVAL 5000 /* Check refinement every N  */
/* ============================================ */

struct queue_entry
{

  u8 *fname; /* File name for the test case      */
  u32 len;   /* Input length                     */

  u8 cal_failed,    /* Calibration failed?              */
      trim_done,    /* Trimmed?                         */
      was_fuzzed,   /* Had any fuzzing done yet?        */
      passed_det,   /* Deterministic stages passed?     */
      has_new_cov,  /* Triggers new coverage?           */
      var_behavior, /* Variable behavior?               */
      favored,      /* Currently favored?               */
      fs_redundant; /* Marked as redundant in the fs?   */

  u32 bitmap_size, /* Number of bits set in bitmap     */
      exec_cksum;  /* Checksum of the execution trace  */

  u64 exec_us,  /* Execution time (us)              */
      handicap, /* Number of queue cycles behind    */
      depth;    /* Path depth                       */

  u8 *trace_mini; /* Trace bytes, if kept             */
  u32 tc_ref;     /* Trace bytes ref count            */

  struct queue_entry *next, /* Next element, if any             */
      *next_100;            /* 100 elements ahead               */

  region_t *regions;       /* Regions keeping information of message(s) sent to the server under test */
  u32 region_count;        /* Total number of regions in this seed */
  u32 index;               /* Index of this queue entry in the whole queue */
  u32 generating_state_id; /* ID of the start at which the new seed was generated */
  u8 is_initial_seed;      /* Is this an initial seed */
  u32 unique_state_count;  /* Unique number of states traversed by this queue entry */

  /* P5: MQTT differential feedback — queue-level divergence score.
   * 0=no divergence, 1-100 = severity (higher → more interesting).
   * Set by mqtt_diff_analyze_and_annotate() after multi-broker exec. */
  u8 mqtt_diff_score;
};

static struct queue_entry *queue, /* Fuzzing queue (linked list)      */
    *queue_cur,                   /* Current offset within the queue  */
    *queue_top,                   /* Top of the list                  */
    *q_prev100;                   /* Previous 100 marker              */

static struct queue_entry *
    top_rated[MAP_SIZE]; /* Top entries for bitmap bytes     */

/* Helper: find queue entry by its index */
static struct queue_entry *find_queue_entry_by_index(u32 idx) {
  struct queue_entry *q = queue;
  while (q) {
    if (q->index == idx) return q;
    q = q->next;
  }
  return NULL;
}

/* Base64 decode helper (simple, no padding robustness needed for small payloads) */
static unsigned char *base64_decode(const char *data, size_t input_length, size_t *out_len) {
  if (!data) return NULL;
  static const signed char tbl[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1, 0,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    /* rest -1 */
  };
  /* Ensure table covers 256 entries */
  unsigned char *out = ck_alloc(input_length);
  size_t outi = 0;
  int val=0, valb=-8;
  for (size_t i=0;i<input_length;i++) {
    unsigned char c = data[i];
    signed char d = (c < 256) ? tbl[c] : -1;
    if (d == -1) continue;
    val = (val<<6) + d;
    valb += 6;
    if (valb>=0) {
      out[outi++] = (unsigned char)((val>>valb)&0xFF);
      valb-=8;
    }
  }
  if (outi == 0) { ck_free(out); return NULL; }
  *out_len = outi;
  return out;
}

struct extra_data
{
  u8 *data;    /* Dictionary token data            */
  u32 len;     /* Dictionary token length          */
  u32 hit_cnt; /* Use count in the corpus          */
};

static struct extra_data *extras; /* Extra tokens to fuzz with        */
static u32 extras_cnt;            /* Total number of tokens read      */

static struct extra_data *a_extras; /* Automatically selected extras    */
static u32 a_extras_cnt;            /* Total number of tokens available */

static u8 *(*post_handler)(u8 *buf, u32 *len);

/* Interesting values, as per config.h */

static s8 interesting_8[] = {INTERESTING_8};
static s16 interesting_16[] = {INTERESTING_8, INTERESTING_16};
static s32 interesting_32[] = {INTERESTING_8, INTERESTING_16, INTERESTING_32};

/* Fuzzing stages */

enum
{
  /* 00 */ STAGE_FLIP1,
  /* 01 */ STAGE_FLIP2,
  /* 02 */ STAGE_FLIP4,
  /* 03 */ STAGE_FLIP8,
  /* 04 */ STAGE_FLIP16,
  /* 05 */ STAGE_FLIP32,
  /* 06 */ STAGE_ARITH8,
  /* 07 */ STAGE_ARITH16,
  /* 08 */ STAGE_ARITH32,
  /* 09 */ STAGE_INTEREST8,
  /* 10 */ STAGE_INTEREST16,
  /* 11 */ STAGE_INTEREST32,
  /* 12 */ STAGE_EXTRAS_UO,
  /* 13 */ STAGE_EXTRAS_UI,
  /* 14 */ STAGE_EXTRAS_AO,
  /* 15 */ STAGE_HAVOC,
  /* 16 */ STAGE_SPLICE
};

/* Stage value types */

enum
{
  /* 00 */ STAGE_VAL_NONE,
  /* 01 */ STAGE_VAL_LE,
  /* 02 */ STAGE_VAL_BE
};

/* Execution status fault codes */

enum
{
  /* 00 */ FAULT_NONE,
  /* 01 */ FAULT_TMOUT,
  /* 02 */ FAULT_CRASH,
  /* 03 */ FAULT_ERROR,
  /* 04 */ FAULT_NOINST,
  /* 05 */ FAULT_NOBITS
};

char **use_argv; /* argument to run the target program. In vanilla AFL, this is a local variable in main. */
/* add these declarations here so we can call these functions earlier */
static u8 run_target(char **argv, u32 timeout);
static inline u32 UR(u32 limit);
static inline u8 has_new_bits(u8 *virgin_map);
static void mqtt_fix_message_length(message_t *m);
static u8 mqtt_fix_length_enabled;

/* AFLNet-specific variables & functions */

u32 server_wait_usecs = 10000;
u32 poll_wait_msecs = 1;
u32 socket_timeout_usecs = 1000;
u8 net_protocol;
u8 *net_ip;
u32 net_port;
char *response_buf = NULL;
int response_buf_size = 0;  // the size of the whole response buffer
u32 *response_bytes = NULL; // an array keeping accumulated response buffer size
                            // e.g., response_bytes[i] keeps the response buffer size
                            // once messages 0->i have been received and processed by the SUT
u32 max_annotated_regions = 0;
u32 target_state_id = 0;
u32 *state_ids = NULL;
u32 state_ids_count = 0;
u32 selected_state_index = 0;
u32 state_cycles = 0;
u32 messages_sent = 0;
char *mqtt_cluster_diff_summary = NULL;
u32 mqtt_cluster_broker_count = 0;
u32 mqtt_cluster_unique_signatures = 0;
u8 mqtt_cluster_diverged = 0;
static u8 mqtt_cluster_probe_logged = 0;
static u8 mqtt_diff_feedback_enabled = 0;   /* MQTT-only: enable diff reward loop */
static u32 mqtt_diff_probe_period = 32;     /* Probe CHATAFL_MQTT_BROKERS every N execs (MQTT init→8) */
static u64 mqtt_diff_last_probe_exec = 0;   /* Last exec index when cluster probe ran */
static double mqtt_last_diff_signal = 0.0;  /* Last normalized divergence signal [0,1] */
/* Runtime-observable differential telemetry (cumulative over run). */
static u64 mqtt_diff_obs_count = 0;         /* #executions with diff signal sampled */
static u64 mqtt_diff_pos_count = 0;         /* #samples where diff_signal > 0 */
static double mqtt_diff_signal_sum = 0.0;   /* Sum of sampled diff signals */
static u32 mqtt_diff_warn_obs_threshold = 500;   /* warn if obs >= this */
static double mqtt_diff_warn_avg_threshold = 0.01; /* and avg <= this */

/* Per-state differential productivity (MQTT-only, state-aware mode).
 * Indexed by state_ids[] index; tracks how often a target state produces
 * cross-broker divergence, then feeds back into state desirability score. */
static double *mqtt_state_diff_reward_sum = NULL;
static u32 *mqtt_state_diff_obs = NULL;
static u32 mqtt_state_diff_cap = 0;

/* ════════════════════════════════════════════════════════════════════
 * P5: Enhanced MQTT Differential Feedback — runtime-observable metrics
 *
 * Tracks field-level (G-field/H-field) divergence following MBFuzzer's
 * three-tier decomposition: type sequence, return codes, payload content.
 * ════════════════════════════════════════════════════════════════════ */
static u64 mqtt_diff_type_divergences    = 0;  /* Type-sequence divergences   */
static u64 mqtt_diff_code_divergences    = 0;  /* Return-code divergences     */
static u64 mqtt_diff_payload_divergences = 0;  /* Payload-content divergences */
static u64 mqtt_diff_fwd_divergences     = 0;  /* O2: Forward-path divergences */
static u64 mqtt_diff_queue_promotions    = 0;  /* Inputs promoted by diff     */

/* P6: Deep-path state promotion metrics */
static u64 mqtt_deep_state_promotions    = 0;  /* Deep-state energy boosts    */
static u64 mqtt_state_stall_resets       = 0;  /* Stall-triggered resets      */

/* V6: Granular P6 observability counters */
static u64 mqtt_p6_deep_state_boosts     = 0;  /* unique_state_count ≥ 5/8    */
static u64 mqtt_p6_stall_boosts          = 0;  /* Stall-aware energy boosts   */
static u64 mqtt_p5_energy_boosts         = 0;  /* P5 diff_score-based boosts  */

/* D4: Unique differential report counter and dedup. */
static u64 unique_diffs = 0;
#define MQTT_DIFF_DEDUP_SLOTS 512
static u32 mqtt_diff_report_hashes[MQTT_DIFF_DEDUP_SLOTS];

/* D1: Coverage-efficiency tracking — detect bitmap growth stalls to
 * dynamically boost havoc energy when coverage is plateauing. */
static u64 last_cov_check_execs = 0;
static u32 last_cov_check_paths = 0;
static u8  mqtt_cov_stagnant = 0;  /* 1 = coverage hasn't grown recently */

/* Per-state consecutive zero-discovery counter for stall detection.
 * Indexed by selected_state_index; reset on new path discovery. */
static u32 *mqtt_state_stall_counter = NULL;
static u32  mqtt_state_stall_cap     = 0;
#define MQTT_STALL_THRESHOLD 200  /* consecutive execs w/o discovery before penalty */

/* Divergence pattern dedup bitmap (4096-entry hash table).
 * Tracks which divergence pattern_hash values have been seen,
 * so we only promote queue entries for NEW divergence patterns. */
#define MQTT_DIV_BITMAP_SIZE 4096
static u8 mqtt_div_pattern_bitmap[MQTT_DIV_BITMAP_SIZE];

/* Last field-level differential result from multi-broker execution.
 * Used by save_if_interesting() to annotate the queue entry. */
static mqtt_diff_result_t mqtt_last_field_diff;
static u8 mqtt_last_field_diff_valid = 0;  /* 1 if mqtt_last_field_diff is fresh */
EXP_ST u8 session_virgin_bits[MAP_SIZE]; /* Regions yet untouched while the SUT is still running */
EXP_ST u8 *cleanup_script;               /* script to clean up the environment of the SUT -- make fuzzing more deterministic */
EXP_ST u8 *netns_name;                   /* network namespace name to run server in */
char **was_fuzzed_map = NULL;            /* A 2D array keeping state-specific was_fuzzed information */
u32 fuzzed_map_states = 0;
u32 fuzzed_map_qentries = 0;
u32 max_seed_region_count = 0;
u32 local_port; /* TCP/UDP port number to use as source */

/* ── A1: Adaptive server-wait ──────────────────────────────────────────
 * Instead of sleeping server_wait_usecs (10 ms) on every single
 * execution, we use an adaptive approach:
 *   - First execution: full sleep (server cold start)
 *   - After first successful connect: wait = 0 (server forks instantly)
 *   - After any connect failure: reset to full sleep for next exec
 * This eliminates the dominant per-exec delay for forking servers. */
static u32  adaptive_wait_usecs;     /* current wait (0 after warmup)  */
static u8   server_warmed_up = 0;    /* 1 after first successful exec  */

/* ── MQTT Persistent Server Mode ───────────────────────────────────────
 * ARCHITECTURE-LEVEL optimization: instead of fork → send → kill per
 * test case (~160 ms), keep the MQTT broker alive across multiple test
 * cases and just reconnect TCP between them (~5 ms).
 *
 * Protocol flow with forkserver:
 *   First exec:   write(ctl) → read(pid) → send_over_network() → [NO read(status)]
 *   Reuse exec:   [NO write/read] → clear trace_bits → send_over_network()
 *   Re-fork exec: kill(child) → read(status) → write(ctl) → read(pid) → send()
 *
 * The forkserver blocks on waitpid(child) between execs. When we
 * finally kill the child (every mqtt_persistent_limit execs or on
 * crash), the forkserver unblocks, writes status, and is ready for
 * the next fork request.
 *
 * MQTT-only: text protocols keep the standard fork-per-exec model.
 * Disabled during calibration to preserve stability measurement. */
static u8   mqtt_persistent_mode     = 0;   /* enabled for -P MQTT        */
static u32  mqtt_persistent_count    = 0;   /* execs on current child     */
static u32  mqtt_persistent_limit    = 20;  /* re-fork every N execs      */
static u8   mqtt_persistent_active   = 0;   /* 1 = child persisted alive  */
static pid_t mqtt_persistent_pid     = 0;   /* PID of persisted child     */
static u8   mqtt_persistent_skip_kill = 0;  /* suppress kill in send_over_network */
static u8   mqtt_in_calibration      = 0;   /* 1 during calibrate_case()  */

/* MQTT fast I/O: skip usleep(10) in aflnet.c net_send/net_recv.
 * Defined in aflnet.c; set here in main() for MQTT protocol. */
extern u8 mqtt_fast_io;

/* flags */
u8 use_net = 0;
u8 poll_wait = 0;
u8 server_wait = 0;
u8 socket_timeout = 0;
u8 protocol_selected = 0;
u8 terminate_child = 0;
u8 child_force_killed = 0;  /* Fix-14a: set by send_over_network() SIGKILL escalation */
u8 corpus_read_or_sync = 0;
u8 state_aware_mode = 0;
u8 region_level_mutation = 0;
u8 state_selection_algo = ROUND_ROBIN, seed_selection_algo = RANDOM_SELECTION;
u8 false_negative_reduction = 0;

/* Track how long we don't observe interesting seeds */
u32 uninteresting_times = 0;
/* Track how much times we ask for breaking coverage plateau */
u32 chat_times = 0;

/* ============================================
 * MQTT-specific Enhancement Flags  (P1/P2)
 * ============================================ */
u8 mqtt_field_mutate_enabled  = 0;  /* P2a: field-aware MQTT mutation in havoc (extern in mp-driver-mqtt.c) */
u8 mqtt_cross_session_enabled = 0;         /* P2b: cross-session state fuzzing (extern in mp-driver-mqtt.c) */

/* ============================================
 * P3: Q-Learning + UCB1 Bandit Schedulers (MQTT only)
 * ============================================ */
static mqtt_ql_t     mqtt_ql;              /* Q-Learning message type scheduler */
static mqtt_bandit_t mqtt_bandit;          /* UCB1 arm selector (replace/insert/field/skip) */
static u8 mqtt_scheduler_enabled = 0;      /* Set to 1 after init for MQTT */

/* ============================================
 * Adaptive Plateau Triggering Variables
 * ============================================ */
static u32 last_edges_count = 0;           /* Edges count at last check */
static u64 last_edges_check_time = 0;      /* Time of last edges check (ms) */
static double edges_growth_rate = 0.0;     /* Edges/minute growth rate */
static u32 adaptive_plateau_threshold = 200; /* Dynamic plateau threshold (starts at UNINTERESTING_THRESHOLD) */

/* ============================================
 * Ablation Control Flags (env-var toggled)
 *
 * Each flag DISABLES one optimization so that ablation experiments
 * can isolate the contribution of individual mechanisms.
 *   CHATAFL_NO_REFINEMENT=1  → disable Tier-2 hypothesis refinement
 *   CHATAFL_NO_FRONTIER=1    → disable frontier bonus + error penalty
 *   CHATAFL_NO_ADAPTIVE=1    → disable adaptive plateau threshold
 *   CHATAFL_NO_STATE_PROMPT=1 → disable state-aware rich prompt + actions[]
 *                               (falls back to ChatAFL's simple prompt)
 * When unset (default), all optimizations are active.
 * ============================================ */
static u8 ablation_no_refinement   = 0;
static u8 ablation_no_frontier     = 0;
static u8 ablation_no_adaptive     = 0;
static u8 ablation_no_state_prompt = 0;

/* ============================================
 * LLM Cost Tracking
 *
 * Accumulates prompt_tokens / completion_tokens from the OpenAI-compatible
 * API "usage" object.  Written to fuzzer_stats and plot_data so the cost
 * of each experimental configuration can be compared quantitatively.
 * ============================================ */
static u64 llm_total_prompt_tokens     = 0;
static u64 llm_total_completion_tokens = 0;
static u64 llm_total_calls             = 0;
static u64 llm_dedup_hits              = 0;  /* prompt-hash cache hits */

/* Simple prompt-hash dedup table for plateau handler.
 * We store the last 64 prompt hashes (djb2) and skip LLM calls that
 * produce an identical hash within the window. */
#define LLM_DEDUP_SLOTS 64
static u32 llm_prompt_hash_ring[LLM_DEDUP_SLOTS];
static u32 llm_prompt_hash_count = 0;

extern char *protocol_name;
extern klist_t(lms) *kl_messages;

typedef struct {
  u8 *ip;
  u32 port;
  char impl_name[32];  /* D2: broker implementation name (e.g. "mosquitto","nanomq") */
} mqtt_broker_endpoint_t;

/* ════════════════════════════════════════════════════════════════════
 * D4: Save structured differential report to out_dir/diffs/.
 *
 * When multi-broker execution detects a behavioral divergence
 * (type/code/payload/forward), save the triggering test case and a
 * human-readable description so the operator can triage RFC
 * non-compliance bugs — matching MBFuzzer's diffs/ output.
 *
 * Dedup: MD5-style hash ring to avoid duplicate reports.
 * ════════════════════════════════════════════════════════════════════ */

/* Forward declarations for functions used in mqtt_save_diff_report */
static u64 get_cur_time(void);
static u32 count_non_255_bytes(u8 *mem);
/* Forward declaration: kl_messages is defined at ~line 1654 after IPSM globals */
extern klist_t(lms) *kl_messages;

static void mqtt_save_diff_report(const char *diff_type,
                                  const char *detail,
                                  mqtt_broker_endpoint_t *eps,
                                  u32 ecnt,
                                  u32 *fwd_hashes) {
  if (!out_dir) return;

  /* Dedup by hashing diff_type + detail */
  u32 dhash = 5381;
  for (const char *p = diff_type; *p; p++)
    dhash = ((dhash << 5) + dhash) + (unsigned char)*p;
  for (const char *p = detail; *p; p++)
    dhash = ((dhash << 5) + dhash) + (unsigned char)*p;

  u32 slot = dhash % MQTT_DIFF_DEDUP_SLOTS;
  if (mqtt_diff_report_hashes[slot] == dhash)
    return;  /* likely duplicate */
  mqtt_diff_report_hashes[slot] = dhash;

  unique_diffs++;

  /* Save the triggering test case (replayable format) */
  u8 *fn_seed = alloc_printf("%s/diffs/id:%06llu,type:%s",
                             out_dir, (unsigned long long)unique_diffs, diff_type);
  save_kl_messages_to_file(kl_messages, fn_seed, 1, messages_sent);
  ck_free(fn_seed);

  /* Save human-readable report */
  u8 *fn_report = alloc_printf("%s/diffs/id:%06llu,type:%s.report.txt",
                               out_dir, (unsigned long long)unique_diffs, diff_type);
  int fd = open((char *)fn_report, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd >= 0) {
    dprintf(fd, "=== ChatAFL-Opt Differential Report #%llu ===\n",
            (unsigned long long)unique_diffs);
    dprintf(fd, "Type      : %s\n", diff_type);
    dprintf(fd, "Detail    : %s\n", detail);
    dprintf(fd, "Exec#     : %llu\n", (unsigned long long)total_execs);
    dprintf(fd, "Timestamp : %llu\n", (unsigned long long)get_cur_time() / 1000);
    dprintf(fd, "Brokers   : %u\n", ecnt);
    for (u32 i = 0; i < ecnt; i++) {
      dprintf(fd, "  [%u] %s:%u (impl=%s) fwd_hash=0x%08x\n",
              i, eps[i].ip, eps[i].port, eps[i].impl_name,
              fwd_hashes ? fwd_hashes[i] : 0);
    }
    /* Flag cross-implementation significance */
    if (ecnt >= 2 && strcmp(eps[0].impl_name, eps[1].impl_name) != 0) {
      dprintf(fd, "\n** CROSS-IMPLEMENTATION DIVERGENCE — likely RFC non-compliance **\n");
    }
    dprintf(fd, "\nQueue position : %u / %u paths\n",
            current_entry, queued_paths);
    dprintf(fd, "Bitmap density : %.2f%%\n",
            ((double)count_non_255_bytes(virgin_bits)) * 100.0 / MAP_SIZE);
    close(fd);
  }
  ck_free(fn_report);
}

static void reset_mqtt_cluster_diff_summary(void) {
  if (mqtt_cluster_diff_summary) {
    ck_free(mqtt_cluster_diff_summary);
    mqtt_cluster_diff_summary = NULL;
  }
  mqtt_cluster_broker_count = 0;
  mqtt_cluster_unique_signatures = 0;
  mqtt_cluster_diverged = 0;
  mqtt_last_diff_signal = 0.0;
}

static int mqtt_open_cluster_socket(const char *ip, u32 port) {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in serv_addr;
  struct sockaddr_in local_serv_addr;
  struct hostent *host_entry = NULL;
  int n;

  if (sockfd < 0) {
    return -1;
  }

  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port);
  if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) != 1) {
    host_entry = gethostbyname(ip);
    if (!host_entry || !host_entry->h_addr_list || !host_entry->h_addr_list[0]) {
      close(sockfd);
      return -1;
    }
    memcpy(&serv_addr.sin_addr, host_entry->h_addr_list[0], (size_t)host_entry->h_length);
  }

  if (local_port > 0) {
    local_serv_addr.sin_family = AF_INET;
    local_serv_addr.sin_addr.s_addr = INADDR_ANY;
    local_serv_addr.sin_port = htons(local_port);
    local_serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (bind(sockfd, (struct sockaddr *)&local_serv_addr, sizeof(struct sockaddr_in))) {
      close(sockfd);
      return -1;
    }
  }

  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    /* A9: Tighter retry — 200 × 500 µs = 100 ms ceiling */
    for (n = 0; n < 200; n++) {
      if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0)
        break;
      usleep(500);
    }
    if (n == 200) {
      close(sockfd);
      return -1;
    }
  }

  /* A3: Disable Nagle for small MQTT control packets */
  { int one = 1; setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)); }

  return sockfd;
}

static u32 mqtt_pack_connect(u8 *out, u32 out_cap, const char *client_id) {
  u32 cid_len = (u32)strlen(client_id);
  u32 rem_len = 10 + 2 + cid_len;
  if (!out || out_cap < (2 + rem_len) || cid_len > 23) {
    return 0;
  }

  out[0] = 0x10;
  out[1] = (u8)rem_len;
  out[2] = 0x00; out[3] = 0x04;
  out[4] = 'M';  out[5] = 'Q'; out[6] = 'T'; out[7] = 'T';
  out[8] = 0x04;
  out[9] = 0x02;
  out[10] = 0x00; out[11] = 0x3C;
  out[12] = (u8)((cid_len >> 8) & 0xFF);
  out[13] = (u8)(cid_len & 0xFF);
  memcpy(out + 14, client_id, cid_len);
  return 14 + cid_len;
}

static u32 mqtt_pack_subscribe(u8 *out, u32 out_cap, u16 pkt_id, const char *topic, u8 qos) {
  u32 tlen = (u32)strlen(topic);
  u32 rem_len = 2 + 2 + tlen + 1;
  if (!out || out_cap < (2 + rem_len) || tlen > 65535) {
    return 0;
  }

  out[0] = 0x82;
  out[1] = (u8)rem_len;
  out[2] = (u8)((pkt_id >> 8) & 0xFF);
  out[3] = (u8)(pkt_id & 0xFF);
  out[4] = (u8)((tlen >> 8) & 0xFF);
  out[5] = (u8)(tlen & 0xFF);
  memcpy(out + 6, topic, tlen);
  out[6 + tlen] = (u8)(qos & 0x03);
  return 7 + tlen;
}

static u32 mqtt_pack_publish(u8 *out, u32 out_cap, const char *topic, const char *payload) {
  u32 tlen = (u32)strlen(topic);
  u32 plen = (u32)strlen(payload);
  u32 rem_len = 2 + tlen + plen;
  if (!out || out_cap < (2 + rem_len) || tlen > 65535) {
    return 0;
  }

  out[0] = 0x30;
  out[1] = (u8)rem_len;
  out[2] = (u8)((tlen >> 8) & 0xFF);
  out[3] = (u8)(tlen & 0xFF);
  memcpy(out + 4, topic, tlen);
  memcpy(out + 4 + tlen, payload, plen);
  return 4 + tlen + plen;
}

static void mqtt_pack_disconnect(u8 *out, u32 out_cap, u32 *out_len) {
  if (!out || out_cap < 2 || !out_len) {
    return;
  }
  out[0] = 0xE0;
  out[1] = 0x00;
  *out_len = 2;
}

static u8 mqtt_packet_type_from_msg(const char *msg, u32 len) {
  if (!msg || len == 0) {
    return 0;
  }
  return (u8)(((u8)msg[0]) >> 4);
}

static char *mqtt_probe_multi_party_interaction(const char *ip, u32 port) {
  struct timeval timeout;
  int subfd = -1;
  int pubfd = -1;
  int ctrlfd = -1;
  char *sub_resp = NULL;
  unsigned int sub_resp_len = 0;
  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;
  char *result = NULL;
  u8 pkt[256];
  u32 pkt_len = 0;
  u32 i = 0;
  u8 prev_ptype = 0;
  u8 have_prev_ptype = 0;
  u32 saved_local_port = local_port;
  kliter_t(lms) *it;

  mqtt_init_spec_state_model();

  timeout.tv_sec = 0;
  timeout.tv_usec = socket_timeout_usecs > 50000 ? socket_timeout_usecs : 50000;

  local_port = 0;
  subfd = mqtt_open_cluster_socket(ip, port);
  pubfd = mqtt_open_cluster_socket(ip, port);
  ctrlfd = mqtt_open_cluster_socket(ip, port);
  local_port = saved_local_port;

  if (subfd < 0 || pubfd < 0 || ctrlfd < 0) {
    result = ck_strdup((u8 *)"mp-connect-failed");
    goto cleanup;
  }

  setsockopt(subfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
  setsockopt(subfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
  setsockopt(pubfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
  setsockopt(pubfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
  setsockopt(ctrlfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
  setsockopt(ctrlfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

  pkt_len = mqtt_pack_connect(pkt, sizeof(pkt), "chatafl_sub");
  if (!pkt_len || net_send(subfd, timeout, (char *)pkt, pkt_len) != (int)pkt_len) {
    result = ck_strdup((u8 *)"mp-sub-connect-send-failed");
    goto cleanup;
  }
  net_recv(subfd, timeout, poll_wait_msecs, &sub_resp, &sub_resp_len);

  pkt_len = mqtt_pack_connect(pkt, sizeof(pkt), "chatafl_pub");
  if (!pkt_len || net_send(pubfd, timeout, (char *)pkt, pkt_len) != (int)pkt_len) {
    result = ck_strdup((u8 *)"mp-pub-connect-send-failed");
    goto cleanup;
  }
  net_recv(pubfd, timeout, poll_wait_msecs, &sub_resp, &sub_resp_len);

  pkt_len = mqtt_pack_connect(pkt, sizeof(pkt), "chatafl_ctrl");
  if (!pkt_len || net_send(ctrlfd, timeout, (char *)pkt, pkt_len) != (int)pkt_len) {
    result = ck_strdup((u8 *)"mp-ctrl-connect-send-failed");
    goto cleanup;
  }
  net_recv(ctrlfd, timeout, poll_wait_msecs, &sub_resp, &sub_resp_len);

  pkt_len = mqtt_pack_subscribe(pkt, sizeof(pkt), 1, "#", 0);
  if (!pkt_len || net_send(subfd, timeout, (char *)pkt, pkt_len) != (int)pkt_len) {
    result = ck_strdup((u8 *)"mp-subscribe-send-failed");
    goto cleanup;
  }
  net_recv(subfd, timeout, poll_wait_msecs, &sub_resp, &sub_resp_len);

  for (it = kl_begin(kl_messages); it != kl_end(kl_messages); it = kl_next(it)) {
    int target_fd = ctrlfd;
    message_t *m = kl_val(it);
    u8 ptype = mqtt_packet_type_from_msg(m->mdata, m->msize);
    int role;

    if (!m || !m->mdata || m->msize == 0) {
      continue;
    }

    if (have_prev_ptype && !mqtt_spec_transition_allowed(prev_ptype, ptype)) {
      continue;
    }

    role = mqtt_role_for_packet_type(ptype);
    if (role == 2) target_fd = pubfd;
    else if (role == 1) target_fd = subfd;
    else target_fd = ctrlfd;

    if (!mqtt_spec_transition_allowed(0, ptype) && !have_prev_ptype) {
      if (ptype != 1) {
        continue;
      }
    }

    if (net_send(target_fd, timeout, m->mdata, m->msize) != (int)m->msize) {
      continue;
    }

    prev_ptype = ptype;
    have_prev_ptype = 1;

    net_recv(target_fd, timeout, poll_wait_msecs, &sub_resp, &sub_resp_len);
    if (target_fd != subfd) {
      net_recv(subfd, timeout, poll_wait_msecs, &sub_resp, &sub_resp_len);
    }
  }

  pkt_len = mqtt_pack_publish(pkt, sizeof(pkt), "chatafl/probe", "ping");
  if (pkt_len) {
    net_send(pubfd, timeout, (char *)pkt, pkt_len);
    net_recv(pubfd, timeout, poll_wait_msecs, &sub_resp, &sub_resp_len);
    for (i = 0; i < 4; i++) {
      if (net_recv(subfd, timeout, poll_wait_msecs, &sub_resp, &sub_resp_len) != 0) {
        break;
      }
    }
  }

  if (sub_resp && sub_resp_len > 0) {
    state_sequence = extract_response_codes_mqtt((unsigned char *)sub_resp, sub_resp_len, &state_count);
    if (state_sequence) {
      result = (char *)state_sequence_to_string(state_sequence, state_count);
      ck_free(state_sequence);
      state_sequence = NULL;
    }
  }

  if (!result) {
    result = ck_strdup((u8 *)"mp-no-response");
  }

cleanup:
  pkt_len = 0;
  mqtt_pack_disconnect(pkt, sizeof(pkt), &pkt_len);
  if (pkt_len && subfd >= 0) {
    net_send(subfd, timeout, (char *)pkt, pkt_len);
  }
  if (pkt_len && pubfd >= 0) {
    net_send(pubfd, timeout, (char *)pkt, pkt_len);
  }
  if (pkt_len && ctrlfd >= 0) {
    net_send(ctrlfd, timeout, (char *)pkt, pkt_len);
  }

  if (sub_resp) ck_free(sub_resp);
  if (state_sequence) ck_free(state_sequence);
  if (subfd >= 0) close(subfd);
  if (pubfd >= 0) close(pubfd);
  if (ctrlfd >= 0) close(ctrlfd);

  return result;
}

/* Forward declaration — defined after helper functions. */
static void mqtt_diff_analyze_responses(char **raw_responses,
                                        unsigned int *raw_response_lens,
                                        u32 broker_count);

static void mqtt_probe_cluster_differences(void) {
  const char *broker_spec = getenv("CHATAFL_MQTT_BROKERS");
  mqtt_broker_endpoint_t *endpoints = NULL;
  char **signatures = NULL;
  char *spec_copy = NULL;
  char *token = NULL;
  char *saveptr = NULL;
  char self_hostname[256];
  int have_self_hostname = 0;
  u32 endpoint_count = 0;
  u32 i = 0;

  if (!protocol_name || strcasecmp(protocol_name, "MQTT") != 0) {
    reset_mqtt_cluster_diff_summary();
    return;
  }

  if (net_protocol != PRO_TCP) {
    reset_mqtt_cluster_diff_summary();
    return;
  }

  /* Skip cluster probing during dry run — partner container likely not ready. */
  if (queue_cycle == 0) {
    reset_mqtt_cluster_diff_summary();
    return;
  }

  /* MQTT cluster-diff probing can be expensive (N brokers × full replay).
   * Throttle probes by execution count when CHATAFL_MQTT_BROKERS is set.
   * Cached signal is reused between probe intervals, with mild decay. */
  if (broker_spec && *broker_spec && mqtt_diff_probe_period > 1) {
    if (total_execs > 0 && mqtt_diff_last_probe_exec > 0 &&
        (total_execs - mqtt_diff_last_probe_exec) < mqtt_diff_probe_period) {
      mqtt_last_diff_signal *= 0.95;
      return;
    }
    mqtt_diff_last_probe_exec = total_execs;
  }

  reset_mqtt_cluster_diff_summary();

  /* Even if no CHATAFL_MQTT_BROKERS is set, still run multi-party
   * probe against the target broker (once). */
  if (!broker_spec || !*broker_spec) {
    static u8 mp_standalone_done = 0;
    if (!mp_standalone_done && net_ip && net_port) {
      char *mp_sig = mqtt_probe_multi_party_interaction((char *)net_ip, net_port);
      if (mp_sig) {
        fprintf(stderr, "[mqtt-mpi] standalone multi-party probe: %s\n", mp_sig);
        ck_free(mp_sig);
      }
      mp_standalone_done = 1;
    }
    mqtt_last_diff_signal = 0.0;
    return;
  }

  /* NOTE: Do NOT filter out self-hostname here.  The main execution path
   * (mqtt_collect_exec_brokers) includes all listed brokers without
   * self-filtering, and the probe path must be consistent to avoid
   * the counter being reset to 0 when the probe fires after a main-path
   * execution that correctly set mqtt_cluster_broker_count=N.  Each
   * container runs its own instrumented broker on 127.0.0.1 while the
   * hostname-aliased broker is the *same* process listening on 0.0.0.0,
   * so including self still produces valid differential data. */
  (void)self_hostname;
  (void)have_self_hostname;

  spec_copy = ck_strdup((u8 *)broker_spec);
  if (!spec_copy) {
    /* L3-fix: Log allocation failure instead of silent return */
    fprintf(stderr, "[L3-warn] mqtt_probe_cluster_differences: "
            "ck_strdup failed for broker_spec\n");
    return;
  }

  token = strtok_r(spec_copy, ",", &saveptr);
  while (token) {
    u8 *ip = NULL;
    u32 port = 0;
    u8 proto = 0;

    while (*token && isspace((unsigned char)*token)) token++;
    if (*token) {
      char *end = token + strlen(token) - 1;
      while (end >= token && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
      }
    }

    if (*token && !parse_net_config((u8 *)token, &proto, &ip, &port) && proto == PRO_TCP) {
      mqtt_broker_endpoint_t *next = (mqtt_broker_endpoint_t *)ck_realloc(endpoints, (endpoint_count + 1) * sizeof(mqtt_broker_endpoint_t));
      if (!next) {
        if (ip) free(ip);
        break;
      }
      endpoints = next;
      endpoints[endpoint_count].ip = ip;
      endpoints[endpoint_count].port = port;
      endpoint_count++;
    } else if (ip) {
      free(ip);
    }

    token = strtok_r(NULL, ",", &saveptr);
  }

  ck_free(spec_copy);

  if (endpoint_count < 2) {
    if (broker_spec && !mqtt_cluster_probe_logged) {
      fprintf(stderr, "[mqtt-cluster] disabled: brokers=%u diverged=%u summary=%s\n",
              endpoint_count, mqtt_cluster_diverged,
              mqtt_cluster_diff_summary ? mqtt_cluster_diff_summary : "(none)");
      mqtt_cluster_probe_logged = 1;
    }
    if (endpoints) {
      for (i = 0; i < endpoint_count; i++) {
        if (endpoints[i].ip) free(endpoints[i].ip);
      }
      ck_free(endpoints);
    }

    /* Even without cluster diff, still run multi-party interaction probe
     * against the TARGET broker.  This exercises sub/pub/ctrl role
     * splitting on the same broker — useful even in single-container mode.
     * We run it on the first call only to avoid per-exec overhead. */
    {
      static u8 mp_local_done = 0;
      if (!mp_local_done && net_ip && net_port) {
        char *mp_sig = mqtt_probe_multi_party_interaction((char *)net_ip, net_port);
        if (mp_sig) {
          fprintf(stderr, "[mqtt-mpi] local multi-party probe: %s\n", mp_sig);
          ck_free(mp_sig);
        }
        mp_local_done = 1;
      }
    }

    return;
  }

  signatures = (char **)ck_alloc(endpoint_count * sizeof(char *));
  if (!signatures) {
    for (i = 0; i < endpoint_count; i++) {
      if (endpoints[i].ip) free(endpoints[i].ip);
    }
    ck_free(endpoints);
    return;
  }
  memset(signatures, 0, endpoint_count * sizeof(char *));

  /* P5: Collect raw response buffers for field-level differential analysis.
   * These are kept alive until after mqtt_diff_analyze_responses(). */
  char **raw_resp_bufs = (char **)ck_alloc(endpoint_count * sizeof(char *));
  unsigned int *raw_resp_lens = (unsigned int *)ck_alloc(endpoint_count * sizeof(unsigned int));
  memset(raw_resp_bufs, 0, endpoint_count * sizeof(char *));
  memset(raw_resp_lens, 0, endpoint_count * sizeof(unsigned int));

  for (i = 0; i < endpoint_count; i++) {
    int sockfd = mqtt_open_cluster_socket((char *)endpoints[i].ip, endpoints[i].port);
    struct timeval timeout;
    char *cluster_response_buf = NULL;
    unsigned int cluster_response_len = 0;
    unsigned int *cluster_state_sequence = NULL;
    unsigned int cluster_state_count = 0;
    kliter_t(lms) *it;

    if (sockfd < 0) {
      signatures[i] = ck_strdup((u8 *)"connect-failed");
      continue;
    }

    timeout.tv_sec = 0;
    timeout.tv_usec = socket_timeout_usecs;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

    for (it = kl_begin(kl_messages); it != kl_end(kl_messages); it = kl_next(it)) {
      if (net_send(sockfd, timeout, kl_val(it)->mdata, kl_val(it)->msize) != kl_val(it)->msize) {
        break;
      }
      if (net_recv(sockfd, timeout, poll_wait_msecs, &cluster_response_buf, &cluster_response_len)) {
        break;
      }
    }

    net_recv(sockfd, timeout, poll_wait_msecs, &cluster_response_buf, &cluster_response_len);

    if (cluster_response_buf && cluster_response_len > 0) {
      cluster_state_sequence = extract_response_codes_mqtt((unsigned char *)cluster_response_buf, cluster_response_len, &cluster_state_count);
      if (cluster_state_sequence) {
        signatures[i] = (char *)state_sequence_to_string(cluster_state_sequence, cluster_state_count);
        ck_free(cluster_state_sequence);
      }
    }

    if (!signatures[i]) {
      signatures[i] = ck_strdup((u8 *)"no-response");
    }

    /* P5: Keep raw response buffer for field-level diff (freed below) */
    raw_resp_bufs[i] = cluster_response_buf;
    raw_resp_lens[i] = cluster_response_len;

    close(sockfd);

    {
      char *mp_sig = mqtt_probe_multi_party_interaction((char *)endpoints[i].ip, endpoints[i].port);
      if (mp_sig) {
        u8 owns_base_sig = 0;
        char *base_sig = signatures[i];
        if (!base_sig) {
          base_sig = (char *)ck_strdup((u8 *)"no-response");
          owns_base_sig = 1;
        }
        char *merged = alloc_printf("%s|mp:%s", base_sig, mp_sig);
        if (signatures[i]) ck_free(signatures[i]);
        signatures[i] = merged;
        if (owns_base_sig) ck_free(base_sig);
        ck_free(mp_sig);
      }
    }
  }

  {
    u32 unique = 0;
    char *summary = ck_strdup((u8 *)"{\"enabled\":1,\"details\":\"");

    for (i = 0; i < endpoint_count; i++) {
      u32 j;
      u8 seen = 0;

      for (j = 0; j < i; j++) {
        if (signatures[j] && signatures[i] && strcmp(signatures[j], signatures[i]) == 0) {
          seen = 1;
          break;
        }
      }
      if (!seen) {
        unique++;
      }

      if (i == 0) {
        char *next = alloc_printf("%s%s:%u=%s", summary, (char *)endpoints[i].ip, endpoints[i].port, signatures[i]);
        ck_free(summary);
        summary = next;
      } else {
        char *next = alloc_printf("%s;%s:%u=%s", summary, (char *)endpoints[i].ip, endpoints[i].port, signatures[i]);
        ck_free(summary);
        summary = next;
      }
    }

    {
      char *final_summary = alloc_printf("%s\",\"brokers\":%u,\"unique_signatures\":%u,\"diverged\":%u}",
                                         summary, endpoint_count, unique, unique > 1);
      double diff_strength = 0.0;
      if (endpoint_count > 1 && unique > 1) {
        diff_strength = (double)(unique - 1) / (double)(endpoint_count - 1);
        if (diff_strength < 0.0) diff_strength = 0.0;
        if (diff_strength > 1.0) diff_strength = 1.0;
      }
      ck_free(summary);
      reset_mqtt_cluster_diff_summary();
      mqtt_cluster_diff_summary = final_summary;
      mqtt_cluster_broker_count = endpoint_count;
      mqtt_cluster_unique_signatures = unique;
      mqtt_cluster_diverged = (unique > 1);
      mqtt_last_diff_signal = diff_strength;

      if (!mqtt_cluster_probe_logged) {
        fprintf(stderr, "[mqtt-cluster] enabled: brokers=%u diverged=%u summary=%s\n",
                mqtt_cluster_broker_count, mqtt_cluster_diverged,
                mqtt_cluster_diff_summary ? mqtt_cluster_diff_summary : "(none)");
        mqtt_cluster_probe_logged = 1;
      }
    }
  }

  /* P5: Field-level differential analysis on raw response buffers.
   * This enriches the hash-based diff_signal with structured
   * G-field/H-field divergence detection (MBFuzzer-style). */
  if (endpoint_count >= 2) {
    mqtt_diff_analyze_responses(raw_resp_bufs, raw_resp_lens, endpoint_count);
  }

  /* Free raw response buffers */
  for (i = 0; i < endpoint_count; i++) {
    if (raw_resp_bufs[i]) ck_free(raw_resp_bufs[i]);
  }
  ck_free(raw_resp_bufs);
  ck_free(raw_resp_lens);

  for (i = 0; i < endpoint_count; i++) {
    if (signatures[i]) ck_free(signatures[i]);
    if (endpoints[i].ip) free(endpoints[i].ip);
  }
  ck_free(signatures);
  ck_free(endpoints);
}

/* Parse CHATAFL_MQTT_BROKERS into endpoint array for per-exec multi-broker
 * main execution. Returns 1 when >=2 valid TCP endpoints are found.
 * Caller owns *out_endpoints and each endpoint.ip (free with free()). */
static u8 mqtt_collect_exec_brokers(mqtt_broker_endpoint_t **out_endpoints,
                                    u32 *out_count) {
  const char *broker_spec = getenv("CHATAFL_MQTT_BROKERS");
  mqtt_broker_endpoint_t *endpoints = NULL;
  char *spec_copy = NULL;
  char *token = NULL, *saveptr = NULL;
  u32 endpoint_count = 0;

  *out_endpoints = NULL;
  *out_count = 0;

  if (!broker_spec || !*broker_spec)
    return 0;

  spec_copy = ck_strdup((u8 *)broker_spec);
  if (!spec_copy)
    return 0;

  token = strtok_r(spec_copy, ",", &saveptr);
  while (token) {
    u8 *ip = NULL;
    u32 port = 0;
    u8 proto = 0;

    while (*token && isspace((unsigned char)*token)) token++;
    if (*token) {
      char *end = token + strlen(token) - 1;
      while (end >= token && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
      }
    }

    if (*token && !parse_net_config((u8 *)token, &proto, &ip, &port) &&
        proto == PRO_TCP) {
      mqtt_broker_endpoint_t *next = (mqtt_broker_endpoint_t *)ck_realloc(
          endpoints, (endpoint_count + 1) * sizeof(mqtt_broker_endpoint_t));
      if (!next) {
        if (ip) free(ip);
        break;
      }
      endpoints = next;
      endpoints[endpoint_count].ip = ip;
      endpoints[endpoint_count].port = port;

      /* D2: Extract optional broker implementation label.
       * Env format: tcp://host:label/port  (label between ':' and '/')
       * Env label override: CHATAFL_MQTT_BROKER_LABELS=mosquitto,nanomq,... */
      memset(endpoints[endpoint_count].impl_name, 0, 32);
      {
        const char *labels_env = getenv("CHATAFL_MQTT_BROKER_LABELS");
        if (labels_env && *labels_env) {
          /* Parse comma-separated labels by index */
          char *lcopy = strdup(labels_env);
          char *ltok = lcopy, *lsave = NULL;
          u32 li = 0;
          ltok = strtok_r(lcopy, ",", &lsave);
          while (ltok && li < endpoint_count) {
            ltok = strtok_r(NULL, ",", &lsave);
            li++;
          }
          if (ltok) {
            while (*ltok && isspace((unsigned char)*ltok)) ltok++;
            snprintf(endpoints[endpoint_count].impl_name, 31, "%s", ltok);
          }
          free(lcopy);
        }
        if (!endpoints[endpoint_count].impl_name[0]) {
          snprintf(endpoints[endpoint_count].impl_name, 31, "broker%u", endpoint_count);
        }
      }
      endpoint_count++;
    } else if (ip) {
      free(ip);
    }

    token = strtok_r(NULL, ",", &saveptr);
  }

  ck_free(spec_copy);

  if (endpoint_count < 2) {
    for (u32 i = 0; i < endpoint_count; i++)
      if (endpoints[i].ip) free(endpoints[i].ip);
    if (endpoints) ck_free(endpoints);
    return 0;
  }

  *out_endpoints = endpoints;
  *out_count = endpoint_count;
  return 1;
}

/* Build a robust signature string from response bytes.
 * NOTE: deliberately parser-free to avoid crashes on malformed broker output
 * when multi-broker differential execution is enabled. */
static char *mqtt_signature_from_response(char *resp, unsigned int resp_len) {
  if (!resp || resp_len == 0)
    return ck_strdup((u8 *)"no-response");

  /* FNV-1a 64-bit over a bounded prefix for stability + speed. */
  const unsigned int max_sample = 8192;
  unsigned int n = (resp_len < max_sample) ? resp_len : max_sample;
  u64 h = 1469598103934665603ULL;

  for (unsigned int i = 0; i < n; i++) {
    h ^= (u8)resp[i];
    h *= 1099511628211ULL;
  }

  return alloc_printf("len=%u,sample=%u,fnv64=%016llx",
                      resp_len, n, (unsigned long long)h);
}

/* Execute one testcase against ONE broker using the existing mp_driver path.
 * If collect_primary=1, writes into global response_buf/response_bytes/messages_sent.
 * Otherwise uses temporary buffers and only returns signature in out_sig. */
static int mqtt_exec_one_broker_mp(const mp_driver_t *mp_drv,
                                   const char *ip, u32 port,
                                   u8 collect_primary,
                                   char **out_sig,
                                   u8 *out_likely_buggy,
                                   u32 *out_fwd_hash) {
  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = socket_timeout_usecs;

  int *mp_fds_buf = NULL;
  mp_context_t mp_ctx;
  int rc = 0;

  char *aux_resp_buf = NULL;
  int aux_resp_size = 0;
  u32 *aux_resp_bytes = NULL;
  u32 aux_messages_sent = 0;

  if (out_sig) *out_sig = NULL;
  if (out_likely_buggy) *out_likely_buggy = 0;
  if (out_fwd_hash) *out_fwd_hash = 0;

  memset(&mp_ctx, 0, sizeof(mp_ctx));
  if (!mp_drv || mp_drv->fd_count <= 0 || mp_drv->fd_count > 64) {
    rc = -1;
    goto cleanup;
  }

  mp_fds_buf = (int *)ck_alloc((u32)mp_drv->fd_count * sizeof(int));
  mp_ctx.fds = mp_fds_buf;
  mp_ctx.fd_count = mp_drv->fd_count;
  mp_ctx.timeout = timeout;
  mp_ctx.poll_wait_msecs = poll_wait_msecs;
  mp_ctx.server_ip = ip;
  mp_ctx.server_port = port;
  mp_ctx.priv = NULL;

  for (int i = 0; i < mp_ctx.fd_count; i++)
    mp_ctx.fds[i] = -1;

  if (collect_primary) {
    messages_sent = 0;
    mp_ctx.response_buf = &response_buf;
    mp_ctx.response_buf_size = &response_buf_size;
  } else {
    mp_ctx.response_buf = &aux_resp_buf;
    mp_ctx.response_buf_size = &aux_resp_size;
  }

  if (mp_drv->open_connections(&mp_ctx) != 0) {
    rc = -1;
    goto cleanup;
  }

  if (mp_drv->handshake(&mp_ctx) != 0) {
    rc = -1;
    goto cleanup;
  }

  for (kliter_t(lms) *it = kl_begin(kl_messages); it != kl_end(kl_messages); it = kl_next(it)) {
    message_t *m = kl_val(it);

    if (!m || !m->mdata || m->msize == 0) {
      if (collect_primary) {
        messages_sent++;
        response_bytes = (u32 *)ck_realloc(response_bytes, messages_sent * sizeof(u32));
        response_bytes[messages_sent - 1] = response_buf_size;
      } else {
        aux_messages_sent++;
        aux_resp_bytes = (u32 *)ck_realloc(aux_resp_bytes, aux_messages_sent * sizeof(u32));
        aux_resp_bytes[aux_messages_sent - 1] = aux_resp_size;
      }
      continue;
    }

    int role = mp_drv->role_for_message(&mp_ctx, (const unsigned char *)m->mdata, m->msize);
    if (role < 0) {
      if (collect_primary) {
        messages_sent++;
        response_bytes = (u32 *)ck_realloc(response_bytes, messages_sent * sizeof(u32));
        response_bytes[messages_sent - 1] = response_buf_size;
      } else {
        aux_messages_sent++;
        aux_resp_bytes = (u32 *)ck_realloc(aux_resp_bytes, aux_messages_sent * sizeof(u32));
        aux_resp_bytes[aux_messages_sent - 1] = aux_resp_size;
      }
      continue;
    }

    if (mqtt_fix_length_enabled)
      mqtt_fix_message_length(m);

    if (role >= mp_ctx.fd_count) {
      if (collect_primary) {
        messages_sent++;
        response_bytes = (u32 *)ck_realloc(response_bytes, messages_sent * sizeof(u32));
        response_bytes[messages_sent - 1] = response_buf_size;
      } else {
        aux_messages_sent++;
        aux_resp_bytes = (u32 *)ck_realloc(aux_resp_bytes, aux_messages_sent * sizeof(u32));
        aux_resp_bytes[aux_messages_sent - 1] = aux_resp_size;
      }
      continue;
    }

    int target_fd = mp_ctx.fds[role];
    if (target_fd < 0) {
      if (collect_primary) {
        messages_sent++;
        response_bytes = (u32 *)ck_realloc(response_bytes, messages_sent * sizeof(u32));
        response_bytes[messages_sent - 1] = response_buf_size;
      } else {
        aux_messages_sent++;
        aux_resp_bytes = (u32 *)ck_realloc(aux_resp_bytes, aux_messages_sent * sizeof(u32));
        aux_resp_bytes[aux_messages_sent - 1] = aux_resp_size;
      }
      continue;
    }
    int n = net_send(target_fd, timeout, m->mdata, m->msize);

    if (collect_primary) {
      messages_sent++;
      response_bytes = (u32 *)ck_realloc(response_bytes, messages_sent * sizeof(u32));
      if (n != (int)m->msize) {
        response_bytes[messages_sent - 1] = response_buf_size;
        rc = -1;
        goto cleanup;
      }
      u32 prev = response_buf_size;
      net_recv(target_fd, timeout, poll_wait_msecs, &response_buf, &response_buf_size);
      if (mp_drv->after_send(&mp_ctx, role) != 0) {
        rc = -1;
        goto cleanup;
      }
      response_bytes[messages_sent - 1] = response_buf_size;
      if (out_likely_buggy)
        *out_likely_buggy = ((u32)prev == (u32)response_buf_size) ? 1 : 0;
    } else {
      aux_messages_sent++;
      aux_resp_bytes = (u32 *)ck_realloc(aux_resp_bytes, aux_messages_sent * sizeof(u32));
      if (n != (int)m->msize) {
        aux_resp_bytes[aux_messages_sent - 1] = aux_resp_size;
        rc = -1;
        goto cleanup;
      }
      net_recv(target_fd, timeout, poll_wait_msecs, &aux_resp_buf, &aux_resp_size);
      if (mp_drv->after_send(&mp_ctx, role) != 0) {
        rc = -1;
        goto cleanup;
      }
      aux_resp_bytes[aux_messages_sent - 1] = aux_resp_size;
    }
  }

cleanup:
  mp_drv->drain_all(&mp_ctx);

  if (collect_primary) {
    if (messages_sent > 0 && response_bytes)
      response_bytes[messages_sent - 1] = response_buf_size;
  } else {
    if (aux_messages_sent > 0 && aux_resp_bytes)
      aux_resp_bytes[aux_messages_sent - 1] = aux_resp_size;
  }

  /* O2: Extract forward-diff hash before cleanup frees the priv state */
  if (out_fwd_hash)
    *out_fwd_hash = mqtt_mp_get_fwd_hash(&mp_ctx);

  mp_drv->cleanup(&mp_ctx);

  if (out_sig) {
    if (collect_primary)
      *out_sig = mqtt_signature_from_response(response_buf, (unsigned int)response_buf_size);
    else
      *out_sig = mqtt_signature_from_response(aux_resp_buf, (unsigned int)aux_resp_size);
  }

  for (int i = 0; i < mp_ctx.fd_count; i++)
    if (mp_ctx.fds[i] >= 0) close(mp_ctx.fds[i]);

  if (mp_fds_buf)
    ck_free(mp_fds_buf);

  if (!collect_primary) {
    if (aux_resp_bytes) ck_free(aux_resp_bytes);
    if (aux_resp_buf) ck_free(aux_resp_buf);
  }

  return rc;
}

/* Build and store MQTT cluster diff summary from per-broker signatures. */
static void mqtt_set_cluster_summary_from_signatures(mqtt_broker_endpoint_t *eps,
                                                     char **sigs,
                                                     u32 cnt) {
  u32 unique = 0;
  char *summary = ck_strdup((u8 *)"{\"enabled\":1,\"details\":\"");

  for (u32 i = 0; i < cnt; i++) {
    u8 seen = 0;
    for (u32 j = 0; j < i; j++) {
      if (sigs[i] && sigs[j] && strcmp(sigs[i], sigs[j]) == 0) {
        seen = 1;
        break;
      }
    }
    if (!seen) unique++;

    char *next = NULL;
    if (i == 0)
      next = alloc_printf("%s%s:%u=%s", summary, (char *)eps[i].ip, eps[i].port, sigs[i] ? sigs[i] : "(null)");
    else
      next = alloc_printf("%s;%s:%u=%s", summary, (char *)eps[i].ip, eps[i].port, sigs[i] ? sigs[i] : "(null)");
    ck_free(summary);
    summary = next;
  }

  char *final_summary = alloc_printf("%s\",\"brokers\":%u,\"unique_signatures\":%u,\"diverged\":%u}",
                                     summary, cnt, unique, unique > 1);
  ck_free(summary);

  reset_mqtt_cluster_diff_summary();
  mqtt_cluster_diff_summary = final_summary;
  mqtt_cluster_broker_count = cnt;
  mqtt_cluster_unique_signatures = unique;
  mqtt_cluster_diverged = (unique > 1);
  mqtt_last_diff_signal = (cnt > 1 && unique > 1)
      ? ((double)(unique - 1) / (double)(cnt - 1))
      : 0.0;
}

/* Implemented state machine */
Agraph_t *ipsm;
static FILE *ipsm_dot_file;

/* Hash table/map and list */
klist_t(lms) * kl_messages;
khash_t(hs32) * khs_ipsm_paths;
khash_t(hms) * khms_states;

// M2_prev points to the last message of M1 (i.e., prefix)
// If M1 is empty, M2_prev == NULL
// M2_next points to the first message of M3 (i.e., suffix)
// If M3 is empty, M2_next point to the end of the kl_messages linked list
kliter_t(lms) * M2_prev, *M2_next;

// Function pointers pointing to Protocol-specific functions
unsigned int *(*extract_response_codes)(unsigned char *buf, unsigned int buf_size, unsigned int *state_count_ref) = NULL;
region_t *(*extract_requests)(unsigned char *buf, unsigned int buf_size, unsigned int *region_count_ref) = NULL;

// Patterns generated from the Language Model
klist_t(rang) * protocol_patterns;
// Message types of the patterns generated from the Language model
khash_t(strSet) * message_types_set;
// Protocol name kept for prompts
char *protocol_name;
// Reward fields - To be used
u32 reward_random;
u32 reward_grammar;

void setup_llm_grammars()
{

  ACTF("Getting grammars from LLM...");

  khash_t(consistency_table) *const_table = kh_init(consistency_table);
  char *first_question;
  char *templates_prompt = construct_prompt_for_templates(protocol_name, &first_question);

  for (int iter = 0; iter < TEMPLATE_CONSISTENCY_COUNT; iter++)
  {
    klist_t(gram) *grammar_list = kl_init(gram);

    char *templates_answer = chat_with_llm(templates_prompt, "gpt-4o-mini", GRAMMAR_RETRIES, 0.5);
    llm_total_prompt_tokens += llm_last_prompt_tokens;
    llm_total_completion_tokens += llm_last_completion_tokens;
    if (templates_answer != NULL) llm_total_calls++;
    if (templates_answer == NULL)
      goto free_templates_answer;

    // printf("## Answer from LLM:\n %s\n", templates_answer);
    char *remaining_prompt = construct_prompt_for_remaining_templates(protocol_name, first_question, templates_answer);
    // printf("remaining prompt is:\n %s\n", remaining_prompt);
    char *remaining_templates = chat_with_llm(remaining_prompt, "gpt-4o-mini", GRAMMAR_RETRIES, 0.5);
    llm_total_prompt_tokens += llm_last_prompt_tokens;
    llm_total_completion_tokens += llm_last_completion_tokens;
    if (remaining_templates != NULL) llm_total_calls++;
    if (remaining_templates == NULL)
      goto free_remaining;

    // printf("## Remaining templates:\n %s\n", remaining_templates);

    char *combined_templates = NULL;
    asprintf(&combined_templates, "%s\n%s", templates_answer, remaining_templates);

    char *grammar_output_path = alloc_printf("%s/protocol-grammars/llm-grammar-output-%d", out_dir, iter);
    int grammar_output_fd = open(grammar_output_path, O_WRONLY | O_CREAT, 0600);

    ck_write(grammar_output_fd, combined_templates, strlen(combined_templates), grammar_output_path);

    close(grammar_output_fd);
    ck_free(grammar_output_path);

    extract_message_grammars(combined_templates, grammar_list);

    kliter_t(gram) * iter;
    for (iter = kl_begin(grammar_list); iter != kl_end(grammar_list); iter = kl_next(iter))
    {
      json_object *jobj = kl_val(iter);

      // Check if jobj is actually an array before accessing
      if (!json_object_is_type(jobj, json_type_array))
      {
        fprintf(stderr, "[!] Warning: Grammar object is not an array, skipping\n");
        continue;
      }

      int array_len = json_object_array_length(jobj);
      if (array_len < 1)
      {
        fprintf(stderr, "[!] Warning: Grammar array is empty, skipping\n");
        continue;
      }

      json_object *header = json_object_array_get_idx(jobj, 0);

      int absent;

      const char *header_str = json_object_get_string(header);

      khiter_t k = kh_put(consistency_table, const_table, header_str, &absent);
      if (absent)
      {
        khash_t(field_table) *field_table = kh_init(field_table);
        kh_value(const_table, k) = field_table;
      }

      for (int i = 1; i < json_object_array_length(jobj); i++)
      {
        const char *v = json_object_get_string(json_object_array_get_idx(jobj, i));
        khash_t(field_table) *field_table = kh_value(const_table, k);
        khiter_t field_k = kh_put(field_table, field_table, v, &absent);
        if (absent)
        {
          kh_value(field_table, field_k) = 0;
        }
        kh_value(field_table, field_k)++;
      }
    }
    kl_destroy_gram(grammar_list);

    free(combined_templates);
    free(remaining_templates);

  free_remaining:
    free(remaining_prompt);

  free_templates_answer:
    free(templates_answer);
  }

  int pattern_index = 0;
  for (khiter_t con_t_iter = kh_begin(const_table); con_t_iter != kh_end(const_table); ++con_t_iter)
  {
    if (kh_exist(const_table, con_t_iter))
    {
      pcre2_code **patterns = ck_alloc(2 * sizeof(pcre2_code *));

      khash_t(field_table) *field_table = kh_value(const_table, con_t_iter);

      json_object *header_v = json_object_new_string(kh_key(const_table, con_t_iter));
      const char *header_str = json_object_to_json_string(header_v);

      char *pattern_path = alloc_printf("%s/protocol-grammars/pattern-%d", out_dir, pattern_index);
      pattern_index++;
      int pattern_fd = open(pattern_path, O_WRONLY | O_CREAT, 0600);

      char *message_type = extract_message_pattern(header_str, field_table, patterns, pattern_fd, pattern_path);
      if (message_type != NULL)
      {
        int discard;
        kh_put(strSet, message_types_set, message_type, &discard);
        *kl_pushp(rang, protocol_patterns) = patterns;
      }

      json_object_put(header_v);
      close(pattern_fd);
      ck_free(pattern_path);

    }
  }

  /* Fix-13: MQTT binary protocol supplementation.
   * The LLM pipeline above runs normally (API calls happen), but for MQTT
   * it produces 0 useful grammars because the LLM cannot generate binary
   * packet templates.  Supplement message_types_set with hardcoded MQTT
   * message types so the enrichment pipeline has types to work with. */
  if (protocol_name && strcasecmp(protocol_name, "MQTT") == 0) {
    ACTF("MQTT: LLM produced %d patterns — supplementing with hardcoded binary types",
         (int)protocol_patterns->size);
    int n = mqtt_setup_hardcoded_grammars(protocol_patterns, message_types_set, out_dir);
    OKF("Injected %d MQTT message types (supplementing LLM results)", n);
  }

  free(first_question);
  free(templates_prompt);
}

range_list parse_buffer(char *buf, size_t buf_len)
{
  range_list best_decomposition;
  kv_init(best_decomposition);
  kliter_t(rang) * iter_rang;
  // Find a valid decomposition of the buffer, according to a header pattern
  for (iter_rang = kl_begin(protocol_patterns); iter_rang != kl_end(protocol_patterns); iter_rang = kl_next(iter_rang))
  {
    pcre2_code **patterns = kl_val(iter_rang);
    pcre2_code *header_pattern = patterns[0];
    pcre2_code *fields_pattern = patterns[1];

    if(header_pattern == NULL || fields_pattern == NULL) continue;

    range_list header_groups = starts_with(buf, buf_len, header_pattern);

    if (kv_size(header_groups) == 0)
    {
      continue;
    }
    else
    {
      range header_match = kv_pop(header_groups);
      char *offsetted_line = buf;
      size_t offsetted_len = buf_len;
      range_list dyn_ranges = get_mutable_ranges(offsetted_line, offsetted_len, header_match.len, fields_pattern);

      for (int i = 0; i < kv_size(dyn_ranges); i++)
      {
        kv_push(range, header_groups, kv_A(dyn_ranges, i));
      }
      kv_destroy(dyn_ranges);

      best_decomposition = header_groups;

      break;
    }
  }

  if (kv_size(best_decomposition) == 0)
  {
    // Graceful degradataion
    range v = {.start = 0, .len = buf_len, .mutable = 1};
    kv_push(range, best_decomposition, v);
  }
  return best_decomposition;
}

/* Initialize the implemented state machine as a graphviz graph */
void setup_ipsm()
{
  ipsm = agopen("g", Agdirected, 0);

  agattr(ipsm, AGNODE, "color", "black"); // Default node colr is black
  agattr(ipsm, AGEDGE, "color", "black"); // Default edge color is black

  khs_ipsm_paths = kh_init(hs32);

  khms_states = kh_init(hms);
}

/* Free memory allocated to state-machine variables */
void destroy_ipsm()
{
  agclose(ipsm);

  kh_destroy(hs32, khs_ipsm_paths);

  state_info_t *state;
  kh_foreach_value(khms_states, state, {ck_free(state->seeds); ck_free(state); });
  kh_destroy(hms, khms_states);

  ck_free(state_ids);
  if (mqtt_state_diff_reward_sum) {
    ck_free(mqtt_state_diff_reward_sum);
    mqtt_state_diff_reward_sum = NULL;
  }
  if (mqtt_state_diff_obs) {
    ck_free(mqtt_state_diff_obs);
    mqtt_state_diff_obs = NULL;
  }
  mqtt_state_diff_cap = 0;
}

/* Get state index in the state IDs list, given a state ID */
u32 get_state_index(u32 state_id)
{
  u32 index = 0;
  for (index = 0; index < state_ids_count; index++)
  {
    if (state_ids[index] == state_id)
      break;
  }
  return index;
}

/* Ensure per-state MQTT differential tables are large enough for current
 * state_ids_count. MQTT-only, no effect on other protocols. */
static void mqtt_ensure_state_diff_tables(void)
{
  if (state_ids_count <= mqtt_state_diff_cap)
    return;

  u32 old_cap = mqtt_state_diff_cap;
  mqtt_state_diff_reward_sum = (double *)ck_realloc(
      mqtt_state_diff_reward_sum, state_ids_count * sizeof(double));
  mqtt_state_diff_obs = (u32 *)ck_realloc(
      mqtt_state_diff_obs, state_ids_count * sizeof(u32));

  for (u32 i = old_cap; i < state_ids_count; i++) {
    mqtt_state_diff_reward_sum[i] = 0.0;
    mqtt_state_diff_obs[i] = 0;
  }
  mqtt_state_diff_cap = state_ids_count;
}

/* Record differential signal for the current target state.
 * Called after each execution from common_fuzz_stuff() (MQTT-only). */
static void mqtt_record_diff_signal_for_target_state(double signal)
{
  if (!mqtt_diff_feedback_enabled || signal <= 0.0)
    return;
  if (!state_aware_mode || target_state_id == 0 || state_ids_count == 0)
    return;

  mqtt_ensure_state_diff_tables();
  u32 idx = get_state_index(target_state_id);
  if (idx >= state_ids_count)
    return;

  mqtt_state_diff_reward_sum[idx] += signal;
  mqtt_state_diff_obs[idx]++;
}

/* Cumulative mean differential signal for runtime observability. */
static double mqtt_diff_signal_avg(void)
{
  if (mqtt_diff_obs_count == 0)
    return 0.0;
  return mqtt_diff_signal_sum / (double)mqtt_diff_obs_count;
}

/* Compute multiplicative state bonus from differential productivity.
 * Bonus range: [1.0, 1.75], intentionally capped to avoid overpowering
 * frontier/coverage heuristics. */
static double mqtt_state_diff_bonus(u32 state_id)
{
  if (!mqtt_diff_feedback_enabled || state_ids_count == 0)
    return 1.0;

  mqtt_ensure_state_diff_tables();
  u32 idx = get_state_index(state_id);
  if (idx >= state_ids_count || mqtt_state_diff_obs[idx] == 0)
    return 1.0;

  double mean = mqtt_state_diff_reward_sum[idx] / (double)mqtt_state_diff_obs[idx];
  if (mean < 0.0) mean = 0.0;
  if (mean > 1.0) mean = 1.0;
  return 1.0 + 0.75 * mean;
}

/* ════════════════════════════════════════════════════════════════════
 * P5: Field-level differential analysis helpers (MQTT-only)
 * ════════════════════════════════════════════════════════════════════ */

/* Ensure state stall counter array is large enough. */
static void mqtt_ensure_stall_table(void) {
  if (state_ids_count > mqtt_state_stall_cap) {
    u32 new_cap = state_ids_count + 16;
    mqtt_state_stall_counter = (u32 *)ck_realloc(
        mqtt_state_stall_counter, new_cap * sizeof(u32));
    for (u32 i = mqtt_state_stall_cap; i < new_cap; i++)
      mqtt_state_stall_counter[i] = 0;
    mqtt_state_stall_cap = new_cap;
  }
}

/* Record a stall (no new paths) for the current target state.
 * Returns 1 if the state has reached stall threshold. */
static u8 mqtt_record_state_stall(void) {
  if (!mqtt_diff_feedback_enabled || !state_aware_mode) return 0;
  if (!protocol_name || strcasecmp(protocol_name, "MQTT") != 0) return 0;
  mqtt_ensure_stall_table();
  u32 idx = selected_state_index;
  if (idx >= mqtt_state_stall_cap) return 0;
  mqtt_state_stall_counter[idx]++;
  if (mqtt_state_stall_counter[idx] >= MQTT_STALL_THRESHOLD) {
    mqtt_state_stall_resets++;
    mqtt_state_stall_counter[idx] = 0;
    return 1;
  }
  return 0;
}

/* Reset stall counter for current state (new path found). */
static void mqtt_reset_state_stall(void) {
  if (!mqtt_diff_feedback_enabled || !state_aware_mode) return;
  if (!protocol_name || strcasecmp(protocol_name, "MQTT") != 0) return;
  mqtt_ensure_stall_table();
  u32 idx = selected_state_index;
  if (idx < mqtt_state_stall_cap)
    mqtt_state_stall_counter[idx] = 0;
}

/* Check if a divergence pattern is new (not yet in bitmap).
 * If new, marks it in the bitmap and returns 1. */
static u8 mqtt_is_new_divergence_pattern(u32 pattern_hash) {
  u32 slot = pattern_hash % MQTT_DIV_BITMAP_SIZE;
  u8 bit   = 1 << (pattern_hash / MQTT_DIV_BITMAP_SIZE % 8);
  if (mqtt_div_pattern_bitmap[slot] & bit) return 0;
  mqtt_div_pattern_bitmap[slot] |= bit;
  return 1;
}

/* Analyze multi-broker responses using field-level comparison.
 * Called from multi-broker execution path.  Updates telemetry and
 * sets mqtt_last_field_diff for save_if_interesting() to consume.
 *
 * raw_responses[i] + raw_response_lens[i] are the per-broker response buffers.
 * broker_count = number of brokers. */
static void mqtt_diff_analyze_responses(char **raw_responses,
                                        unsigned int *raw_response_lens,
                                        u32 broker_count) {
  mqtt_response_fields_t *fields;
  mqtt_diff_result_t result;

  mqtt_last_field_diff_valid = 0;
  if (broker_count < 2) return;

  /* Parse each broker's response into structured fields (stack-allocated). */
  fields = (mqtt_response_fields_t *)ck_alloc(
      broker_count * sizeof(mqtt_response_fields_t));

  for (u32 i = 0; i < broker_count; i++) {
    mqtt_diff_parse_response(
        (const unsigned char *)raw_responses[i],
        raw_response_lens[i], &fields[i]);
  }

  /* Pairwise comparison — find maximum divergence */
  result = mqtt_diff_compare_n(fields, (int)broker_count);

  /* Update telemetry */
  switch (result.severity) {
  case MQTT_DIV_TYPE:
  case MQTT_DIV_MISSING:
    mqtt_diff_type_divergences++;
    break;
  case MQTT_DIV_CODE:
    mqtt_diff_code_divergences++;
    break;
  case MQTT_DIV_PAYLOAD:
    mqtt_diff_payload_divergences++;
    break;
  default:
    break;
  }

  /* Override mqtt_last_diff_signal with field-level strength.
   * Field-level gives a HIGHER strength for type/code divergences. */
  if (result.severity > MQTT_DIV_NONE) {
    double field_signal = 0.0;
    switch (result.severity) {
    case MQTT_DIV_MISSING: field_signal = 1.0;   break;
    case MQTT_DIV_TYPE:    field_signal = 0.9;    break;
    case MQTT_DIV_CODE:    field_signal = 0.6;    break;
    case MQTT_DIV_PAYLOAD: field_signal = 0.3;    break;
    default:               field_signal = 0.0;    break;
    }
    /* Blend with raw-hash signal: take the higher one */
    if (field_signal > mqtt_last_diff_signal)
      mqtt_last_diff_signal = field_signal;
  }

  mqtt_last_field_diff = result;
  mqtt_last_field_diff_valid = 1;

  ck_free(fields);
}

/* Expand the size of the map when a new seed or a new state has been discovered */
void expand_was_fuzzed_map(u32 new_states, u32 new_qentries)
{
  int i, j;
  // Realloc the memory
  was_fuzzed_map = (char **)ck_realloc(was_fuzzed_map, (fuzzed_map_states + new_states) * sizeof(char *));
  for (i = 0; i < fuzzed_map_states + new_states; i++)
    was_fuzzed_map[i] = (char *)ck_realloc(was_fuzzed_map[i], (fuzzed_map_qentries + new_qentries) * sizeof(char));

  // All new cells are marked as -1 -- meaning UNREACHABLE
  // Keep other cells untouched
  for (i = 0; i < fuzzed_map_states + new_states; i++)
    for (j = 0; j < fuzzed_map_qentries + new_qentries; j++)
      if ((i >= fuzzed_map_states) || (j >= fuzzed_map_qentries))
        was_fuzzed_map[i][j] = -1;

  // Update total number of states (rows) and total number of queue entries (columns) in the was_fuzzed_map
  fuzzed_map_states += new_states;
  fuzzed_map_qentries += new_qentries;
}

/* Get unique state count, given a state sequence */
u32 get_unique_state_count(unsigned int *state_sequence, unsigned int state_count)
{
  // A hash set is used so that no state is counted twice
  khash_t(hs32) * khs_state_ids;
  khs_state_ids = kh_init(hs32);

  unsigned int discard, state_id, i;
  u32 result = 0;

  for (i = 0; i < state_count; i++)
  {
    state_id = state_sequence[i];

    if (kh_get(hs32, khs_state_ids, state_id) != kh_end(khs_state_ids))
    {
      continue;
    }
    else
    {
      kh_put(hs32, khs_state_ids, state_id, &discard);
      result++;
    }
  }

  kh_destroy(hs32, khs_state_ids);
  return result;
}

/* Check if a state sequence is interesting (e.g., new state is discovered). Loop is taken into account */
u8 is_state_sequence_interesting(unsigned int *state_sequence, unsigned int state_count)
{
  // limit the loop count to only 1
  u32 *trimmed_state_sequence = NULL;
  u32 i, count = 0;

  /* B5-fix: MQTT-aware loop suppression threshold.
   * Original: collapse ≥3 identical consecutive states.
   * For MQTT with B1 (PUBLISH in IPSM), forwarded PUBLISHes create
   * legitimate repeated patterns like [SUBACK, PUB_topic_A, PUB_topic_A,
   * PUB_topic_B, ...].  Raising the threshold to 5 allows deeper
   * exploration of subscription delivery paths without unbounded growth.
   * Text protocols keep the original threshold of 3. */
  u32 loop_threshold = 3;
  if (protocol_name && strcasecmp(protocol_name, "MQTT") == 0)
    loop_threshold = 5;

  for (i = 0; i < state_count; i++)
  {
    if ((i >= loop_threshold) &&
        (state_sequence[i] == state_sequence[i - 1]) &&
        (state_sequence[i] == state_sequence[i - 2]))
      continue;
    count++;
    trimmed_state_sequence = (u32 *)realloc(trimmed_state_sequence, count * sizeof(unsigned int));
    trimmed_state_sequence[count - 1] = state_sequence[i];
  }

  // Calculate the hash based on the shortened state sequence
  u32 hashKey = hash32(trimmed_state_sequence, count * sizeof(unsigned int), 0);
  if (trimmed_state_sequence)
    free(trimmed_state_sequence);

  if (kh_get(hs32, khs_ipsm_paths, hashKey) != kh_end(khs_ipsm_paths))
  {
    return 0;
  }
  else
  {
    int dummy;
    kh_put(hs32, khs_ipsm_paths, hashKey, &dummy);
    return 1;
  }
}

/* Update the annotations of regions (i.e., state sequence received from the server) */
void update_region_annotations(struct queue_entry *q)
{
  u32 i = 0;

  for (i = 0; i < messages_sent; i++)
  {
    if ((response_bytes[i] == 0) || (i > 0 && (response_bytes[i] - response_bytes[i - 1] == 0)))
    {
      q->regions[i].state_sequence = NULL;
      q->regions[i].state_count = 0;
    }
    else
    {
      unsigned int state_count;
      q->regions[i].state_sequence = (*extract_response_codes)(response_buf, response_bytes[i], &state_count);
      q->regions[i].state_count = state_count;
    }
  }
}

/* Choose a region data for region-level mutations */
u8 *choose_source_region(u32 *out_len)
{
  u8 *out = NULL;
  *out_len = 0;
  struct queue_entry *q = queue;

  // randomly select a seed
  u32 index = UR(queued_paths);
  while (index != 0)
  {
    q = q->next;
    index--;
  }

  // randomly select a region in the selected seed
  if (q->region_count)
  {
    u32 reg_index = UR(q->region_count);
    u32 len = q->regions[reg_index].end_byte - q->regions[reg_index].start_byte + 1;
    if (len <= MAX_FILE)
    {
      out = (u8 *)ck_alloc(len);
      if (out == NULL)
        PFATAL("Unable allocate a memory region to store a region");
      *out_len = len;
      // Read region data into memory. */
      FILE *fp = fopen(q->fname, "rb");
      fseek(fp, q->regions[reg_index].start_byte, SEEK_CUR);
      fread(out, 1, len, fp);
      fclose(fp);
    }
  }

  return out;
}

/* Update #fuzzs visiting a specific state */
void update_fuzzs()
{
  unsigned int state_count, i, discard;
  unsigned int *state_sequence = (*extract_response_codes)(response_buf, response_buf_size, &state_count);

  // A hash set is used so that the #paths is not updated more than once for one specific state
  khash_t(hs32) * khs_state_ids;
  khint_t k;
  khs_state_ids = kh_init(hs32);

  for (i = 0; i < state_count; i++)
  {
    unsigned int state_id = state_sequence[i];

    if (kh_get(hs32, khs_state_ids, state_id) != kh_end(khs_state_ids))
    {
      continue;
    }
    else
    {
      kh_put(hs32, khs_state_ids, state_id, &discard);
      k = kh_get(hms, khms_states, state_id);
      if (k != kh_end(khms_states))
      {
        kh_val(khms_states, k)->fuzzs++;
      }
    }
  }
  ck_free(state_sequence);
  kh_destroy(hs32, khs_state_ids);
}

/* Return the index of the "region" containing a given value */
u32 index_search(u32 *A, u32 n, u32 val)
{
  u32 index = 0;
  for (index = 0; index < n; index++)
  {
    if (val <= A[index])
      break;
  }
  return index;
}

/* Calculate state scores and select the next state */
u32 update_scores_and_select_next_state(u8 mode)
{
  u32 result = 0, i;

  if (state_ids_count == 0)
    return 0;

  u32 *state_scores = NULL;
  state_scores = (u32 *)ck_alloc(state_ids_count * sizeof(u32));
  if (!state_scores)
    PFATAL("Cannot allocate memory for state_scores");

  khint_t k;
  state_info_t *state;
  // Update the states' score
  for (i = 0; i < state_ids_count; i++)
  {
    u32 state_id = state_ids[i];

    k = kh_get(hms, khms_states, state_id);
    if (k != kh_end(khms_states))
    {
      state = kh_val(khms_states, k);
      switch (mode)
      {
      case FAVOR:
      {
        double base = ceil(1000 * pow(2, -log10(log10(state->fuzzs + 1) * state->selected_times + 1)) * pow(2, log(state->paths_discovered + 1)));

        /* Fix 5: Frontier bonus for node discovery.
         *
         * Problem: hypothesis-guided mutations produce more valid protocol
         * sequences, which excels at discovering new state transitions (edges)
         * between known states but may under-explore "frontier" states —
         * states with few outgoing edges where new nodes are most likely
         * to be found.
         *
         * Solution: count outgoing edges for this state in the IPSM graph.
         * States with fewer outgoing edges get a multiplicative bonus,
         * biasing the weighted random selection toward frontier exploration.
         *
         *   out_degree 0-1  → ×4.0  (uncharted frontier, highest priority)
         *   out_degree 2-3  → ×2.0  (partially explored)
         *   out_degree 4+   → ×1.0  (well-explored, no bonus)
         */
        double frontier_bonus = 1.0;
        if (!ablation_no_frontier) {
          char sid_str[STATE_STR_LEN];
          snprintf(sid_str, STATE_STR_LEN, "%d", state_id);
          Agnode_t *nd = agnode(ipsm, sid_str, FALSE);
          if (nd) {
            int out_degree = 0;
            Agedge_t *e;
            for (e = agfstout(ipsm, nd); e; e = agnxtout(ipsm, e))
              out_degree++;
            if (out_degree <= 1)       frontier_bonus = 4.0;
            else if (out_degree <= 3)  frontier_bonus = 2.0;
            /* else: 1.0 (no bonus) */
          } else {
            /* State not yet in IPSM graph → maximum frontier bonus */
            frontier_bonus = 4.0;
          }

          /* Fix-19 revised: Acceptability penalty — softer to preserve
           * crash-finding in error states.  Three-tier logic:
           *
           * error_hint=1 (structural: 4xx/5xx, not yet proven productive)
           *   → frontier_bonus × 0.5   (was 0.25 — too aggressive, error
           *     states in SIP/FTP/SMTP are where parser crashes live)
           *
           * error_hint=0 (unknown, e.g. binary protocols) AND
           * behaviorally unproductive (selected≥30, productivity<0.005)
           *   → frontier_bonus × 0.7   (was 0.5 at selected≥20/prod<0.01
           *     — tightened criteria to avoid premature penalty)
           *
           * error_hint=2 (confirmed productive despite error code)
           *   → no penalty (full bonus preserved)
           */
          if (state->error_hint == 1) {
            frontier_bonus *= 0.5;
          } else if (state->error_hint == 0 &&
                     state->selected_times >= 30 &&
                     state->productivity < 0.005) {
            frontier_bonus *= 0.7;
          }
          /* error_hint == 2: confirmed productive → no penalty */
        }

        /* MQTT-only differential bonus:
         * States that repeatedly produce cross-broker divergence receive
         * additional weight, improving deep-path conversion of state edges. */
        if (mqtt_diff_feedback_enabled && protocol_name &&
            strcasecmp(protocol_name, "MQTT") == 0) {
          frontier_bonus *= mqtt_state_diff_bonus(state_id);
        }

        /* V3-4: Forwarding-state priority — PUBLISH response states
         * (type_nibble=3 → state_id in [12288,16384)) represent
         * forwarding activity.  A modest ×1.25 bonus encourages
         * more exploration of message-forwarding code paths
         * (subs__send, sub__messages_queue, send__publish). */
        if (protocol_name && strcasecmp(protocol_name, "MQTT") == 0 &&
            (state_id >> 12) == 3) {
          frontier_bonus *= 1.25;
        }

        state->score = (u32)(base * frontier_bonus);
        break;
      }
        // other cases are reserved
      }

      if (i == 0)
      {
        state_scores[i] = state->score;
      }
      else
      {
        state_scores[i] = state_scores[i - 1] + state->score;
      }
    }
  }

  u32 randV = UR(state_scores[state_ids_count - 1]);
  u32 idx = index_search(state_scores, state_ids_count, randV);
  result = state_ids[idx];

  if (state_scores)
    ck_free(state_scores);
  return result;
}

/* Select a target state at which we do state-aware fuzzing */
unsigned int choose_target_state(u8 mode)
{
  u32 result = 0;

  switch (mode)
  {
  case RANDOM_SELECTION: // Random state selection
    selected_state_index = UR(state_ids_count);
    result = state_ids[selected_state_index];
    break;
  case ROUND_ROBIN: // Round-robin state selection
    result = state_ids[selected_state_index];
    selected_state_index++;
    if (selected_state_index == state_ids_count)
      selected_state_index = 0;
    break;
  case FAVOR:
    /* Do ROUND_ROBIN for a few cycles to get enough statistical information*/
    if (state_cycles < 5)
    {
      result = state_ids[selected_state_index];
      selected_state_index++;
      if (selected_state_index == state_ids_count)
      {
        selected_state_index = 0;
        state_cycles++;
      }
      break;
    }

    result = update_scores_and_select_next_state(FAVOR);
    break;
  default:
    break;
  }

  return result;
}

/* Select a seed to exercise the target state */
struct queue_entry *choose_seed(u32 target_state_id, u8 mode)
{
  khint_t k;
  state_info_t *state;
  struct queue_entry *result = NULL;

  k = kh_get(hms, khms_states, target_state_id);
  if (k != kh_end(khms_states))
  {
    state = kh_val(khms_states, k);

    if (state->seeds_count == 0)
      return NULL;

    switch (mode)
    {
    case RANDOM_SELECTION: // Random seed selection
      state->selected_seed_index = UR(state->seeds_count);
      result = state->seeds[state->selected_seed_index];
      break;
    case ROUND_ROBIN: // Round-robin seed selection
      result = state->seeds[state->selected_seed_index];
      state->selected_seed_index++;
      if (state->selected_seed_index == state->seeds_count)
        state->selected_seed_index = 0;
      break;
    case FAVOR:
      if (state->seeds_count > 10)
      {
        // Do seed selection similar to AFL + take into account state-aware information
        // e.g., was_fuzzed information becomes state-aware
        u32 passed_cycles = 0;
        while (passed_cycles < 5)
        {
          result = state->seeds[state->selected_seed_index];
          if (state->selected_seed_index + 1 == state->seeds_count)
          {
            state->selected_seed_index = 0;
            passed_cycles++;
          }
          else
            state->selected_seed_index++;

          // Skip this seed with high probability if it is neither an initial seed nor a seed generated while the
          // current target_state_id was targeted
          if (result->generating_state_id != target_state_id && !result->is_initial_seed && UR(100) < 90)
            continue;

          u32 target_state_index = get_state_index(target_state_id);
          if (pending_favored)
          {
            /* If we have any favored, non-fuzzed new arrivals in the queue,
               possibly skip to them at the expense of already-fuzzed or non-favored
               cases. */
            if (((was_fuzzed_map[target_state_index][result->index] == 1) || !result->favored) && UR(100) < SKIP_TO_NEW_PROB)
              continue;

            /* Otherwise, this seed is selected */
            break;
          }
          else if (!result->favored && queued_paths > 10)
          {
            /* Otherwise, still possibly skip non-favored cases, albeit less often.
               The odds of skipping stuff are higher for already-fuzzed inputs and
               lower for never-fuzzed entries. */
            if (queue_cycle > 1 && (was_fuzzed_map[target_state_index][result->index] == 0))
            {
              if (UR(100) < SKIP_NFAV_NEW_PROB)
                continue;
            }
            else
            {
              if (UR(100) < SKIP_NFAV_OLD_PROB)
                continue;
            }

            /* Otherwise, this seed is selected */
            break;
          }
        }
      }
      else
      {
        // Do Round-robin if seeds_count of the selected state is small
        result = state->seeds[state->selected_seed_index];
        state->selected_seed_index++;
        if (state->selected_seed_index == state->seeds_count)
          state->selected_seed_index = 0;
      }
      break;
    default:
      break;
    }
  }
  else
  {
    PFATAL("AFLNet - the states hashtable has no entries for state %d", target_state_id);
  }

  return result;
}

static u64 get_cur_time(void);

/* Update state-aware variables */
void update_state_aware_variables(struct queue_entry *q, u8 dry_run)
{
  khint_t k;
  int discard, i;
  state_info_t *state;
  unsigned int state_count;

  if (!response_buf_size || !response_bytes)
    return;

  unsigned int *state_sequence = (*extract_response_codes)(response_buf, response_buf_size, &state_count);

  q->unique_state_count = get_unique_state_count(state_sequence, state_count);

  if (is_state_sequence_interesting(state_sequence, state_count))
  {
    // Save the current kl_messages to a file which can be used to replay the newly discovered paths on the ipsm
    u8 *temp_str = state_sequence_to_string(state_sequence, state_count);
    u8 *fname = alloc_printf("%s/replayable-new-ipsm-paths/id:%llu:%s:%s", out_dir, get_cur_time() / 1000, temp_str, dry_run ? basename(q->fname) : "new");
    save_kl_messages_to_file(kl_messages, fname, 1, messages_sent);
    ck_free(temp_str);
    ck_free(fname);

    u8 *responses_fname = alloc_printf("%s/responses-ipsm/id:%s", out_dir, basename(q->fname));
    save_responses_to_file(response_buf, response_buf_size, response_bytes, responses_fname, messages_sent);
    ck_free(responses_fname);

    // Update the IPSM graph
    if (state_count > 1)
    {
      unsigned int prevStateID = state_sequence[0];

      for (i = 1; i < state_count; i++)
      {
        unsigned int curStateID = state_sequence[i];
        char fromState[STATE_STR_LEN], toState[STATE_STR_LEN];
        snprintf(fromState, STATE_STR_LEN, "%d", prevStateID);
        snprintf(toState, STATE_STR_LEN, "%d", curStateID);

        // Check if the prevStateID and curStateID have been added to the state machine as vertices
        // Check also if the edge prevStateID->curStateID has been added
        Agnode_t *from, *to;
        Agedge_t *edge;
        from = agnode(ipsm, fromState, FALSE);
        if (!from)
        {
          // Add a node to the graph
          from = agnode(ipsm, fromState, TRUE);
          if (dry_run)
            agset(from, "color", "blue");
          else
            agset(from, "color", "red");

          // Insert this newly discovered state into the states hashtable
          state_info_t *newState_From = (state_info_t *)ck_alloc(sizeof(state_info_t));
          newState_From->id = prevStateID;
          newState_From->is_covered = 1;
          newState_From->paths = 0;
          newState_From->paths_discovered = 0;
          newState_From->selected_times = 0;
          newState_From->fuzzs = 0;
          newState_From->score = 1;
          newState_From->selected_seed_index = 0;
          newState_From->seeds = NULL;
          newState_From->seeds_count = 0;
          /* Fix-19: Initialize acceptability fields */
          newState_From->error_hint = classify_state_error_hint(prevStateID, protocol_name);
          newState_From->productivity = 0.0;

          k = kh_put(hms, khms_states, prevStateID, &discard);
          kh_value(khms_states, k) = newState_From;

          // Insert this into the state_ids array too
          state_ids = (u32 *)ck_realloc(state_ids, (state_ids_count + 1) * sizeof(u32));
          state_ids[state_ids_count++] = prevStateID;

          if (prevStateID != 0)
            expand_was_fuzzed_map(1, 0);
        }

        to = agnode(ipsm, toState, FALSE);
        if (!to)
        {
          // Add a node to the graph
          to = agnode(ipsm, toState, TRUE);
          if (dry_run)
            agset(to, "color", "blue");
          else
            agset(to, "color", "red");

          // Insert this newly discovered state into the states hashtable
          state_info_t *newState_To = (state_info_t *)ck_alloc(sizeof(state_info_t));
          newState_To->id = curStateID;
          newState_To->is_covered = 1;
          newState_To->paths = 0;
          newState_To->paths_discovered = 0;
          newState_To->selected_times = 0;
          newState_To->fuzzs = 0;
          newState_To->score = 1;
          newState_To->selected_seed_index = 0;
          newState_To->seeds = NULL;
          newState_To->seeds_count = 0;
          /* Fix-19: Initialize acceptability fields */
          newState_To->error_hint = classify_state_error_hint(curStateID, protocol_name);
          newState_To->productivity = 0.0;

          k = kh_put(hms, khms_states, curStateID, &discard);
          kh_value(khms_states, k) = newState_To;

          // Insert this into the state_ids array too
          state_ids = (u32 *)ck_realloc(state_ids, (state_ids_count + 1) * sizeof(u32));
          state_ids[state_ids_count++] = curStateID;

          if (curStateID != 0)
            expand_was_fuzzed_map(1, 0);
        }

        // Check if an edge from->to exists
        edge = agedge(ipsm, from, to, NULL, FALSE);
        if (!edge)
        {
          // Add an edge to the graph
          edge = agedge(ipsm, from, to, "new_edge", TRUE);
          if (dry_run)
            agset(edge, "color", "blue");
          else
            agset(edge, "color", "red");
        }

        // Update prevStateID
        prevStateID = curStateID;
      }
    }

    // Update the dot file
    s32 fd;
    u8 *tmp;
    tmp = alloc_printf("%s/ipsm.dot", out_dir);
    fd = open(tmp, O_WRONLY | O_CREAT, 0600);
    if (fd < 0)
    {
      PFATAL("Unable to create %s", tmp);
    }
    else
    {
      ipsm_dot_file = fdopen(fd, "w");
      agwrite(ipsm, ipsm_dot_file);
      close(fileno(ipsm_dot_file));
      ck_free(tmp);
    }
  }

  // Update others no matter the new seed leads to interesting state sequence or not

  // Annotate the regions
  update_region_annotations(q);

  // Update the states hashtable to keep the list of seeds which help us to reach a specific state
  // Iterate over the regions & their annotated state (sub)sequences and update the hashtable accordingly
  // All seed should "reach" state 0 (initial state) so we add this one to the map first
  k = kh_get(hms, khms_states, 0);
  if (k != kh_end(khms_states))
  {
    state = kh_val(khms_states, k);
    state->seeds = (void **)ck_realloc(state->seeds, (state->seeds_count + 1) * sizeof(void *));
    state->seeds[state->seeds_count] = (void *)q;
    state->seeds_count++;

    was_fuzzed_map[0][q->index] = 0; // Mark it as reachable but not fuzzed
  }
  else
  {
    PFATAL("AFLNet - the states hashtable should always contain an entry of the initial state");
  }

  // Now update other states
  for (i = 0; i < q->region_count; i++)
  {
    unsigned int regional_state_count = q->regions[i].state_count;
    if (regional_state_count > 0)
    {
      // reachable_state_id is the last ID in the state_sequence
      unsigned int reachable_state_id = q->regions[i].state_sequence[regional_state_count - 1];

      k = kh_get(hms, khms_states, reachable_state_id);
      if (k != kh_end(khms_states))
      {
        state = kh_val(khms_states, k);
        state->seeds = (void **)ck_realloc(state->seeds, (state->seeds_count + 1) * sizeof(void *));
        state->seeds[state->seeds_count] = (void *)q;
        state->seeds_count++;
      }
      else
      {
        // XXX. This branch is supposed to be not reachable
        // However, due to some undeterminism, new state could be seen during regions' annotating process
        // even though the state was not observed before
        // To completely fix this, we should fix all causes leading to potential undeterminism
        // For now, we just add the state into the hashtable

        state_info_t *newState = (state_info_t *)ck_alloc(sizeof(state_info_t));
        newState->id = reachable_state_id;
        newState->is_covered = 1;
        newState->paths = 0;
        newState->paths_discovered = 0;
        newState->selected_times = 0;
        newState->fuzzs = 0;
        newState->score = 1;
        newState->selected_seed_index = 0;
        newState->seeds = NULL;
        newState->seeds = (void **)ck_realloc(newState->seeds, sizeof(void *));
        newState->seeds[0] = (void *)q;
        newState->seeds_count = 1;
        /* Fix-19: Initialize acceptability fields */
        newState->error_hint = classify_state_error_hint(reachable_state_id, protocol_name);
        newState->productivity = 0.0;

        k = kh_put(hms, khms_states, reachable_state_id, &discard);
        kh_value(khms_states, k) = newState;

        // Insert this into the state_ids array too
        state_ids = (u32 *)ck_realloc(state_ids, (state_ids_count + 1) * sizeof(u32));
        state_ids[state_ids_count++] = reachable_state_id;

        if (reachable_state_id != 0)
          expand_was_fuzzed_map(1, 0);
      }

      was_fuzzed_map[get_state_index(reachable_state_id)][q->index] = 0; // Mark it as reachable but not fuzzed
    }
  }

  // Update the number of paths which have traversed a specific state
  // It can be used for calculating fuzzing energy
  // A hash set is used so that the #paths is not updated more than once for one specific state
  khash_t(hs32) * khs_state_ids;
  khs_state_ids = kh_init(hs32);

  for (i = 0; i < state_count; i++)
  {
    unsigned int state_id = state_sequence[i];

    if (kh_get(hs32, khs_state_ids, state_id) != kh_end(khs_state_ids))
    {
      continue;
    }
    else
    {
      kh_put(hs32, khs_state_ids, state_id, &discard);
      k = kh_get(hms, khms_states, state_id);
      if (k != kh_end(khms_states))
      {
        kh_val(khms_states, k)->paths++;
      }
    }
  }
  kh_destroy(hs32, khs_state_ids);

  // Update paths_discovered
  if (!dry_run)
  {
    k = kh_get(hms, khms_states, target_state_id);
    if (k != kh_end(khms_states))
    {
      kh_val(khms_states, k)->paths_discovered++;
    }
  }

  /* Fix-19: Update productivity and behavioral confirmation for all states.
   *
   * productivity = paths_discovered / (selected_times + 1.0)
   *   — cached here so FAVOR scoring can read it in O(1)
   *
   * Behavioral override logic (requires sufficient sample, selected_times >= 10):
   *   error_hint=1 AND productivity >= 0.1  →  promote to 2 (productive)
   *     e.g. FTP 550 that leads to interesting retry paths
   *   error_hint=0 AND productivity < 0.005 AND selected_times >= 30
   *     →  demote to 1 (behaviorally confirmed dead-end)
   *     e.g. MQTT PINGRESP (0xD0) that never produces new coverage
   */
  for (u32 si = 0; si < state_ids_count; si++)
  {
    k = kh_get(hms, khms_states, state_ids[si]);
    if (k != kh_end(khms_states))
    {
      state_info_t *st = kh_val(khms_states, k);
      st->productivity = (double)st->paths_discovered / (st->selected_times + 1.0);

      if (st->selected_times >= 10)
      {
        /* Promotion: structural error hint but actually productive */
        if (st->error_hint == 1 && st->productivity >= 0.1)
        {
          st->error_hint = 2;  /* confirmed productive, remove penalty */
          fprintf(stderr,
                  "[fix-19] State %u promoted: error_hint 1->2 (productivity=%.3f)\n",
                  st->id, st->productivity);
        }
      }
      if (st->selected_times >= 30)
      {
        /* Demotion: unknown protocol state but behaviorally dead */
        if (st->error_hint == 0 && st->productivity < 0.005)
        {
          st->error_hint = 1;  /* behaviorally confirmed unproductive */
          fprintf(stderr,
                  "[fix-19] State %u demoted: error_hint 0->1 (productivity=%.4f, sel=%u)\n",
                  st->id, st->productivity, st->selected_times);
        }
      }
    }
  }

  // Free state sequence
  if (state_sequence)
    ck_free(state_sequence);
}

/* ── MQTT remaining_length fixer ──────────────────────────────────────
 *
 * After AFL's byte-level mutations, the MQTT remaining_length field
 * inside each packet may be inconsistent with the actual body length.
 * This causes the broker to reject or misparsee the packet, wasting
 * the execution.
 *
 * mqtt_fix_message_length() is called on each individual message_t
 * (already split by extract_requests_mqtt) BEFORE net_send().
 * It re-encodes remaining_length so it matches the actual body size.
 *
 * Activation: only when protocol is MQTT.
 *   - Default: ON for MQTT.
 *   - Override: CHATAFL_MQTT_FIX_LENGTH=0 to disable.
 *
 * Protocol isolation: this function is never called for non-MQTT
 * protocols; the call site is guarded by mqtt_fix_length_enabled.
 * ──────────────────────────────────────────────────────────────────── */
static u8 mqtt_fix_length_enabled = 0;  /* set once at startup */

/* Encode MQTT variable-length integer into out[].  Returns number of
 * bytes written (1–4), or 0 on overflow (value > 268435455). */
static u32 mqtt_encode_remaining_length(u32 value, u8 *out) {
  u32 i = 0;
  do {
    u8 byte = (u8)(value % 128);
    value /= 128;
    if (value > 0) byte |= 0x80;
    out[i++] = byte;
  } while (value > 0 && i < 4);
  return (value == 0) ? i : 0;
}

/* Decode MQTT variable-length integer starting at buf[1..].
 * Returns bytes consumed (1–4) or 0 on error.
 * *out_len receives the decoded value. */
static u32 mqtt_decode_remaining_length(const u8 *buf, u32 buf_size,
                                        u32 *out_len) {
  u32 multiplier = 1, value = 0, pos = 1; /* skip fixed header byte 0 */
  for (u32 i = 0; i < 4; i++) {
    if (pos >= buf_size) return 0;
    u8 encoded = buf[pos++];
    value += (encoded & 0x7F) * multiplier;
    if ((encoded & 0x80) == 0) { *out_len = value; return pos - 1; }
    multiplier *= 128;
  }
  return 0;
}

/* Fix remaining_length in message m (in-place, may reallocate m->mdata).
 * Only operates on messages ≥ 2 bytes with a valid type nibble (1–15). */
static void mqtt_fix_message_length(message_t *m) {
  if (!m || !m->mdata || m->msize < 2) return;

  u8 type_nibble = ((u8)m->mdata[0] >> 4) & 0x0F;
  if (type_nibble < 1 || type_nibble > 15) return;

  /* Decode current remaining_length */
  u32 cur_rem_len = 0;
  u32 rl_bytes = mqtt_decode_remaining_length((u8 *)m->mdata, m->msize,
                                              &cur_rem_len);
  if (rl_bytes == 0) return;  /* can't parse → leave untouched */

  u32 header_size = 1 + rl_bytes;  /* fixed header byte + RL encoding */
  u32 body_size = m->msize - header_size;

  /* If remaining_length already matches, nothing to do */
  if (cur_rem_len == body_size) return;

  /* Re-encode with correct body_size */
  u8 new_rl[4];
  u32 new_rl_bytes = mqtt_encode_remaining_length(body_size, new_rl);
  if (new_rl_bytes == 0) return;  /* overflow → leave untouched */

  u32 new_header_size = 1 + new_rl_bytes;
  u32 new_total = new_header_size + body_size;

  if (new_rl_bytes != rl_bytes) {
    /* Avoid reallocating the message buffer here: the message ownership
     * is shared across multiple execution paths and reallocation can
     * interfere with later cleanup on malformed packets.  When the
     * encoded length width changes, skip the fix safely. */
    return;
  }

  /* Same encoding size → patch in place only. */
  (void)new_header_size;
  (void)new_total;
  memcpy(m->mdata + 1, new_rl, new_rl_bytes);
}

/* Send (mutated) messages in order to the server under test */
int send_over_network()
{
  int n;
  u8 likely_buggy = 0;
  struct sockaddr_in serv_addr;
  struct sockaddr_in local_serv_addr;

  // Clean up the server if needed
  // (Skip in persistent mode — server state is preserved across execs.)
  if (cleanup_script && !mqtt_persistent_skip_kill)
    system(cleanup_script);

  // Wait a bit for the server initialization
  // A1-fix: Use adaptive wait — full sleep only on first exec or after
  // connect failure; 0 after first successful connect (forking servers
  // are ready instantly after the first fork).
  // (Skip in persistent mode — server is already fully initialized.)
  if (mqtt_persistent_skip_kill) {
    /* no wait — server is alive from previous exec */
  } else {
    if (!server_warmed_up)
      adaptive_wait_usecs = server_wait_usecs;  /* cold start: full 10 ms */
    usleep(adaptive_wait_usecs);
  }

  // Clear the response buffer and reset the response buffer size
  if (response_buf)
  {
    ck_free(response_buf);
    response_buf = NULL;
    response_buf_size = 0;
  }

  if (response_bytes)
  {
    ck_free(response_bytes);
    response_bytes = NULL;
  }

  /* ── Multi-Party Driver Skeleton ─────────────────────────────────────
   *
   * Generic multi-connection mode driven by mp_driver_t (mp-driver.h).
   * The skeleton is protocol-agnostic; all protocol-specific logic lives
   * in the driver callbacks (e.g., mp-driver-mqtt.c).
   *
   * Flow: look up driver → open N fds → handshake → route messages →
   *       drain → cleanup → close.  If no driver exists or any setup
   *       step fails, fall through to the original single-fd path.
   *
   * Open-Closed: the single-fd text protocol path below is completely
   * untouched.  New protocols add a driver .c file and register it in
   * mp_driver_for_protocol() — send_over_network() never changes.
   * ─────────────────────────────────────────────────────────────────── */

  int sockfd = -1;
  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = socket_timeout_usecs;
  kliter_t(lms) *it;
  messages_sent = 0;

  const mp_driver_t *mp_drv = mp_driver_for_protocol(protocol_name);

  if (mp_drv && net_protocol == PRO_TCP)
  {
    /* MQTT multi-broker MAIN architecture:
     * If CHATAFL_MQTT_BROKERS has >=2 endpoints, replay the test case on
     * all brokers, collect per-broker signatures, and derive differential
     * signal from the main execution path.
     *
     * O1-fix: Throttled by mqtt_diff_probe_period (default 8).  Between
     * probes we skip to the generic multi-fd path (single broker, 3 fds)
     * to maintain throughput.  The period controls the tradeoff between
     * diff signal freshness and exec/sec.  The cached diff signal decays
     * by 0.95× per non-probe exec so its influence fades gracefully.
     *
     * SAFETY: Skip during dry run (queue_cycle == 0) — partner container
     * may not be ready. */
    if (protocol_name && strcasecmp(protocol_name, "MQTT") == 0
        && queue_cycle > 0) {

      /* O1-fix: Throttle multi-broker exec by probe period */
      u8 do_multi_broker_exec = 1;
      if (mqtt_diff_probe_period > 1) {
        if (total_execs > 0 && mqtt_diff_last_probe_exec > 0 &&
            (total_execs - mqtt_diff_last_probe_exec) < mqtt_diff_probe_period) {
          do_multi_broker_exec = 0;
          mqtt_last_diff_signal *= 0.98;  /* V6: slower decay keeps signal alive */
        } else {
          mqtt_diff_last_probe_exec = total_execs;
        }
      }

      mqtt_broker_endpoint_t *eps = NULL;
      u32 ecnt = 0;
      if (do_multi_broker_exec && mqtt_collect_exec_brokers(&eps, &ecnt)) {
        char **sigs = (char **)ck_alloc(ecnt * sizeof(char *));
        memset(sigs, 0, ecnt * sizeof(char *));

        /* O2: Per-broker forward-diff hashes */
        u32 *fwd_hashes = (u32 *)ck_alloc(ecnt * sizeof(u32));
        memset(fwd_hashes, 0, ecnt * sizeof(u32));

        u8 primary_likely_buggy = 0;
        int primary_rc = mqtt_exec_one_broker_mp(
            mp_drv, (const char *)eps[0].ip, eps[0].port,
            1, &sigs[0], &primary_likely_buggy, &fwd_hashes[0]);

        if (primary_rc != 0) {
          mp_multi_fallback++;
          for (u32 i = 0; i < ecnt; i++) if (sigs[i]) ck_free(sigs[i]);
          ck_free(sigs);
          ck_free(fwd_hashes);
          for (u32 i = 0; i < ecnt; i++) if (eps[i].ip) free(eps[i].ip);
          ck_free(eps);
          /* Reset response state corrupted by the failed primary execution.
           * Without this, the single-fd fallback path appends to stale
           * response_buf data and response_bytes indices become inconsistent,
           * leading to out-of-bounds access in downstream analysis code. */
          if (response_buf) { ck_free(response_buf); response_buf = NULL; }
          response_buf_size = 0;
          if (response_bytes) { ck_free(response_bytes); response_bytes = NULL; }
          messages_sent = 0;
          goto MP_SINGLE_FD_FALLBACK;
        }

        likely_buggy = primary_likely_buggy;

        /* A1: multi-broker primary connected — zero the wait */
        server_warmed_up = 1;
        adaptive_wait_usecs = 0;

        for (u32 i = 1; i < ecnt; i++) {
          /* M4-fix: Check secondary broker return value instead of
           * silently discarding it.  A non-zero return means the
           * secondary broker may have crashed or refused connection. */
          int sec_rc = mqtt_exec_one_broker_mp(mp_drv,
                                        (const char *)eps[i].ip,
                                        eps[i].port,
                                        0,
                                        &sigs[i],
                                        NULL,
                                        &fwd_hashes[i]);
          if (sec_rc != 0) {
            fprintf(stderr, "[M4-warn] Secondary broker %s:%u exec failed "
                    "(rc=%d) — possible crash\n",
                    eps[i].ip ? (char *)eps[i].ip : "?", eps[i].port, sec_rc);
          }
          if (!sigs[i])
            sigs[i] = ck_strdup((u8 *)"exec-failed");
        }

        mqtt_set_cluster_summary_from_signatures(eps, sigs, ecnt);

        /* O2: Forward-differential signal — compare fwd_hashes across brokers.
         * If any broker's forwarding fingerprint differs, this indicates a
         * message routing / QoS / retain divergence in the broker's
         * subs__send() / sub__messages_queue() code paths. */
        if (ecnt >= 2 && mqtt_diff_feedback_enabled) {
          u8 fwd_diverged = 0;
          for (u32 i = 1; i < ecnt; i++) {
            if (fwd_hashes[i] != fwd_hashes[0]) {
              fwd_diverged = 1;
              break;
            }
          }
          if (fwd_diverged) {
            /* Boost diff signal — forwarding divergence is high-value */
            if (mqtt_last_diff_signal < 0.8)
              mqtt_last_diff_signal = 0.8;
            mqtt_diff_fwd_divergences++;

            /* V6-Fix-1: Bridge fwd_hash divergence → field_diff.
             *
             * Root cause (Apr-16 analysis): Both brokers are the SAME
             * implementation, so field-level analysis (type/code/payload)
             * always returns MQTT_DIV_NONE.  But fwd_hash DOES diverge
             * due to non-deterministic broker behavior (timing, session
             * state, QoS retransmission, message ordering).
             *
             * Without this bridge, mqtt_diff_score = 0 for ALL queue
             * entries → P5 energy multiplier never fires → P5/P6
             * differential feedback is completely dead.
             *
             * Fix: When fwd_hash diverges but field-level found nothing,
             * synthesize a MQTT_DIV_PAYLOAD result (lowest severity).
             * This yields diff_score = 10 + 30*0.3 = 19 → ×2 energy
             * in calculate_score(), activating the differential chain.
             *
             * This is semantically correct: fwd_hash divergence means
             * the broker's internal message routing (subs__send,
             * sub__messages_queue) behaved differently across runs,
             * exercising non-deterministic code paths worth exploring. */
            if (mqtt_last_field_diff.severity == MQTT_DIV_NONE ||
                !mqtt_last_field_diff_valid) {
              mqtt_last_field_diff.severity = MQTT_DIV_PAYLOAD;
              mqtt_last_field_diff.strength = 0.3;
              mqtt_last_field_diff.pattern_hash =
                  fwd_hashes[0] ^ (ecnt > 1 ? fwd_hashes[1] : 0);
              mqtt_last_field_diff_valid = 1;
              mqtt_diff_payload_divergences++;  /* count as payload-level */
            }

            /* D4: Save structured differential report */
            char fwd_detail[256];
            snprintf(fwd_detail, sizeof(fwd_detail),
                     "fwd_hash[0]=0x%08x vs fwd_hash[1]=0x%08x (brokers=%u)",
                     fwd_hashes[0], ecnt > 1 ? fwd_hashes[1] : 0, ecnt);
            mqtt_save_diff_report("fwd_divergence", fwd_detail,
                                  eps, ecnt, fwd_hashes);
          }
        }

        /* D4: Signature-level divergence report (covers CONNACK/SUBACK/etc.) */
        if (ecnt >= 2 && mqtt_cluster_diverged && sigs[0] && sigs[1]) {
          char sig_detail[512];
          snprintf(sig_detail, sizeof(sig_detail),
                   "sig[0]=\"%.200s\" vs sig[1]=\"%.200s\"",
                   (char *)sigs[0], (char *)sigs[1]);
          mqtt_save_diff_report("sig_divergence", sig_detail,
                                eps, ecnt, fwd_hashes);
        }

        if (!mqtt_cluster_probe_logged) {
          fprintf(stderr, "[mqtt-cluster-main] brokers=%u unique=%u diverged=%u\n",
                  mqtt_cluster_broker_count,
                  mqtt_cluster_unique_signatures,
                  mqtt_cluster_diverged);
          mqtt_cluster_probe_logged = 1;
        }

        /* H3-fix: Stabilization loop with SHM sync.
         * The old loop was a NO-OP: has_new_bits() destructively clears
         * virgin bits on the 1st call, so the 2nd call always returns 0
         * (no new bits) because trace_bits hasn't changed — there's no
         * usleep to let the server update shared memory.  Fix: sleep
         * 200 µs per iteration + memory barrier so the kernel/CPU
         * propagates SHM writes from the child.  50 × 200 µs = 10 ms
         * max — sufficient for MQTT async PUBLISH forwarding. */
        memset(session_virgin_bits, 255, MAP_SIZE);
        {
          int stab_iter = 0;
          while (stab_iter++ < 50) {
            usleep(200);
            __sync_synchronize();
            if (has_new_bits(session_virgin_bits) != 2)
              break;
          }
        }

        for (u32 i = 0; i < ecnt; i++) {
          if (sigs[i]) ck_free(sigs[i]);
          if (eps[i].ip) free(eps[i].ip);
        }
        ck_free(sigs);
        ck_free(fwd_hashes);
        ck_free(eps);

        mp_multi_ok++;
        sockfd = -1;
        goto MP_MULTI_DONE;
      }
    }

    /* ── Generic multi-fd path via driver callbacks ── */
    int *mp_fds_buf = NULL;
    mp_context_t mp_ctx;
    memset(&mp_ctx, 0, sizeof(mp_ctx));
    if (!mp_drv || mp_drv->fd_count <= 0 || mp_drv->fd_count > 64) {
      mp_multi_fallback++;
      goto MP_SINGLE_FD_FALLBACK;
    }

    mp_fds_buf = (int *)ck_alloc((u32)mp_drv->fd_count * sizeof(int));
    mp_ctx.fds              = mp_fds_buf;
    mp_ctx.fd_count         = mp_drv->fd_count;
    mp_ctx.timeout          = timeout;
    mp_ctx.poll_wait_msecs  = poll_wait_msecs;
    mp_ctx.server_ip        = (const char *)net_ip;
    mp_ctx.server_port      = net_port;
    mp_ctx.response_buf     = &response_buf;
    mp_ctx.response_buf_size = &response_buf_size;
    mp_ctx.priv             = NULL;

    for (int i = 0; i < mp_ctx.fd_count; i++)
      mp_ctx.fds[i] = -1;

    /* Step 1: Open connections */
    if (mp_drv->open_connections(&mp_ctx) != 0) {
      mp_multi_fallback++;
      for (int i = 0; i < mp_ctx.fd_count; i++)
        if (mp_ctx.fds[i] >= 0) close(mp_ctx.fds[i]);
      goto MP_SINGLE_FD_FALLBACK;
    }

    /* A1: multi-fd connected — zero the wait for subsequent execs */
    server_warmed_up = 1;
    adaptive_wait_usecs = 0;

    /* Step 2: Protocol-level handshake */
    if (mp_drv->handshake(&mp_ctx) != 0) {
      mp_multi_hshake_fail++;
      goto MP_MULTI_CLEANUP;
    }

    /* Step 3: Route each message from the mutated queue */
    for (it = kl_begin(kl_messages); it != kl_end(kl_messages); it = kl_next(it))
    {
      message_t *m = kl_val(it);

      if (!m || !m->mdata || m->msize == 0) {
        messages_sent++;
        response_bytes = (u32 *)ck_realloc(response_bytes, messages_sent * sizeof(u32));
        response_bytes[messages_sent - 1] = response_buf_size;
        continue;
      }

      int role = mp_drv->role_for_message(&mp_ctx,
                                          (const unsigned char *)m->mdata,
                                          m->msize);
      if (role < 0) {
        /* Driver says skip this message (e.g. CONNECT/DISCONNECT) */
        messages_sent++;
        response_bytes = (u32 *)ck_realloc(response_bytes, messages_sent * sizeof(u32));
        response_bytes[messages_sent - 1] = response_buf_size;
        continue;
      }

      if (role >= mp_ctx.fd_count) {
        messages_sent++;
        response_bytes = (u32 *)ck_realloc(response_bytes, messages_sent * sizeof(u32));
        response_bytes[messages_sent - 1] = response_buf_size;
        continue;
      }

      int target_fd = mp_ctx.fds[role];
      if (target_fd < 0) {
        messages_sent++;
        response_bytes = (u32 *)ck_realloc(response_bytes, messages_sent * sizeof(u32));
        response_bytes[messages_sent - 1] = response_buf_size;
        continue;
      }

      /* MQTT: fix remaining_length before sending */
      if (mqtt_fix_length_enabled) mqtt_fix_message_length(m);

      n = net_send(target_fd, timeout, m->mdata, m->msize);
      messages_sent++;
      response_bytes = (u32 *)ck_realloc(response_bytes, messages_sent * sizeof(u32));

      if (n != (int)m->msize) {
        response_bytes[messages_sent - 1] = response_buf_size;
        goto MP_MULTI_CLEANUP;
      }

      /* Collect response from the target fd */
      u32 prev_buf_size = response_buf_size;
      net_recv(target_fd, timeout, poll_wait_msecs, &response_buf, &response_buf_size);

      /* Let the driver drain other fds if needed (e.g. forwarded msgs) */
      if (mp_drv->after_send(&mp_ctx, role) != 0)
        goto MP_MULTI_CLEANUP;

      response_bytes[messages_sent - 1] = response_buf_size;

      if ((u32)prev_buf_size == (u32)response_buf_size)
        likely_buggy = 1;
      else
        likely_buggy = 0;
    }

MP_MULTI_CLEANUP:
    /* Final drain of all fds */
    mp_drv->drain_all(&mp_ctx);

    if (messages_sent > 0 && response_bytes != NULL)
      response_bytes[messages_sent - 1] = response_buf_size;

    /* Protocol-specific cleanup (disconnect, free priv, post-processing) */
    mp_drv->cleanup(&mp_ctx);

    /* Post-cleanup: protocol-specific probes that live in afl-fuzz.c
     * (static functions, cannot be called from the driver .c file) */
    if (protocol_name && strcasecmp(protocol_name, "MQTT") == 0)
      mqtt_probe_cluster_differences();
    else
      reset_mqtt_cluster_diff_summary();

    /* H3-fix: Stabilization loop with SHM sync (generic multi-fd path).
     * See H3-fix comment in multi-broker path for rationale. */
    memset(session_virgin_bits, 255, MAP_SIZE);
    {
      int stab_iter = 0;
      while (stab_iter++ < 50) {
        usleep(200);
        __sync_synchronize();
        if (has_new_bits(session_virgin_bits) != 2)
          break;
      }
    }

    /* Close all fds */
    for (int i = 0; i < mp_ctx.fd_count; i++)
      if (mp_ctx.fds[i] >= 0) close(mp_ctx.fds[i]);

    if (mp_fds_buf)
      ck_free(mp_fds_buf);

    mp_multi_ok++;
    sockfd = -1;
    goto MP_MULTI_DONE;
  }

MP_SINGLE_FD_FALLBACK:

  /* Defensive reset: any multi-fd path that jumped here may have partially
   * written to the global response buffers.  Zero everything so the
   * single-fd path starts from a clean slate. */
  if (response_buf)  { ck_free(response_buf);  response_buf = NULL; }
  response_buf_size = 0;
  if (response_bytes) { ck_free(response_bytes); response_bytes = NULL; }
  messages_sent = 0;

  /* ── Original single-fd path (ALL text protocols + MQTT fallback) ── */
  {
    if (net_protocol == PRO_TCP)
      sockfd = socket(AF_INET, SOCK_STREAM, 0);
    else if (net_protocol == PRO_UDP)
      sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sockfd < 0)
    {
      PFATAL("Cannot create a socket");
    }

    // Set timeout for socket data sending/receiving -- otherwise it causes a big delay
    // if the server is still alive after processing all the requests
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

    /* MQTT: disable Nagle algorithm — MQTT packets are small (4–128 bytes)
     * and Nagle's 200 ms batching delay kills throughput.  TCP_NODELAY
     * sends each write() immediately.  MQTT-only: text protocols may
     * benefit from Nagle batching for multi-line commands. */
    if (protocol_name && strcasecmp(protocol_name, "MQTT") == 0) {
      int tcp_nodelay_flag = 1;
      setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY,
                 &tcp_nodelay_flag, sizeof(tcp_nodelay_flag));
      /* SO_LINGER with linger=0: close() sends RST immediately instead
       * of going through TIME_WAIT.  This ensures the forked broker
       * child receives an immediate connection-closed signal, reducing
       * non-determinism from lingering TCP state. */
      struct linger lg = {1, 0};
      setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
    }

    memset(&serv_addr, '0', sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(net_port);
    serv_addr.sin_addr.s_addr = inet_addr(net_ip);

    // This piece of code is only used for targets that send responses to a specific port number
    // The Kamailio SIP server is an example. After running this code, the intialized sockfd
    // will be bound to the given local port
    if (local_port > 0)
    {
      local_serv_addr.sin_family = AF_INET;
      local_serv_addr.sin_addr.s_addr = INADDR_ANY;
      local_serv_addr.sin_port = htons(local_port);

      local_serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
      if (bind(sockfd, (struct sockaddr *)&local_serv_addr, sizeof(struct sockaddr_in)))
      {
        FATAL("Unable to bind socket on local source port");
      }
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
      /* Retry connect — MQTT on localhost via forkserver is ready within
       * a few ms; 100 retries × 1 ms = 100 ms is ample.  Text protocols
       * keep the original 1000 × 1 ms = 1 s for slower servers. */
      int retry_limit = (protocol_name
                         && strcasecmp(protocol_name, "MQTT") == 0)
                        ? 100 : 1000;
      for (n = 0; n < retry_limit; n++)
      {
        if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0)
          break;
        usleep(1000);
      }
      if (n == retry_limit)
      {
        close(sockfd);
        /* A1-fix: connect failed after retries — reset adaptive wait
         * so next exec gets the full server_wait_usecs delay. */
        adaptive_wait_usecs = server_wait_usecs;
        server_warmed_up = 0;
        return 1;
      }
    }

    /* A1-fix: Successful connect — server is forking normally.
     * Skip the initial delay on subsequent executions. */
    server_warmed_up = 1;
    adaptive_wait_usecs = 0;

    // retrieve early server response if needed
    if (net_recv(sockfd, timeout, poll_wait_msecs, &response_buf, &response_buf_size))
      goto HANDLE_RESPONSES;

    // write the request messages
    for (it = kl_begin(kl_messages); it != kl_end(kl_messages); it = kl_next(it))
    {
      message_t *m = kl_val(it);
      if (!m || !m->mdata || m->msize == 0) {
        messages_sent++;
        response_bytes = (u32 *)ck_realloc(response_bytes, messages_sent * sizeof(u32));
        response_bytes[messages_sent - 1] = response_buf_size;
        continue;
      }

      /* MQTT: fix remaining_length before sending */
      if (mqtt_fix_length_enabled) mqtt_fix_message_length(m);

      n = net_send(sockfd, timeout, m->mdata, m->msize);
      messages_sent++;

      // Allocate memory to store new accumulated response buffer size
      response_bytes = (u32 *)ck_realloc(response_bytes, messages_sent * sizeof(u32));

      // Jump out if something wrong leading to incomplete message sent
      if (n != m->msize)
      {
        goto HANDLE_RESPONSES;
      }

      // retrieve server response
      u32 prev_buf_size = response_buf_size;
      if (net_recv(sockfd, timeout, poll_wait_msecs, &response_buf, &response_buf_size))
      {
        goto HANDLE_RESPONSES;
      }

      // Update accumulated response buffer size
      response_bytes[messages_sent - 1] = response_buf_size;

      // set likely_buggy flag if AFLNet does not receive any feedback from the server
      // it could be a signal of a potentiall server crash, like the case of CVE-2019-7314
      if (prev_buf_size == response_buf_size)
        likely_buggy = 1;
      else
        likely_buggy = 0;
    }

HANDLE_RESPONSES:

    net_recv(sockfd, timeout, poll_wait_msecs, &response_buf, &response_buf_size);

    if (messages_sent > 0 && response_bytes != NULL)
    {
      response_bytes[messages_sent - 1] = response_buf_size;
    }

    if (protocol_name && strcasecmp(protocol_name, "MQTT") == 0)
    {
      mqtt_probe_cluster_differences();
    }
    else
    {
      reset_mqtt_cluster_diff_summary();
    }

    /* H3-fix: Stabilization loop with SHM sync (single-fd fallback path).
     * Reduced from 50 × 200 µs = 10 ms to 15 × 200 µs = 3 ms.
     * On localhost, SHM updates propagate within 1–2 iterations;
     * 3 ms is ample headroom while saving ~7 ms/exec. */
    memset(session_virgin_bits, 255, MAP_SIZE);
    {
      int stab_iter = 0;
      while (stab_iter++ < 15) {
        usleep(200);
        __sync_synchronize();
        if (has_new_bits(session_virgin_bits) != 2)
          break;
      }
    }

    close(sockfd);
    sockfd = -1;
  } /* end single-fd block */

MP_MULTI_DONE:
  (void)0;  /* label requires a statement */

  /* H6-fix: For MQTT multi-fd paths, do NOT skip the kill/reap block
   * when likely_buggy is set — the multi-broker process lifecycle
   * requires proper SIGTERM → SIGKILL escalation to avoid zombies
   * and ensure coverage bitmaps are flushed.
   * Text protocols keep the original early-return (no regression). */
  if (likely_buggy && false_negative_reduction
      && !(protocol_name && strcasecmp(protocol_name, "MQTT") == 0))
    return 0;

  /* MQTT Persistent Mode: skip the entire SIGTERM → kill → waitpid
   * section.  The child stays alive for the next exec.  run_target()
   * will reuse it via the persistent reuse path. */
  if (mqtt_persistent_skip_kill)
    return 0;

  child_force_killed = 0;  /* Fix-14a: reset before each termination attempt */

  if (terminate_child && (child_pid > 0))
    kill(child_pid, SIGTERM);

  /* Fix-14: Bounded process-termination wait with SIGKILL escalation.
   *
   * Original: unbounded while(1) busy-polling kill(pid, 0) at 100% CPU.
   *
   * Problem: after SIGTERM, forking servers need to signal and reap their
   * child processes, then run ASAN destructors — this can take 0.5–1+
   * second while the fuzzer wastes CPU in a tight spin loop.
   *
   * Fix: poll every 200 µs instead of busy-spinning, and escalate to
   * SIGKILL after 50 ms.  The 50 ms grace period is generous for
   * graceful shutdown; any server still alive at that point is stuck in
   * teardown, not in a crash-reportable state.  For non-forking servers
   * the process is already gone by the first check, so this is a no-op. */
  {
    /* H2-fix: MQTT — mosquitto exits in <5 ms after SIGTERM; 30 ms
     * (150 × 200 µs) is 6× that, ample for edge cases.
     * Previous 100 ms wasted ~70 ms/exec.  Text protocols keep 200 ms. */
    int kill_limit = (protocol_name
                      && strcasecmp(protocol_name, "MQTT") == 0)
                     ? 150     /* 150 × 200 µs = 30 ms */
                     : 1000;   /* 1000 × 200 µs = 200 ms */
    int kill_wait = 0;
    while (1)
    {
      int kstat = kill(child_pid, 0);
      if ((kstat != 0) && (errno == ESRCH))
        break;
      if (++kill_wait >= kill_limit) {
        kill(child_pid, SIGKILL);
        child_force_killed = 1;          /* Fix-14a: tell run_target() this is not a crash */
        usleep(1000);                    /* 1 ms for kernel cleanup */
        break;
      }
      usleep(200);
    }
  }

  return 0;
}
/* End of AFLNet-specific variables & functions */

/* Get unix time in milliseconds */

static u64 get_cur_time(void)
{

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);
}

/* Get unix time in microseconds */

static u64 get_cur_time_us(void)
{

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000000ULL) + tv.tv_usec;
}

/* Generate a random number (from 0 to limit - 1). This may
   have slight bias. */

static inline u32 UR(u32 limit)
{

  if (unlikely(!rand_cnt--))
  {

    u32 seed[2];

    ck_read(dev_urandom_fd, &seed, sizeof(seed), "/dev/urandom");

    srandom(seed[0]);
    rand_cnt = (RESEED_RNG / 2) + (seed[1] % RESEED_RNG);
  }

  return random() % limit;
}

/* Shuffle an array of pointers. Might be slightly biased. */

static void shuffle_ptrs(void **ptrs, u32 cnt)
{

  u32 i;

  for (i = 0; i < cnt - 2; i++)
  {

    u32 j = i + UR(cnt - i);
    void *s = ptrs[i];
    ptrs[i] = ptrs[j];
    ptrs[j] = s;
  }
}

#ifdef HAVE_AFFINITY

/* Build a list of processes bound to specific cores. Returns -1 if nothing
   can be found. Assumes an upper bound of 4k CPUs. */

static void bind_to_free_cpu(void)
{

  DIR *d;
  struct dirent *de;
  cpu_set_t c;

  u8 cpu_used[4096] = {0};
  u32 i;

  if (cpu_core_count < 2)
    return;

  if (getenv("AFL_NO_AFFINITY"))
  {

    WARNF("Not binding to a CPU core (AFL_NO_AFFINITY set).");
    return;
  }

  d = opendir("/proc");

  if (!d)
  {

    WARNF("Unable to access /proc - can't scan for free CPU cores.");
    return;
  }

  ACTF("Checking CPU core loadout...");

  /* Introduce some jitter, in case multiple AFL tasks are doing the same
     thing at the same time... */

  usleep(R(1000) * 250);

  /* Scan all /proc/<pid>/status entries, checking for Cpus_allowed_list.
     Flag all processes bound to a specific CPU using cpu_used[]. This will
     fail for some exotic binding setups, but is likely good enough in almost
     all real-world use cases. */

  while ((de = readdir(d)))
  {

    u8 *fn;
    FILE *f;
    u8 tmp[MAX_LINE];
    u8 has_vmsize = 0;

    if (!isdigit(de->d_name[0]))
      continue;

    fn = alloc_printf("/proc/%s/status", de->d_name);

    if (!(f = fopen(fn, "r")))
    {
      ck_free(fn);
      continue;
    }

    while (fgets(tmp, MAX_LINE, f))
    {

      u32 hval;

      /* Processes without VmSize are probably kernel tasks. */

      if (!strncmp(tmp, "VmSize:\t", 8))
        has_vmsize = 1;

      if (!strncmp(tmp, "Cpus_allowed_list:\t", 19) &&
          !strchr(tmp, '-') && !strchr(tmp, ',') &&
          sscanf(tmp + 19, "%u", &hval) == 1 && hval < sizeof(cpu_used) &&
          has_vmsize)
      {

        cpu_used[hval] = 1;
        break;
      }
    }

    ck_free(fn);
    fclose(f);
  }

  closedir(d);

  for (i = 0; i < cpu_core_count; i++)
    if (!cpu_used[i])
      break;

  if (i == cpu_core_count)
  {

    SAYF("\n" cLRD "[-] " cRST
         "Uh-oh, looks like all %u CPU cores on your system are allocated to\n"
         "    other instances of afl-fuzz (or similar CPU-locked tasks). Starting\n"
         "    another fuzzer on this machine is probably a bad plan, but if you are\n"
         "    absolutely sure, you can set AFL_NO_AFFINITY and try again.\n",
         cpu_core_count);

    FATAL("No more free CPU cores");
  }

  OKF("Found a free CPU core, binding to #%u.", i);

  cpu_aff = i;

  CPU_ZERO(&c);
  CPU_SET(i, &c);

  if (sched_setaffinity(0, sizeof(c), &c))
    PFATAL("sched_setaffinity failed");
}

#endif /* HAVE_AFFINITY */

#ifndef IGNORE_FINDS

/* Helper function to compare buffers; returns first and last differing offset. We
   use this to find reasonable locations for splicing two files. */

static void locate_diffs(u8 *ptr1, u8 *ptr2, u32 len, s32 *first, s32 *last)
{

  s32 f_loc = -1;
  s32 l_loc = -1;
  u32 pos;

  for (pos = 0; pos < len; pos++)
  {

    if (*(ptr1++) != *(ptr2++))
    {

      if (f_loc == -1)
        f_loc = pos;
      l_loc = pos;
    }
  }

  *first = f_loc;
  *last = l_loc;

  return;
}

#endif /* !IGNORE_FINDS */

/* Describe integer. Uses 12 cyclic static buffers for return values. The value
   returned should be five characters or less for all the integers we reasonably
   expect to see. */

static u8 *DI(u64 val)
{

  static u8 tmp[12][16];
  static u8 cur;

  cur = (cur + 1) % 12;

#define CHK_FORMAT(_divisor, _limit_mult, _fmt, _cast)    \
  do                                                      \
  {                                                       \
    if (val < (_divisor) * (_limit_mult))                 \
    {                                                     \
      sprintf(tmp[cur], _fmt, ((_cast)val) / (_divisor)); \
      return tmp[cur];                                    \
    }                                                     \
  } while (0)

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1000, 99.95, "%0.01fk", double);

  /* 100k - 999k */
  CHK_FORMAT(1000, 1000, "%lluk", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1000 * 1000, 9.995, "%0.02fM", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1000 * 1000, 99.95, "%0.01fM", double);

  /* 100M - 999M */
  CHK_FORMAT(1000 * 1000, 1000, "%lluM", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000, 9.995, "%0.02fG", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1000LL * 1000 * 1000, 99.95, "%0.01fG", double);

  /* 100G - 999G */
  CHK_FORMAT(1000LL * 1000 * 1000, 1000, "%lluG", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 9.995, "%0.02fT", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 99.95, "%0.01fT", double);

  /* 100T+ */
  strcpy(tmp[cur], "infty");
  return tmp[cur];
}

/* Describe float. Similar to the above, except with a single
   static buffer. */

static u8 *DF(double val)
{

  static u8 tmp[16];

  if (val < 99.995)
  {
    sprintf(tmp, "%0.02f", val);
    return tmp;
  }

  if (val < 999.95)
  {
    sprintf(tmp, "%0.01f", val);
    return tmp;
  }

  return DI((u64)val);
}

/* Describe integer as memory size. */

static u8 *DMS(u64 val)
{

  static u8 tmp[12][16];
  static u8 cur;

  cur = (cur + 1) % 12;

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu B", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1024, 99.95, "%0.01f kB", double);

  /* 100k - 999k */
  CHK_FORMAT(1024, 1000, "%llu kB", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1024 * 1024, 9.995, "%0.02f MB", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1024 * 1024, 99.95, "%0.01f MB", double);

  /* 100M - 999M */
  CHK_FORMAT(1024 * 1024, 1000, "%llu MB", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024, 9.995, "%0.02f GB", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1024LL * 1024 * 1024, 99.95, "%0.01f GB", double);

  /* 100G - 999G */
  CHK_FORMAT(1024LL * 1024 * 1024, 1000, "%llu GB", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 9.995, "%0.02f TB", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 99.95, "%0.01f TB", double);

#undef CHK_FORMAT

  /* 100T+ */
  strcpy(tmp[cur], "infty");
  return tmp[cur];
}

/* Describe time delta. Returns one static buffer, 34 chars of less. */

static u8 *DTD(u64 cur_ms, u64 event_ms)
{

  static u8 tmp[64];
  u64 delta;
  s32 t_d, t_h, t_m, t_s;

  if (!event_ms)
    return "none seen yet";

  delta = cur_ms - event_ms;

  t_d = delta / 1000 / 60 / 60 / 24;
  t_h = (delta / 1000 / 60 / 60) % 24;
  t_m = (delta / 1000 / 60) % 60;
  t_s = (delta / 1000) % 60;

  sprintf(tmp, "%s days, %u hrs, %u min, %u sec", DI(t_d), t_h, t_m, t_s);
  return tmp;
}

/* Mark deterministic checks as done for a particular queue entry. We use the
   .state file to avoid repeating deterministic fuzzing when resuming aborted
   scans. */

static void mark_as_det_done(struct queue_entry *q)
{

  u8 *fn = strrchr(q->fname, '/');
  s32 fd;

  fn = alloc_printf("%s/queue/.state/deterministic_done/%s", out_dir, fn + 1);

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0)
    PFATAL("Unable to create '%s'", fn);
  close(fd);

  ck_free(fn);

  q->passed_det = 1;
}

/* Mark as variable. Create symlinks if possible to make it easier to examine
   the files. */

static void mark_as_variable(struct queue_entry *q)
{

  u8 *fn = strrchr(q->fname, '/') + 1, *ldest;

  ldest = alloc_printf("../../%s", fn);
  fn = alloc_printf("%s/queue/.state/variable_behavior/%s", out_dir, fn);

  if (symlink(ldest, fn))
  {

    s32 fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
      PFATAL("Unable to create '%s'", fn);
    close(fd);
  }

  ck_free(ldest);
  ck_free(fn);

  q->var_behavior = 1;
}

/* Mark / unmark as redundant (edge-only). This is not used for restoring state,
   but may be useful for post-processing datasets. */

static void mark_as_redundant(struct queue_entry *q, u8 state)
{

  u8 *fn;
  s32 fd;

  if (state == q->fs_redundant)
    return;

  q->fs_redundant = state;

  fn = strrchr(q->fname, '/');
  fn = alloc_printf("%s/queue/.state/redundant_edges/%s", out_dir, fn + 1);

  if (state)
  {

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
      PFATAL("Unable to create '%s'", fn);
    close(fd);
  }
  else
  {

    if (unlink(fn))
      PFATAL("Unable to remove '%s'", fn);
  }

  ck_free(fn);
}

/* Append new test case to the queue. */

static void add_to_queue(u8 *fname, u32 len, u8 passed_det)
{

  struct queue_entry *q = ck_alloc(sizeof(struct queue_entry));

  q->fname = fname;
  q->len = len;
  q->depth = cur_depth + 1;
  q->passed_det = passed_det;
  q->regions = NULL;
  q->region_count = 0;
  q->index = queued_paths;
  q->generating_state_id = target_state_id;
  q->is_initial_seed = 0;
  q->unique_state_count = 0;

  if (q->depth > max_depth)
    max_depth = q->depth;

  if (queue_top)
  {

    queue_top->next = q;
    queue_top = q;
  }
  else
    q_prev100 = queue = queue_top = q;

  queued_paths++;
  pending_not_fuzzed++;

  cycles_wo_finds = 0;

  if (!(queued_paths % 100))
  {

    q_prev100->next_100 = q;
    q_prev100 = q;
  }

  /* AFLNet: extract regions keeping client requests if needed */
  if (corpus_read_or_sync)
  {
    FILE *fp;
    unsigned char *buf;

    /* opening file for reading */
    fp = fopen(fname, "rb");

    buf = (unsigned char *)ck_alloc(len);
    u32 byte_count = fread(buf, 1, len, fp);
    fclose(fp);

    if (byte_count != len)
      PFATAL("AFLNet - Inconsistent file length '%s'", fname);
    q->regions = (*extract_requests)(buf, len, &q->region_count);
    ck_free(buf);

    // Keep track the maximal number of seed regions
    // We use this for some optimization to reduce the overhead while following the server's sequence diagram
    if ((corpus_read_or_sync == 1) && (q->region_count > max_seed_region_count))
      max_seed_region_count = q->region_count;
  }
  else
  {
    // Convert the linked list kl_messages to regions
    q->regions = convert_kl_messages_to_regions(kl_messages, &q->region_count, messages_sent);
  }

  /* save the regions' information to file for debugging purpose */
  u8 *fn = alloc_printf("%s/regions/%s", out_dir, basename(fname));
  save_regions_to_file(q->regions, q->region_count, fn);
  ck_free(fn);

  last_path_time = get_cur_time();

  // Add a new column to the was_fuzzed map
  if (fuzzed_map_states)
  {
    expand_was_fuzzed_map(0, 1);
  }
  else
  {
    // Also add a new row (for state 0) if needed
    expand_was_fuzzed_map(1, 1);
  }
}

/* Destroy the entire queue. */

EXP_ST void destroy_queue(void)
{

  struct queue_entry *q = queue, *n;

  while (q)
  {

    n = q->next;
    ck_free(q->fname);
    ck_free(q->trace_mini);
    u32 i;
    // Free AFLNet-specific data structure
    for (i = 0; i < q->region_count; i++)
    {
      if (q->regions[i].state_sequence)
        ck_free(q->regions[i].state_sequence);
    }
    if (q->regions)
      ck_free(q->regions);
    ck_free(q);
    q = n;
  }
}

/* Write bitmap to file. The bitmap is useful mostly for the secret
   -B option, to focus a separate fuzzing session on a particular
   interesting input without rediscovering all the others. */

EXP_ST void write_bitmap(void)
{

  u8 *fname;
  s32 fd;

  if (!bitmap_changed)
    return;
  bitmap_changed = 0;

  fname = alloc_printf("%s/fuzz_bitmap", out_dir);
  fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0)
    PFATAL("Unable to open '%s'", fname);

  ck_write(fd, virgin_bits, MAP_SIZE, fname);

  close(fd);
  ck_free(fname);
}

/* Read bitmap from file. This is for the -B option again. */

EXP_ST void read_bitmap(u8 *fname)
{

  s32 fd = open(fname, O_RDONLY);

  if (fd < 0)
    PFATAL("Unable to open '%s'", fname);

  ck_read(fd, virgin_bits, MAP_SIZE, fname);

  close(fd);
}

/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen.
   Updates the map, so subsequent calls will always return 0.

   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */

static inline u8 has_new_bits(u8 *virgin_map)
{

#ifdef WORD_SIZE_64

  u64 *current = (u64 *)trace_bits;
  u64 *virgin = (u64 *)virgin_map;

  u32 i = (MAP_SIZE >> 3);

#else

  u32 *current = (u32 *)trace_bits;
  u32 *virgin = (u32 *)virgin_map;

  u32 i = (MAP_SIZE >> 2);

#endif /* ^WORD_SIZE_64 */

  u8 ret = 0;

  while (i--)
  {

    /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
       that have not been already cleared from the virgin map - since this will
       almost always be the case. */

    if (unlikely(*current) && unlikely(*current & *virgin))
    {

      if (likely(ret < 2))
      {

        u8 *cur = (u8 *)current;
        u8 *vir = (u8 *)virgin;

        /* Looks like we have not found any new bytes yet; see if any non-zero
           bytes in current[] are pristine in virgin[]. */

#ifdef WORD_SIZE_64

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
            (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
            (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff))
          ret = 2;
        else
          ret = 1;

#else

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff))
          ret = 2;
        else
          ret = 1;

#endif /* ^WORD_SIZE_64 */
      }

      *virgin &= ~*current;
    }

    current++;
    virgin++;
  }

  if (ret && virgin_map == virgin_bits)
    bitmap_changed = 1;

  return ret;
}

/* Count the number of bits set in the provided bitmap. Used for the status
   screen several times every second, does not have to be fast. */

static u32 count_bits(u8 *mem)
{

  u32 *ptr = (u32 *)mem;
  u32 i = (MAP_SIZE >> 2);
  u32 ret = 0;

  while (i--)
  {

    u32 v = *(ptr++);

    /* This gets called on the inverse, virgin bitmap; optimize for sparse
       data. */

    if (v == 0xffffffff)
    {
      ret += 32;
      continue;
    }

    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;
  }

  return ret;
}

#define FF(_b) (0xff << ((_b) << 3))

/* Count the number of bytes set in the bitmap. Called fairly sporadically,
   mostly to update the status screen or calibrate and examine confirmed
   new paths. */

static u32 count_bytes(u8 *mem)
{

  u32 *ptr = (u32 *)mem;
  u32 i = (MAP_SIZE >> 2);
  u32 ret = 0;

  while (i--)
  {

    u32 v = *(ptr++);

    if (!v)
      continue;
    if (v & FF(0))
      ret++;
    if (v & FF(1))
      ret++;
    if (v & FF(2))
      ret++;
    if (v & FF(3))
      ret++;
  }

  return ret;
}

/* Count the number of non-255 bytes set in the bitmap. Used strictly for the
   status screen, several calls per second or so. */

static u32 count_non_255_bytes(u8 *mem)
{

  u32 *ptr = (u32 *)mem;
  u32 i = (MAP_SIZE >> 2);
  u32 ret = 0;

  while (i--)
  {

    u32 v = *(ptr++);

    /* This is called on the virgin bitmap, so optimize for the most likely
       case. */

    if (v == 0xffffffff)
      continue;
    if ((v & FF(0)) != FF(0))
      ret++;
    if ((v & FF(1)) != FF(1))
      ret++;
    if ((v & FF(2)) != FF(2))
      ret++;
    if ((v & FF(3)) != FF(3))
      ret++;
  }

  return ret;
}

/* Destructively simplify trace by eliminating hit count information
   and replacing it with 0x80 or 0x01 depending on whether the tuple
   is hit or not. Called on every new crash or timeout, should be
   reasonably fast. */

static const u8 simplify_lookup[256] = {

    [0] = 1,
    [1 ... 255] = 128

};

#ifdef WORD_SIZE_64

static void simplify_trace(u64 *mem)
{

  u32 i = MAP_SIZE >> 3;

  while (i--)
  {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem))
    {

      u8 *mem8 = (u8 *)mem;

      mem8[0] = simplify_lookup[mem8[0]];
      mem8[1] = simplify_lookup[mem8[1]];
      mem8[2] = simplify_lookup[mem8[2]];
      mem8[3] = simplify_lookup[mem8[3]];
      mem8[4] = simplify_lookup[mem8[4]];
      mem8[5] = simplify_lookup[mem8[5]];
      mem8[6] = simplify_lookup[mem8[6]];
      mem8[7] = simplify_lookup[mem8[7]];
    }
    else
      *mem = 0x0101010101010101ULL;

    mem++;
  }
}

#else

static void simplify_trace(u32 *mem)
{

  u32 i = MAP_SIZE >> 2;

  while (i--)
  {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem))
    {

      u8 *mem8 = (u8 *)mem;

      mem8[0] = simplify_lookup[mem8[0]];
      mem8[1] = simplify_lookup[mem8[1]];
      mem8[2] = simplify_lookup[mem8[2]];
      mem8[3] = simplify_lookup[mem8[3]];
    }
    else
      *mem = 0x01010101;

    mem++;
  }
}

#endif /* ^WORD_SIZE_64 */

/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */

static const u8 count_class_lookup8[256] = {

    [0] = 0,
    [1] = 1,
    [2] = 2,
    [3] = 4,
    [4 ... 7] = 8,
    [8 ... 15] = 16,
    [16 ... 31] = 32,
    [32 ... 127] = 64,
    [128 ... 255] = 128

};

static u16 count_class_lookup16[65536];

EXP_ST void init_count_class16(void)
{

  u32 b1, b2;

  for (b1 = 0; b1 < 256; b1++)
    for (b2 = 0; b2 < 256; b2++)
      count_class_lookup16[(b1 << 8) + b2] =
          (count_class_lookup8[b1] << 8) |
          count_class_lookup8[b2];
}

#ifdef WORD_SIZE_64

static inline void classify_counts(u64 *mem)
{

  u32 i = MAP_SIZE >> 3;

  while (i--)
  {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem))
    {

      u16 *mem16 = (u16 *)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];
      mem16[2] = count_class_lookup16[mem16[2]];
      mem16[3] = count_class_lookup16[mem16[3]];
    }

    mem++;
  }
}

#else

static inline void classify_counts(u32 *mem)
{

  u32 i = MAP_SIZE >> 2;

  while (i--)
  {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem))
    {

      u16 *mem16 = (u16 *)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];
    }

    mem++;
  }
}

#endif /* ^WORD_SIZE_64 */

/* Get rid of shared memory (atexit handler). */

static void remove_shm(void)
{

  shmctl(shm_id, IPC_RMID, NULL);
}

/* Compact trace bytes into a smaller bitmap. We effectively just drop the
   count information here. This is called only sporadically, for some
   new paths. */

static void minimize_bits(u8 *dst, u8 *src)
{

  u32 i = 0;

  while (i < MAP_SIZE)
  {

    if (*(src++))
      dst[i >> 3] |= 1 << (i & 7);
    i++;
  }
}

/* When we bump into a new path, we call this to see if the path appears
   more "favorable" than any of the existing ones. The purpose of the
   "favorables" is to have a minimal set of paths that trigger all the bits
   seen in the bitmap so far, and focus on fuzzing them at the expense of
   the rest.

   The first step of the process is to maintain a list of top_rated[] entries
   for every byte in the bitmap. We win that slot if there is no previous
   contender, or if the contender has smaller unique state count or
   it has a more favorable speed x size factor. */

static void update_bitmap_score(struct queue_entry *q)
{

  u32 i;
  u64 fav_factor = q->exec_us * q->len;

  /* For every byte set in trace_bits[], see if there is a previous winner,
     and how it compares to us. */

  for (i = 0; i < MAP_SIZE; i++)

    if (trace_bits[i])
    {

      if (top_rated[i])
      {

        /* AFLNet check unique state count first */

        if (q->unique_state_count < top_rated[i]->unique_state_count)
          continue;

        /* Faster-executing or smaller test cases are favored. */

        if ((q->unique_state_count < top_rated[i]->unique_state_count) && (fav_factor > top_rated[i]->exec_us * top_rated[i]->len))
          continue;

        /* Looks like we're going to win. Decrease ref count for the
           previous winner, discard its trace_bits[] if necessary. */

        if (!--top_rated[i]->tc_ref)
        {
          ck_free(top_rated[i]->trace_mini);
          top_rated[i]->trace_mini = 0;
        }
      }

      /* Insert ourselves as the new winner. */

      top_rated[i] = q;
      q->tc_ref++;

      if (!q->trace_mini)
      {
        q->trace_mini = ck_alloc(MAP_SIZE >> 3);
        minimize_bits(q->trace_mini, trace_bits);
      }

      score_changed = 1;
    }
}

/* The second part of the mechanism discussed above is a routine that
   goes over top_rated[] entries, and then sequentially grabs winners for
   previously-unseen bytes (temp_v) and marks them as favored, at least
   until the next run. The favored entries are given more air time during
   all fuzzing steps. */

static void cull_queue(void)
{

  struct queue_entry *q;
  static u8 temp_v[MAP_SIZE >> 3];
  u32 i;

  if (dumb_mode || !score_changed)
    return;

  score_changed = 0;

  memset(temp_v, 255, MAP_SIZE >> 3);

  queued_favored = 0;
  pending_favored = 0;

  q = queue;

  while (q)
  {
    if (!q->is_initial_seed)
      q->favored = 0;
    q = q->next;
  }

  /* Let's see if anything in the bitmap isn't captured in temp_v.
     If yes, and if it has a top_rated[] contender, let's use it. */

  for (i = 0; i < MAP_SIZE; i++)
    if (top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7))))
    {

      u32 j = MAP_SIZE >> 3;

      /* Remove all bits belonging to the current entry from temp_v. */

      while (j--)
        if (top_rated[i]->trace_mini[j])
          temp_v[j] &= ~top_rated[i]->trace_mini[j];

      top_rated[i]->favored = 1;
      queued_favored++;

      // if (!top_rated[i]->was_fuzzed) pending_favored++;
      /* AFLNet takes into account more information to make this decision */
      if ((top_rated[i]->generating_state_id == target_state_id || top_rated[i]->is_initial_seed) && (was_fuzzed_map[get_state_index(target_state_id)][top_rated[i]->index] == 0))
        pending_favored++;
    }

  q = queue;

  while (q)
  {
    mark_as_redundant(q, !q->favored);
    q = q->next;
  }
}

/* Configure shared memory and virgin_bits. This is called at startup. */

EXP_ST void setup_shm(void)
{

  u8 *shm_str;

  if (!in_bitmap)
    memset(virgin_bits, 255, MAP_SIZE);

  memset(virgin_tmout, 255, MAP_SIZE);
  memset(virgin_crash, 255, MAP_SIZE);

  shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

  if (shm_id < 0)
    PFATAL("shmget() failed");

  atexit(remove_shm);

  shm_str = alloc_printf("%d", shm_id);

  /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
     we don't want them to detect instrumentation, since we won't be sending
     fork server commands. This should be replaced with better auto-detection
     later on, perhaps? */

  if (!dumb_mode)
    setenv(SHM_ENV_VAR, shm_str, 1);

  ck_free(shm_str);

  trace_bits = shmat(shm_id, NULL, 0);

  if (!trace_bits)
    PFATAL("shmat() failed");
}

/* Load postprocessor, if available. */

static void setup_post(void)
{

  void *dh;
  u8 *fn = getenv("AFL_POST_LIBRARY");
  u32 tlen = 6;

  if (!fn)
    return;

  ACTF("Loading postprocessor from '%s'...", fn);

  dh = dlopen(fn, RTLD_NOW);
  if (!dh)
    FATAL("%s", dlerror());

  post_handler = dlsym(dh, "afl_postprocess");
  if (!post_handler)
    FATAL("Symbol 'afl_postprocess' not found.");

  /* Do a quick test. It's better to segfault now than later =) */

  post_handler("hello", &tlen);

  OKF("Postprocessor installed successfully.");
}

/* ================================================================
 * Fix-8: Parallel enrichment infrastructure.
 * Each task captures one (seed_content, combo_subset) pair.
 * Workers only call enrich_sequence() — pure LLM I/O, thread-safe.
 * All file I/O and khash manipulation stays in the main thread.
 * ================================================================ */

typedef struct {
    char *seed_content;           /* shared read-only ptr (owned by seed_data) */
    khash_t(strSet) *subset;      /* read-only ptr (owned by message_subsets) */
    const char *protocol;         /* global read-only */
    char *result;                 /* worker writes enriched string, or NULL */
    char *seed_file_name;         /* strdup'd, for output naming */
    int  combo_idx;               /* for output file naming */
    unsigned long long prompt_tokens;     /* per-task token usage */
    unsigned long long completion_tokens; /* per-task token usage */
} enrich_task_t;

typedef struct {
    enrich_task_t *tasks;
    int            n_tasks;
    int            next_task;     /* next index to claim */
    pthread_mutex_t lock;
} enrich_pool_t;

static void *enrich_worker(void *arg) {
    enrich_pool_t *pool = (enrich_pool_t *)arg;
    while (1) {
        pthread_mutex_lock(&pool->lock);
        int idx = pool->next_task++;
        pthread_mutex_unlock(&pool->lock);
        if (idx >= pool->n_tasks) break;

        enrich_task_t *t = &pool->tasks[idx];
        t->result = enrich_sequence(t->seed_content, t->subset, t->protocol);
        /* Capture TLS token usage into the task struct (thread-safe: each
         * thread writes to its own task, llm_last_* are __thread). */
        t->prompt_tokens     = llm_last_prompt_tokens;
        t->completion_tokens = llm_last_completion_tokens;
    }
    return NULL;
}

/* Track per-seed heap data so we can free it after all workers finish. */
typedef struct {
    char              *content;     /* malloc'd file content */
    char              *mqtt_text;   /* MQTT text representation (NULL for text protocols) */
    message_set_list   subsets;     /* C(n,2) subsets (owns khash_t ptrs) */
    khash_t(strSet)   *messages;    /* missing-types set */
} seed_data_t;

void get_seeds_with_messsage_types(const char *in_dir, khash_t(strSet) * message_types_set)
{
  struct dirent **nl_files;
  int nl_cnt = scandir(in_dir, &nl_files, NULL, alphasort);
  if (nl_cnt < 0)
  {
    printf("Error in reading the directory %s\n", in_dir);
    exit(1);
  }

  OKF("Found %d protocol message types for enrichment", kh_size(message_types_set));

  /* Fix-8: call curl_global_init ONCE before any worker threads */
  chat_llm_global_init();

  int seeds_processed = 0;
  int total_enriched = 0;

  /* --- Phase 1: collect enrichment tasks from all seeds --- */
  enrich_task_t *tasks = NULL;
  int n_tasks = 0, tasks_cap = 0;
  seed_data_t   *seed_arr = NULL;
  int n_seed_data = 0, seed_cap = 0;

  // traverse the directory to read the files
  for (int i = 0; i < nl_cnt; i++)
  {
    char *nl_file_name = nl_files[i]->d_name;
    // skip the . and .. files and files whose name includes "enriched"
    if (strcmp(nl_file_name, ".") == 0 || strcmp(nl_file_name, "..") == 0 || strstr(nl_file_name, "enriched") != NULL)
    {
      continue;
    }

    seeds_processed++;
    ACTF("Processing seed %d: %s", seeds_processed, nl_file_name);
    char *nl_file_path = malloc(strlen(in_dir) + strlen(nl_file_name) + 2);
    strcpy(nl_file_path, in_dir);
    strcat(nl_file_path, "/");
    strcat(nl_file_path, nl_file_name);
    // printf("## File path: %s\n", nl_file_path);

    FILE *nl_file = fopen(nl_file_path, "r");
    if (nl_file == NULL)
    {
      printf("Error in opening the file %s\n", nl_file_path);
      exit(1);
    }

    // read the whole file into a buffer
    fseek(nl_file, 0, SEEK_END);
    size_t fsize = ftell(nl_file);
    fseek(nl_file, 0, SEEK_SET);
    char *nl_file_content = malloc(fsize + 1);
    fread(nl_file_content, fsize, 1, nl_file);
    nl_file_content[fsize] = '\0';
    // printf("## File content:\n %s\n", nl_file_content);
    fclose(nl_file);
    free(nl_file_path);

    u32 region_count = 0;
    region_t *regions = (*extract_requests)(nl_file_content, fsize, &region_count);

    khash_t(strSet) *messages = duplicate_hash(message_types_set); // duplicate the message set

    for (int j = 0; j < region_count; j++)
    { 
      // remove all messages that are observed
      char *header;
      int is_mqtt = (protocol_name && strcasecmp(protocol_name, "MQTT") == 0);

      if (is_mqtt) {
        /* Fix-13b: MQTT binary header extraction.
         * For binary MQTT, the first byte's upper nibble identifies the packet type.
         * Text-based scanning would produce garbage. */
        header = mqtt_extract_type_from_region(
            (const unsigned char *)nl_file_content, regions[j].start_byte);
        if (!header) {
          header = ck_alloc(8);
          snprintf(header, 8, "0x%02X",
                   (unsigned char)nl_file_content[regions[j].start_byte]);
        }
      } else {
        int header_len = 0;
        while (regions[j].start_byte + header_len < regions[j].end_byte 
        && nl_file_content[regions[j].start_byte + header_len] != ' ' 
        && nl_file_content[regions[j].start_byte + header_len] != '\r' 
        && nl_file_content[regions[j].start_byte + header_len] != '\n'
        && nl_file_content[regions[j].start_byte + header_len] != '\\')
        {
          header_len++;
        }
        header = ck_alloc(header_len + 1);
        memcpy(header, nl_file_content + regions[j].start_byte, header_len);
        header[header_len] = '\0';
      }

      khiter_t k = kh_get(strSet, messages, header);
      if (kh_exist(messages, k))
      {
        kh_del(strSet, messages, k);
      }
      ck_free(header);
    }

    ck_free(regions);

    if(kh_size(messages) == 0) 
    {
      kh_destroy(strSet,messages);
      // No missing message types, cannot enrich
      continue;
    }

    int original_missing = kh_size(messages);
    OKF("Missing %d message types, generating combinations...", original_missing);

    while(kh_size(messages) > MAX_ENRICHMENT_CORPUS_SIZE) 
    {
      khiter_t x =UR(kh_end(messages));
      if (kh_exist(messages, x))
      {
        kh_del(strSet, messages, x);
      }
    }

    message_set_list message_subsets = message_combinations(messages,MAX_ENRICHMENT_MESSAGE_TYPES);

    int n_combos = kv_size(message_subsets);
    OKF("Seed '%s': %d combos (no cap — full enrichment)", nl_file_name, n_combos);

    /* For MQTT: convert binary seed to text representation for LLM.
     * The LLM cannot process raw binary — it needs human-readable text.
     * mqtt_binary_to_text() decodes each MQTT packet into text lines like:
     *   CONNECT ClientId=fuzz_client CleanSession=1 KeepAlive=60
     *   SUBSCRIBE PacketId=1 Topic=test/# QoS=0
     * This text is what enrich_sequence() will embed in the LLM prompt. */
    char *seed_for_llm = nl_file_content;
    int is_mqtt_seed = (protocol_name && strcasecmp(protocol_name, "MQTT") == 0);
    if (is_mqtt_seed) {
      seed_for_llm = mqtt_binary_to_text((const unsigned char *)nl_file_content, fsize);
      if (!seed_for_llm || !*seed_for_llm) {
        fprintf(stderr, "[!] MQTT binary_to_text failed for seed '%s', using fallback\n", nl_file_name);
        free(seed_for_llm);
        seed_for_llm = strdup("CONNECT ClientId=fuzz_client CleanSession=1 KeepAlive=60\n"
                              "PINGREQ\nDISCONNECT\n");
      }
      ACTF("MQTT seed '%s' converted to text (%zu bytes -> %zu chars)",
           nl_file_name, fsize, strlen(seed_for_llm));
    }

    /* Store seed data for later cleanup (content + subsets stay alive
     * until all workers are done). */
    if (n_seed_data >= seed_cap) {
      seed_cap = seed_cap ? seed_cap * 2 : 16;
      seed_arr = realloc(seed_arr, seed_cap * sizeof(seed_data_t));
    }
    seed_arr[n_seed_data].content  = nl_file_content;
    seed_arr[n_seed_data].mqtt_text = is_mqtt_seed ? seed_for_llm : NULL;
    seed_arr[n_seed_data].subsets  = message_subsets;
    seed_arr[n_seed_data].messages = messages;
    n_seed_data++;

    /* Collect one task per combo. */
    for (int c = 0; c < n_combos; c++) {
      if (n_tasks >= tasks_cap) {
        tasks_cap = tasks_cap ? tasks_cap * 2 : 64;
        tasks = realloc(tasks, tasks_cap * sizeof(enrich_task_t));
      }
      enrich_task_t *t = &tasks[n_tasks];
      t->seed_content   = is_mqtt_seed ? seed_for_llm : nl_file_content;
      t->subset         = kv_A(message_subsets, c);
      t->protocol       = protocol_name;
      t->result         = NULL;
      t->seed_file_name = strdup(nl_file_name);
      t->combo_idx      = c;
      n_tasks++;
    }

    /* NOTE: do NOT free nl_file_content, subsets or messages here —
     * workers will read them.  Freed after all threads join. */
  }

  /* ==== Phase 2: parallel LLM enrichment ==== */
  OKF("Collected %d enrichment tasks from %d seeds — launching %d threads",
      n_tasks, seeds_processed,
      n_tasks < ENRICHMENT_THREADS ? n_tasks : ENRICHMENT_THREADS);

  if (n_tasks > 0) {
    enrich_pool_t pool = {
        .tasks     = tasks,
        .n_tasks   = n_tasks,
        .next_task = 0,
        .lock      = PTHREAD_MUTEX_INITIALIZER
    };

    int n_threads = ENRICHMENT_THREADS;
    if (n_threads > n_tasks) n_threads = n_tasks;

    pthread_t *tids = malloc(n_threads * sizeof(pthread_t));
    for (int t = 0; t < n_threads; t++)
      pthread_create(&tids[t], NULL, enrich_worker, &pool);
    for (int t = 0; t < n_threads; t++)
      pthread_join(tids[t], NULL);
    free(tids);
    pthread_mutex_destroy(&pool.lock);

    /* Accumulate per-task token usage into global counters (main thread).
     * Tokens are always accumulated (even failed calls may have been billed
     * by the API), but llm_total_calls only counts successful calls. */
    for (int i = 0; i < n_tasks; i++) {
      llm_total_prompt_tokens     += tasks[i].prompt_tokens;
      llm_total_completion_tokens += tasks[i].completion_tokens;
      if (tasks[i].result != NULL) llm_total_calls++;
    }
  }

  /* ==== Phase 3: process results (main thread only) ==== */
  int is_mqtt_result = (protocol_name && strcasecmp(protocol_name, "MQTT") == 0);

  for (int i = 0; i < n_tasks; i++) {
    enrich_task_t *t = &tasks[i];
    if (t->result == NULL) {
      free(t->seed_file_name);
      continue;
    }

    /* Build output path: enriched_<combo_idx>_<seed_file_name> */
    char *enriched_file_name = malloc(strlen(t->seed_file_name) + 10 + 20);
    strcpy(enriched_file_name, "enriched_");
    sprintf(enriched_file_name + 9, "%d_", t->combo_idx);
    strcat(enriched_file_name, t->seed_file_name);

    char *enriched_file_path = malloc(strlen(in_dir) + strlen(enriched_file_name) + 2);
    strcpy(enriched_file_path, in_dir);
    strcat(enriched_file_path, "/");
    strcat(enriched_file_path, enriched_file_name);

    if (is_mqtt_result) {
      /* Fix-13b: MQTT text→binary conversion.
       * The LLM returned text descriptions of MQTT packets.
       * Convert them to valid binary packets using mqtt_text_to_binary(). */
      size_t bin_len = 0;
      unsigned char *binary_seed = mqtt_text_to_binary(t->result, &bin_len);
      if (binary_seed && bin_len > 0) {
        int fd = open(enriched_file_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
          ssize_t written = write(fd, binary_seed, bin_len);
          close(fd);
          if (written == (ssize_t)bin_len) {
            total_enriched++;
            OKF("Created MQTT binary enriched seed: %s (%zu bytes)", enriched_file_name, bin_len);
          }
        }
        free(binary_seed);
      } else {
        fprintf(stderr, "[!] MQTT text_to_binary failed for enriched result, skipping\n");
      }
    } else {
      /* Original text protocol path */
      /* Validate: skip if enriched text == original seed */
      char *formatted_orig = format_string(t->seed_content);
      char *unescaped      = unescape_string(t->result);
      char *formatted_new  = format_string(unescaped);

      if (formatted_new == NULL ||
          strcmp(formatted_new, formatted_orig) == 0) {
        printf("## Skip the same seed\n");
        free(t->seed_file_name);
        free(t->result);
        free(enriched_file_name);
        free(enriched_file_path);
        continue;
      }

      unescaped = format_request_message(unescaped);
      write_new_seeds(enriched_file_path, unescaped);
      total_enriched++;
      OKF("Created enriched seed: %s", enriched_file_name);
    }

    free(enriched_file_name);
    free(enriched_file_path);
    free(t->seed_file_name);
    free(t->result);
  }

  /* ==== Cleanup ==== */
  free(tasks);
  for (int s = 0; s < n_seed_data; s++) {
    for (int c = 0; c < kv_size(seed_arr[s].subsets); c++)
      kh_destroy(strSet, kv_A(seed_arr[s].subsets, c));
    kh_destroy(strSet, seed_arr[s].messages);
    free(seed_arr[s].content);
    if (seed_arr[s].mqtt_text) free(seed_arr[s].mqtt_text);
  }
  free(seed_arr);

  OKF("Enrichment complete: generated %d enriched seeds from %d processed seeds", 
      total_enriched, seeds_processed);
}

/* Enrich the testcases before startup */
static void enrich_testcases(void)
{
  ACTF("Enriching test cases from LLM...");

  // Get seeds to states and save them to the in_dir (all protocols, including MQTT)
  get_seeds_with_messsage_types(in_dir, message_types_set);

  /* Fix-13: MQTT binary protocol supplementation.
   * The LLM enrichment pipeline above runs normally (API calls happen),
   * but its text-based enriched seeds are invalid for MQTT's binary format.
   * Supplement with programmatic binary seed generation. */
  if (protocol_name && strcasecmp(protocol_name, "MQTT") == 0) {
    ACTF("MQTT: supplementing LLM enrichment with programmatic binary seeds");
    int n = mqtt_enrich_seeds(in_dir, message_types_set);
    OKF("MQTT supplementation: generated %d binary seeds", n);

    /* P0+P2: Generate MQTT v5 seeds for v5 code path coverage.
     * These exercise mosquitto's v5-specific code: property__read_all(),
     * handle__auth(), v5 DISCONNECT with reason code, subscription
     * options (No Local, Retain Handling), Topic Alias mapping, etc. */
    ACTF("MQTT: generating v5 structured seeds");
    u32 nv5 = mqtt_generate_v5_seeds(in_dir);
    OKF("MQTT v5 seeds: generated %u files", nv5);
  }
}

/* Read all testcases from the input directory, then queue them for testing.
   Called at startup. */

static void read_testcases(void)
{

  struct dirent **nl;
  s32 nl_cnt;
  u32 i;
  u8 *fn;

  /* AFLNet: set this flag to enable request extractions while adding new seed to the queue */
  corpus_read_or_sync = 1;

  /* Auto-detect non-in-place resumption attempts. */

  fn = alloc_printf("%s/queue", in_dir);
  if (!access(fn, F_OK))
    in_dir = fn;
  else
    ck_free(fn);

  ACTF("Scanning '%s'...", in_dir);

  /* We use scandir() + alphasort() rather than readdir() because otherwise,
     the ordering  of test cases would vary somewhat randomly and would be
     difficult to control. */

  nl_cnt = scandir(in_dir, &nl, NULL, alphasort);

  if (nl_cnt < 0)
  {

    if (errno == ENOENT || errno == ENOTDIR)

      SAYF("\n" cLRD "[-] " cRST
           "The input directory does not seem to be valid - try again. The fuzzer needs\n"
           "    one or more test case to start with - ideally, a small file under 1 kB\n"
           "    or so. The cases must be stored as regular files directly in the input\n"
           "    directory.\n");

    PFATAL("Unable to open '%s'", in_dir);
  }

  if (shuffle_queue && nl_cnt > 1)
  {

    ACTF("Shuffling queue...");
    shuffle_ptrs((void **)nl, nl_cnt);
  }

  for (i = 0; i < nl_cnt; i++)
  {

    struct stat st;

    u8 *fn = alloc_printf("%s/%s", in_dir, nl[i]->d_name);
    u8 *dfn = alloc_printf("%s/.state/deterministic_done/%s", in_dir, nl[i]->d_name);

    u8 passed_det = 0;

    free(nl[i]); /* not tracked */

    if (lstat(fn, &st) || access(fn, R_OK))
      PFATAL("Unable to access '%s'", fn);

    /* This also takes care of . and .. */

    if (!S_ISREG(st.st_mode) || !st.st_size || strstr(fn, "/README.txt"))
    {

      ck_free(fn);
      ck_free(dfn);
      continue;
    }

    if (st.st_size > MAX_FILE)
      FATAL("Test case '%s' is too big (%s, limit is %s)", fn,
            DMS(st.st_size), DMS(MAX_FILE));

    /* Check for metadata that indicates that deterministic fuzzing
       is complete for this entry. We don't want to repeat deterministic
       fuzzing when resuming aborted scans, because it would be pointless
       and probably very time-consuming. */

    if (!access(dfn, F_OK))
      passed_det = 1;
    ck_free(dfn);

    add_to_queue(fn, st.st_size, passed_det);
  }

  /* AFLNet: unset this flag to disable request extractions while adding new seed to the queue */
  corpus_read_or_sync = 0;

  free(nl); /* not tracked */

  if (!queued_paths)
  {

    SAYF("\n" cLRD "[-] " cRST
         "Looks like there are no valid test cases in the input directory! The fuzzer\n"
         "    needs one or more test case to start with - ideally, a small file under\n"
         "    1 kB or so. The cases must be stored as regular files directly in the\n"
         "    input directory.\n");

    FATAL("No usable test cases in '%s'", in_dir);
  }

  last_path_time = 0;
  queued_at_start = queued_paths;
}

/* Helper function for load_extras. */

static int compare_extras_len(const void *p1, const void *p2)
{
  struct extra_data *e1 = (struct extra_data *)p1,
                    *e2 = (struct extra_data *)p2;

  return e1->len - e2->len;
}

static int compare_extras_use_d(const void *p1, const void *p2)
{
  struct extra_data *e1 = (struct extra_data *)p1,
                    *e2 = (struct extra_data *)p2;

  return e2->hit_cnt - e1->hit_cnt;
}

/* Read extras from a file, sort by size. */

static void load_extras_file(u8 *fname, u32 *min_len, u32 *max_len,
                             u32 dict_level)
{

  FILE *f;
  u8 buf[MAX_LINE];
  u8 *lptr;
  u32 cur_line = 0;

  f = fopen(fname, "r");

  if (!f)
    PFATAL("Unable to open '%s'", fname);

  while ((lptr = fgets(buf, MAX_LINE, f)))
  {

    u8 *rptr, *wptr;
    u32 klen = 0;

    cur_line++;

    /* Trim on left and right. */

    while (isspace(*lptr))
      lptr++;

    rptr = lptr + strlen(lptr) - 1;
    while (rptr >= lptr && isspace(*rptr))
      rptr--;
    rptr++;
    *rptr = 0;

    /* Skip empty lines and comments. */

    if (!*lptr || *lptr == '#')
      continue;

    /* All other lines must end with '"', which we can consume. */

    rptr--;

    if (rptr < lptr || *rptr != '"')
      FATAL("Malformed name=\"value\" pair in line %u.", cur_line);

    *rptr = 0;

    /* Skip alphanumerics and dashes (label). */

    while (isalnum(*lptr) || *lptr == '_')
      lptr++;

    /* If @number follows, parse that. */

    if (*lptr == '@')
    {

      lptr++;
      if (atoi(lptr) > dict_level)
        continue;
      while (isdigit(*lptr))
        lptr++;
    }

    /* Skip whitespace and = signs. */

    while (isspace(*lptr) || *lptr == '=')
      lptr++;

    /* Consume opening '"'. */

    if (*lptr != '"')
      FATAL("Malformed name=\"keyword\" pair in line %u.", cur_line);

    lptr++;

    if (!*lptr)
      FATAL("Empty keyword in line %u.", cur_line);

    /* Okay, let's allocate memory and copy data between "...", handling
       \xNN escaping, \\, and \". */

    extras = ck_realloc_block(extras, (extras_cnt + 1) *
                                          sizeof(struct extra_data));

    wptr = extras[extras_cnt].data = ck_alloc(rptr - lptr);

    while (*lptr)
    {

      char *hexdigits = "0123456789abcdef";

      switch (*lptr)
      {

      case 1 ... 31:
      case 128 ... 255:
        FATAL("Non-printable characters in line %u.", cur_line);

      case '\\':

        lptr++;

        if (*lptr == '\\' || *lptr == '"')
        {
          *(wptr++) = *(lptr++);
          klen++;
          break;
        }

        if (*lptr != 'x' || !isxdigit(lptr[1]) || !isxdigit(lptr[2]))
          FATAL("Invalid escaping (not \\xNN) in line %u.", cur_line);

        *(wptr++) =
            ((strchr(hexdigits, tolower(lptr[1])) - hexdigits) << 4) |
            (strchr(hexdigits, tolower(lptr[2])) - hexdigits);

        lptr += 3;
        klen++;

        break;

      default:

        *(wptr++) = *(lptr++);
        klen++;
      }
    }

    extras[extras_cnt].len = klen;

    if (extras[extras_cnt].len > MAX_DICT_FILE)
      FATAL("Keyword too big in line %u (%s, limit is %s)", cur_line,
            DMS(klen), DMS(MAX_DICT_FILE));

    if (*min_len > klen)
      *min_len = klen;
    if (*max_len < klen)
      *max_len = klen;

    extras_cnt++;
  }

  fclose(f);
}

/* Read extras from the extras directory and sort them by size. */

static void load_extras(u8 *dir)
{

  DIR *d;
  struct dirent *de;
  u32 min_len = MAX_DICT_FILE, max_len = 0, dict_level = 0;
  u8 *x;

  /* If the name ends with @, extract level and continue. */

  if ((x = strchr(dir, '@')))
  {

    *x = 0;
    dict_level = atoi(x + 1);
  }

  ACTF("Loading extra dictionary from '%s' (level %u)...", dir, dict_level);

  d = opendir(dir);

  if (!d)
  {

    if (errno == ENOTDIR)
    {
      load_extras_file(dir, &min_len, &max_len, dict_level);
      goto check_and_sort;
    }

    PFATAL("Unable to open '%s'", dir);
  }

  if (x)
    FATAL("Dictionary levels not supported for directories.");

  while ((de = readdir(d)))
  {

    struct stat st;
    u8 *fn = alloc_printf("%s/%s", dir, de->d_name);
    s32 fd;

    if (lstat(fn, &st) || access(fn, R_OK))
      PFATAL("Unable to access '%s'", fn);

    /* This also takes care of . and .. */
    if (!S_ISREG(st.st_mode) || !st.st_size)
    {

      ck_free(fn);
      continue;
    }

    if (st.st_size > MAX_DICT_FILE)
      FATAL("Extra '%s' is too big (%s, limit is %s)", fn,
            DMS(st.st_size), DMS(MAX_DICT_FILE));

    if (min_len > st.st_size)
      min_len = st.st_size;
    if (max_len < st.st_size)
      max_len = st.st_size;

    extras = ck_realloc_block(extras, (extras_cnt + 1) *
                                          sizeof(struct extra_data));

    extras[extras_cnt].data = ck_alloc(st.st_size);
    extras[extras_cnt].len = st.st_size;

    fd = open(fn, O_RDONLY);

    if (fd < 0)
      PFATAL("Unable to open '%s'", fn);

    ck_read(fd, extras[extras_cnt].data, st.st_size, fn);

    close(fd);
    ck_free(fn);

    extras_cnt++;
  }

  closedir(d);

check_and_sort:

  if (!extras_cnt)
    FATAL("No usable files in '%s'", dir);

  qsort(extras, extras_cnt, sizeof(struct extra_data), compare_extras_len);

  OKF("Loaded %u extra tokens, size range %s to %s.", extras_cnt,
      DMS(min_len), DMS(max_len));

  if (max_len > 32)
    WARNF("Some tokens are relatively large (%s) - consider trimming.",
          DMS(max_len));

  if (extras_cnt > MAX_DET_EXTRAS)
    WARNF("More than %u tokens - will use them probabilistically.",
          MAX_DET_EXTRAS);
}

/* Helper function for maybe_add_auto() */

static inline u8 memcmp_nocase(u8 *m1, u8 *m2, u32 len)
{

  while (len--)
    if (tolower(*(m1++)) ^ tolower(*(m2++)))
      return 1;
  return 0;
}

/* Maybe add automatic extra. */

static void maybe_add_auto(u8 *mem, u32 len)
{

  u32 i;

  /* Allow users to specify that they don't want auto dictionaries. */

  if (!MAX_AUTO_EXTRAS || !USE_AUTO_EXTRAS)
    return;

  /* Skip runs of identical bytes. */

  for (i = 1; i < len; i++)
    if (mem[0] ^ mem[i])
      break;

  if (i == len)
    return;

  /* Reject builtin interesting values. */

  if (len == 2)
  {

    i = sizeof(interesting_16) >> 1;

    while (i--)
      if (*((u16 *)mem) == interesting_16[i] ||
          *((u16 *)mem) == SWAP16(interesting_16[i]))
        return;
  }

  if (len == 4)
  {

    i = sizeof(interesting_32) >> 2;

    while (i--)
      if (*((u32 *)mem) == interesting_32[i] ||
          *((u32 *)mem) == SWAP32(interesting_32[i]))
        return;
  }

  /* Reject anything that matches existing extras. Do a case-insensitive
     match. We optimize by exploiting the fact that extras[] are sorted
     by size. */

  for (i = 0; i < extras_cnt; i++)
    if (extras[i].len >= len)
      break;

  for (; i < extras_cnt && extras[i].len == len; i++)
    if (!memcmp_nocase(extras[i].data, mem, len))
      return;

  /* Last but not least, check a_extras[] for matches. There are no
     guarantees of a particular sort order. */

  auto_changed = 1;

  for (i = 0; i < a_extras_cnt; i++)
  {

    if (a_extras[i].len == len && !memcmp_nocase(a_extras[i].data, mem, len))
    {

      a_extras[i].hit_cnt++;
      goto sort_a_extras;
    }
  }

  /* At this point, looks like we're dealing with a new entry. So, let's
     append it if we have room. Otherwise, let's randomly evict some other
     entry from the bottom half of the list. */

  if (a_extras_cnt < MAX_AUTO_EXTRAS)
  {

    a_extras = ck_realloc_block(a_extras, (a_extras_cnt + 1) *
                                              sizeof(struct extra_data));

    a_extras[a_extras_cnt].data = ck_memdup(mem, len);
    a_extras[a_extras_cnt].len = len;
    a_extras_cnt++;
  }
  else
  {

    i = MAX_AUTO_EXTRAS / 2 +
        UR((MAX_AUTO_EXTRAS + 1) / 2);

    ck_free(a_extras[i].data);

    a_extras[i].data = ck_memdup(mem, len);
    a_extras[i].len = len;
    a_extras[i].hit_cnt = 0;
  }

sort_a_extras:

  /* First, sort all auto extras by use count, descending order. */

  qsort(a_extras, a_extras_cnt, sizeof(struct extra_data),
        compare_extras_use_d);

  /* Then, sort the top USE_AUTO_EXTRAS entries by size. */

  qsort(a_extras, MIN(USE_AUTO_EXTRAS, a_extras_cnt),
        sizeof(struct extra_data), compare_extras_len);
}

/* Save automatically generated extras. */

static void save_auto(void)
{

  u32 i;

  if (!auto_changed)
    return;
  auto_changed = 0;

  for (i = 0; i < MIN(USE_AUTO_EXTRAS, a_extras_cnt); i++)
  {

    u8 *fn = alloc_printf("%s/queue/.state/auto_extras/auto_%06u", out_dir, i);
    s32 fd;

    fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (fd < 0)
      PFATAL("Unable to create '%s'", fn);

    ck_write(fd, a_extras[i].data, a_extras[i].len, fn);

    close(fd);
    ck_free(fn);
  }
}

/* Load automatically generated extras. */

static void load_auto(void)
{

  u32 i;

  for (i = 0; i < USE_AUTO_EXTRAS; i++)
  {

    u8 tmp[MAX_AUTO_EXTRA + 1];
    u8 *fn = alloc_printf("%s/.state/auto_extras/auto_%06u", in_dir, i);
    s32 fd, len;

    fd = open(fn, O_RDONLY, 0600);

    if (fd < 0)
    {

      if (errno != ENOENT)
        PFATAL("Unable to open '%s'", fn);
      ck_free(fn);
      break;
    }

    /* We read one byte more to cheaply detect tokens that are too
       long (and skip them). */

    len = read(fd, tmp, MAX_AUTO_EXTRA + 1);

    if (len < 0)
      PFATAL("Unable to read from '%s'", fn);

    if (len >= MIN_AUTO_EXTRA && len <= MAX_AUTO_EXTRA)
      maybe_add_auto(tmp, len);

    close(fd);
    ck_free(fn);
  }

  if (i)
    OKF("Loaded %u auto-discovered dictionary tokens.", i);
  else
    OKF("No auto-generated dictionary tokens to reuse.");
}

/* Destroy extras. */

static void destroy_extras(void)
{

  u32 i;

  for (i = 0; i < extras_cnt; i++)
    ck_free(extras[i].data);

  ck_free(extras);

  for (i = 0; i < a_extras_cnt; i++)
    ck_free(a_extras[i].data);

  ck_free(a_extras);
}

/* Move process to the network namespace "netns_name" */

static void move_process_to_netns()
{
  const char *netns_path_fmt = "/var/run/netns/%s";
  char netns_path[272]; /* 15 for "/var/.." + 256 for netns name + 1 '\0' */
  int netns_fd;

  if (strlen(netns_name) > 256)
    FATAL("Network namespace name \"%s\" is too long", netns_name);

  sprintf(netns_path, netns_path_fmt, netns_name);

  netns_fd = open(netns_path, O_RDONLY);
  if (netns_fd == -1)
    PFATAL("Unable to open %s", netns_path);

  if (setns(netns_fd, CLONE_NEWNET) == -1)
    PFATAL("setns failed");
}

/* Spin up fork server (instrumented mode only). The idea is explained here:

   http://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html

   In essence, the instrumentation allows us to skip execve(), and just keep
   cloning a stopped child. So, we just execute once, and then send commands
   through a pipe. The other part of this logic is in afl-as.h. */

EXP_ST void init_forkserver(char **argv)
{

  static struct itimerval it;
  int st_pipe[2], ctl_pipe[2];
  int status;
  s32 rlen;

  ACTF("Spinning up the fork server...");

  if (pipe(st_pipe) || pipe(ctl_pipe))
    PFATAL("pipe() failed");

  forksrv_pid = fork();

  if (forksrv_pid < 0)
    PFATAL("fork() failed");

  if (!forksrv_pid)
  {

    struct rlimit r;

    /* Umpf. On OpenBSD, the default fd limit for root users is set to
       soft 128. Let's try to fix that... */

    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSRV_FD + 2)
    {

      r.rlim_cur = FORKSRV_FD + 2;
      setrlimit(RLIMIT_NOFILE, &r); /* Ignore errors */
    }

    if (mem_limit)
    {

      r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

      setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

      /* This takes care of OpenBSD, which doesn't have RLIMIT_AS, but
         according to reliable sources, RLIMIT_DATA covers anonymous
         maps - so we should be getting good protection against OOM bugs. */

      setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */
    }

    /* Dumping cores is slow and can lead to anomalies if SIGKILL is delivered
       before the dump is complete. */

    r.rlim_max = r.rlim_cur = 0;

    setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

    /* Move the process to the different namespace. */

    if (netns_name)
      move_process_to_netns();

    /* Isolate the process and configure standard descriptors. If out_file is
       specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

    setsid();

    dup2(dev_null_fd, 1);
    dup2(dev_null_fd, 2);

    if (out_file)
    {

      dup2(dev_null_fd, 0);
    }
    else
    {

      dup2(out_fd, 0);
      close(out_fd);
    }

    /* Set up control and status pipes, close the unneeded original fds. */

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0)
      PFATAL("dup2() failed");
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0)
      PFATAL("dup2() failed");

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    close(out_dir_fd);
    close(dev_null_fd);
    close(dev_urandom_fd);
    close(fileno(plot_file));

    /* This should improve performance a bit, since it stops the linker from
       doing extra work post-fork(). */

    if (!getenv("LD_BIND_LAZY"))
      setenv("LD_BIND_NOW", "1", 0);

    /* Set sane defaults for ASAN if nothing else specified. */

    setenv("ASAN_OPTIONS", "abort_on_error=1:"
                           "detect_leaks=0:"
                           "symbolize=0:"
                           "allocator_may_return_null=1",
           0);

    /* MSAN is tricky, because it doesn't support abort_on_error=1 at this
       point. So, we do this in a very hacky way. */

    setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                                                              "symbolize=0:"
                                                              "abort_on_error=1:"
                                                              "allocator_may_return_null=1:"
                                                              "msan_track_origins=0",
           0);

    execv(target_path, argv);

    /* Use a distinctive bitmap signature to tell the parent about execv()
       falling through. */

    *(u32 *)trace_bits = EXEC_FAIL_SIG;
    exit(0);
  }

  /* Close the unneeded endpoints. */

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  fsrv_ctl_fd = ctl_pipe[1];
  fsrv_st_fd = st_pipe[0];

  /* Wait for the fork server to come up, but don't wait too long. */

  it.it_value.tv_sec = ((exec_tmout * FORK_WAIT_MULT) / 1000);
  it.it_value.tv_usec = ((exec_tmout * FORK_WAIT_MULT) % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  rlen = read(fsrv_st_fd, &status, 4);

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. */

  if (rlen == 4)
  {
    OKF("All right - fork server is up.");
    return;
  }

  if (child_timed_out)
    FATAL("Timeout while initializing fork server (adjusting -t may help)");

  if (waitpid(forksrv_pid, &status, 0) <= 0)
    PFATAL("waitpid() failed");

  if (WIFSIGNALED(status))
  {

    if (mem_limit && mem_limit < 500 && uses_asan)
    {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! Since it seems to be built with ASAN and you have a\n"
           "    restrictive memory limit configured, this is expected; please read\n"
           "    %s/notes_for_asan.txt for help.\n",
           doc_path);
    }
    else if (!mem_limit)
    {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! There are several probable explanations:\n\n"

           "    - The binary is just buggy and explodes entirely on its own. If so, you\n"
           "      need to fix the underlying problem or find a better replacement.\n\n"

#ifdef __APPLE__

           "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
           "      break afl-fuzz performance optimizations when running platform-specific\n"
           "      targets. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

           "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
           "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");
    }
    else
    {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! There are several probable explanations:\n\n"

           "    - The current memory limit (%s) is too restrictive, causing the\n"
           "      target to hit an OOM condition in the dynamic linker. Try bumping up\n"
           "      the limit with the -m setting in the command line. A simple way confirm\n"
           "      this diagnosis would be:\n\n"

#ifdef RLIMIT_AS
           "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
           "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif /* ^RLIMIT_AS */

           "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
           "      estimate the required amount of virtual memory for the binary.\n\n"

           "    - The binary is just buggy and explodes entirely on its own. If so, you\n"
           "      need to fix the underlying problem or find a better replacement.\n\n"

#ifdef __APPLE__

           "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
           "      break afl-fuzz performance optimizations when running platform-specific\n"
           "      targets. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

           "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
           "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
           DMS(mem_limit << 20), mem_limit - 1);
    }

    FATAL("Fork server crashed with signal %d", WTERMSIG(status));
  }

  if (*(u32 *)trace_bits == EXEC_FAIL_SIG)
    FATAL("Unable to execute target application ('%s')", argv[0]);

  if (mem_limit && mem_limit < 500 && uses_asan)
  {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated before we could complete a\n"
         "    handshake with the injected code. Since it seems to be built with ASAN and\n"
         "    you have a restrictive memory limit configured, this is expected; please\n"
         "    read %s/notes_for_asan.txt for help.\n",
         doc_path);
  }
  else if (!mem_limit)
  {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated before we could complete a\n"
         "    handshake with the injected code. Perhaps there is a horrible bug in the\n"
         "    fuzzer. Poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");
  }
  else
  {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated before we could complete a\n"
         "    handshake with the injected code. There are %s probable explanations:\n\n"

         "%s"
         "    - The current memory limit (%s) is too restrictive, causing an OOM\n"
         "      fault in the dynamic linker. This can be fixed with the -m option. A\n"
         "      simple way to confirm the diagnosis may be:\n\n"

#ifdef RLIMIT_AS
         "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
         "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif /* ^RLIMIT_AS */

         "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
         "      estimate the required amount of virtual memory for the binary.\n\n"

         "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
         "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
         getenv(DEFER_ENV_VAR) ? "three" : "two",
         getenv(DEFER_ENV_VAR) ? "    - You are using deferred forkserver, but __AFL_INIT() is never\n"
                                 "      reached before the program terminates.\n\n"
                               : "",
         DMS(mem_limit << 20), mem_limit - 1);
  }

  FATAL("Fork server handshake failed");
}

/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update trace_bits[]. */

static u8 run_target(char **argv, u32 timeout)
{

  static struct itimerval it;
  static u32 prev_timed_out = 0;
  static u64 exec_ms = 0;

  int status = 0;
  u32 tb4;

  child_timed_out = 0;

  /* After this memset, trace_bits[] are effectively volatile, so we
     must prevent any earlier operations from venturing into that
     territory. */

  memset(trace_bits, 0, MAP_SIZE);
  MEM_BARRIER();

  /* ── MQTT Persistent Server Mode: reuse child across test cases ────
   *
   * When the broker child from a previous exec is still alive, we skip
   * the forkserver fork and just reconnect TCP.  The forkserver is
   * blocked in waitpid(child) — we leave it there until we decide to
   * re-fork (every mqtt_persistent_limit execs, or on crash/timeout).
   *
   * Disabled during calibration (mqtt_in_calibration) so that stability
   * measurement uses deterministic fresh-forked children. */

  if (mqtt_persistent_mode && mqtt_persistent_active
      && !mqtt_in_calibration) {

    /* Verify the persisted child is still alive. */
    if (kill(mqtt_persistent_pid, 0) == 0) {

      /* ── Reuse path: child alive ──────────────────────────────── */
      child_pid = mqtt_persistent_pid;   /* SIGALRM needs this */
      child_timed_out = 0;

      it.it_value.tv_sec  = (timeout / 1000);
      it.it_value.tv_usec = (timeout % 1000) * 1000;
      setitimer(ITIMER_REAL, &it, NULL);

      mqtt_persistent_skip_kill = 1;
      if (use_net) send_over_network();
      mqtt_persistent_skip_kill = 0;

      /* Check: did the child survive? */
      if (child_timed_out || kill(mqtt_persistent_pid, 0) != 0) {
        /* Child died (timeout or crash).  The forkserver's waitpid()
         * has now returned — read the exit status it wrote. */
        s32 res;
        if ((res = read(fsrv_st_fd, &status, 4)) != 4) {
          if (stop_soon) return 0;
          RPFATAL(res, "Unable to communicate with fork server "
                       "(persistent child died)");
        }
        mqtt_persistent_active = 0;
        mqtt_persistent_count  = 0;
        mqtt_persistent_pid    = 0;
        child_pid = 0;

        /* Cancel timer */
        it.it_value.tv_sec = 0; it.it_value.tv_usec = 0;
        setitimer(ITIMER_REAL, &it, NULL);

        total_execs++;
        MEM_BARRIER();

#ifdef WORD_SIZE_64
        classify_counts((u64 *)trace_bits);
#else
        classify_counts((u32 *)trace_bits);
#endif
        prev_timed_out = child_timed_out;

        if (child_timed_out && WIFSIGNALED(status)
            && WTERMSIG(status) == SIGKILL)
          return FAULT_TMOUT;
        if (WIFSIGNALED(status) && !stop_soon)
          return FAULT_CRASH;
        return FAULT_NONE;
      }

      /* Child alive — cancel timer, bump counters. */
      it.it_value.tv_sec = 0; it.it_value.tv_usec = 0;
      setitimer(ITIMER_REAL, &it, NULL);

      total_execs++;
      mqtt_persistent_count++;

      /* Time to re-fork?  Kill the child, read status, reset. */
      if (mqtt_persistent_count >= mqtt_persistent_limit) {
        kill(mqtt_persistent_pid, SIGTERM);
        usleep(5000);                        /* 5 ms graceful shutdown  */
        kill(mqtt_persistent_pid, SIGKILL);  /* ensure it's dead        */
        s32 res;
        if ((res = read(fsrv_st_fd, &status, 4)) != 4) {
          if (stop_soon) return 0;
          RPFATAL(res, "Unable to communicate with fork server "
                       "(persistent re-fork)");
        }
        mqtt_persistent_active = 0;
        mqtt_persistent_count  = 0;
        mqtt_persistent_pid    = 0;
        child_pid = 0;
      }

      MEM_BARRIER();
#ifdef WORD_SIZE_64
      classify_counts((u64 *)trace_bits);
#else
      classify_counts((u32 *)trace_bits);
#endif
      prev_timed_out = 0;
      return FAULT_NONE;

    } else {
      /* ── Child died between execs (spontaneous crash).
       *    Read the forkserver status and fall through to normal fork. */
      s32 res;
      if ((res = read(fsrv_st_fd, &status, 4)) != 4) {
        if (stop_soon) return 0;
        RPFATAL(res, "Unable to communicate with fork server "
                     "(persistent child gone)");
      }
      mqtt_persistent_active = 0;
      mqtt_persistent_count  = 0;
      mqtt_persistent_pid    = 0;
      /* Fall through to standard fork path below. */
    }
  }

  /* If we're running in "dumb" mode, we can't rely on the fork server
     logic compiled into the target program, so we will just keep calling
     execve(). There is a bit of code duplication between here and
     init_forkserver(), but c'est la vie. */

  if (dumb_mode == 1 || no_forkserver)
  {

    child_pid = fork();

    if (child_pid < 0)
      PFATAL("fork() failed");

    if (!child_pid)
    {

      struct rlimit r;

      if (mem_limit)
      {

        r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

        setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

        setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */
      }

      r.rlim_max = r.rlim_cur = 0;

      setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

      /* Move the process to the different namespace. */

      if (netns_name)
        move_process_to_netns();

      /* Isolate the process and configure standard descriptors. If out_file is
         specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

      setsid();

      dup2(dev_null_fd, 1);
      dup2(dev_null_fd, 2);

      if (out_file)
      {

        dup2(dev_null_fd, 0);
      }
      else
      {

        dup2(out_fd, 0);
        close(out_fd);
      }

      /* On Linux, would be faster to use O_CLOEXEC. Maybe TODO. */

      close(dev_null_fd);
      close(out_dir_fd);
      close(dev_urandom_fd);
      close(fileno(plot_file));

      /* Set sane defaults for ASAN if nothing else specified. */

      setenv("ASAN_OPTIONS", "abort_on_error=1:"
                             "detect_leaks=0:"
                             "symbolize=0:"
                             "allocator_may_return_null=1",
             0);

      setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                                                                "symbolize=0:"
                                                                "msan_track_origins=0",
             0);

      execv(target_path, argv);

      /* Use a distinctive bitmap value to tell the parent about execv()
         falling through. */

      *(u32 *)trace_bits = EXEC_FAIL_SIG;
      exit(0);
    }
  }
  else
  {

    s32 res;

    /* In non-dumb mode, we have the fork server up and running, so simply
       tell it to have at it, and then read back PID. */

    if ((res = write(fsrv_ctl_fd, &prev_timed_out, 4)) != 4)
    {

      if (stop_soon)
        return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");
    }

    if ((res = read(fsrv_st_fd, &child_pid, 4)) != 4)
    {

      if (stop_soon)
        return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");
    }

    if (child_pid <= 0)
      FATAL("Fork server is misbehaving (OOM?)");
  }

  /* Configure timeout, as requested by user, then wait for child to terminate. */

  it.it_value.tv_sec = (timeout / 1000);
  it.it_value.tv_usec = (timeout % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  /* The SIGALRM handler simply kills the child_pid and sets child_timed_out. */

  if (dumb_mode == 1 || no_forkserver)
  {
    if (use_net) {
      int net_rc = send_over_network();
      /* H4-fix: For MQTT, log network I/O failures for diagnostics.
       * Text protocols: net_rc is discarded (original behavior). */
      if (net_rc != 0 && protocol_name
          && strcasecmp(protocol_name, "MQTT") == 0)
        fprintf(stderr, "[H4-warn] send_over_network failed "
                "(rc=%d, dumb_mode)\n", net_rc);
    }
    if (waitpid(child_pid, &status, 0) <= 0)
      PFATAL("waitpid() failed");
  }
  else
  {
    /* MQTT persistent mode: tell send_over_network() to skip the kill. */
    u8 try_persist = (mqtt_persistent_mode && !mqtt_in_calibration);
    if (try_persist) mqtt_persistent_skip_kill = 1;

    if (use_net) {
      int net_rc = send_over_network();
      /* H4-fix: For MQTT, log network I/O failures for diagnostics.
       * Text protocols: net_rc is discarded (original behavior). */
      if (net_rc != 0 && protocol_name
          && strcasecmp(protocol_name, "MQTT") == 0)
        fprintf(stderr, "[H4-warn] send_over_network failed "
                "(rc=%d, forkserver)\n", net_rc);
    }
    mqtt_persistent_skip_kill = 0;

    /* MQTT Persistent: if the child survived, persist it for reuse.
     * The forkserver is blocked in waitpid(child) — we leave it there
     * and reuse the child for the next N test cases. */
    if (try_persist && !child_timed_out
        && kill(child_pid, 0) == 0) {

      mqtt_persistent_active = 1;
      mqtt_persistent_pid    = child_pid;
      mqtt_persistent_count  = 1;

      /* Cancel timer. */
      it.it_value.tv_sec = 0; it.it_value.tv_usec = 0;
      setitimer(ITIMER_REAL, &it, NULL);

      total_execs++;
      MEM_BARRIER();

#ifdef WORD_SIZE_64
      classify_counts((u64 *)trace_bits);
#else
      classify_counts((u32 *)trace_bits);
#endif
      prev_timed_out = 0;
      return FAULT_NONE;
    }

    /* Not persisting (calibration / timeout / child died).
     * Read exit status from forkserver normally. */
    s32 res;

    if ((res = read(fsrv_st_fd, &status, 4)) != 4)
    {

      if (stop_soon)
        return 0;
      RPFATAL(res, "Unable to communicate with fork server (OOM?)");
    }
  }

  if (!WIFSTOPPED(status))
    child_pid = 0;

  getitimer(ITIMER_REAL, &it);
  exec_ms = (u64)timeout - (it.it_value.tv_sec * 1000 +
                            it.it_value.tv_usec / 1000);

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  total_execs++;
// Usage: export CFLAGS="-D SHORT_BENCH" or export CFLGAS="-D LONG_BENCH"
#ifdef LONG_BENCH
  if (total_execs == 1000000)
  {
    OKF("AFLNet: Done!");
    raise(SIGINT);
  }
#elif SHORT_BENCH
  if (total_execs == 10000)
  {
    OKF("AFLNet: Done!");
    raise(SIGINT);
  }
#else
#endif

  /* Any subsequent operations on trace_bits must not be moved by the
     compiler below this point. Past this location, trace_bits[] behave
     very normally and do not have to be treated as volatile. */

  MEM_BARRIER();

  tb4 = *(u32 *)trace_bits;

#ifdef WORD_SIZE_64
  classify_counts((u64 *)trace_bits);
#else
  classify_counts((u32 *)trace_bits);
#endif /* ^WORD_SIZE_64 */

  prev_timed_out = child_timed_out;

  /* Report outcome to caller. */

  if (WIFSIGNALED(status) && !stop_soon)
  {

    kill_signal = WTERMSIG(status);

    if (child_timed_out && kill_signal == SIGKILL)
      return FAULT_TMOUT;

    if (kill_signal == SIGTERM) {
      /* M1-fix: For MQTT, log when child received SIGTERM that we
       * didn't send (terminate_child=0) — indicates external kill
       * (OOM killer, cgroup limits, etc.).  Expected SIGTERMs from
       * our own terminate_child path are silent.
       * Text protocols: always silent (original behavior). */
      if (!terminate_child && protocol_name
          && strcasecmp(protocol_name, "MQTT") == 0)
        fprintf(stderr, "[M1-warn] MQTT child received unexpected "
                "SIGTERM (terminate_child=0)\n");
      return FAULT_NONE;
    }

    /* Fix-14c: SIGKILL from send_over_network() bounded-kill-wait
     * escalation is a deliberate termination, NOT a timeout.
     *
     * Safety argument:
     *  1. Real timeouts (SIGALRM → SIGKILL) are already caught ABOVE
     *     via child_timed_out — that check runs first and correctly
     *     returns FAULT_TMOUT.  We only reach here when child_timed_out
     *     is FALSE, meaning the exec_tmout timer did NOT fire.
     *  2. child_force_killed is set in send_over_network() AFTER the
     *     socket is closed and network I/O is complete.  The process
     *     is in shutdown (dbus/avahi cleanup, fd teardown), not in a
     *     crash-reportable state.
     *  3. Any real crash (SIGSEGV/SIGABRT) completes in <200 ms
     *     (ASAN handlers included); the 200 ms grace period in
     *     send_over_network() is sufficient.
     *
     * Returning FAULT_TMOUT here (the old Fix-14a behavior) caused:
     *  - Coverage checked against virgin_tmout instead of virgin_bits,
     *    silently discarding new queue entries (paths_found halved).
     *  - Inflated unique_hangs from non-hanging inputs (140 false
     *    hangs on forked-daapd vs 17 on baseline).
     *  - subseq_tmouts accumulation reducing mutation depth.
     *  - Hang-verification re-run was ALREADY non-functional for
     *    servers with exec_tmout > hang_tmout (e.g. forked-daapd
     *    -t 5000+ vs EXEC_TIMEOUT=1000).
     *
     * Scope: only affects servers that take >200 ms to die after
     * SIGTERM (e.g. forked-daapd with dbus/avahi).  Fast-exit
     * servers never trigger child_force_killed, so they are
     * completely unaffected by this change. */
    if (kill_signal == SIGKILL && child_force_killed)
    {
      child_force_killed = 0;
      forced_kills++;
      return FAULT_NONE;
    }

    return FAULT_CRASH;
  }

  /* A somewhat nasty hack for MSAN, which doesn't support abort_on_error and
     must use a special exit code. */

  if (uses_asan && WEXITSTATUS(status) == MSAN_ERROR)
  {
    kill_signal = 0;
    return FAULT_CRASH;
  }

  if ((dumb_mode == 1 || no_forkserver) && tb4 == EXEC_FAIL_SIG)
    return FAULT_ERROR;

  /* It makes sense to account for the slowest units only if the testcase was run
  under the user defined timeout. */
  if (!(timeout > exec_tmout) && (slowest_exec_ms < exec_ms))
  {
    slowest_exec_ms = exec_ms;
  }

  return FAULT_NONE;
}

/* Write modified data to file for testing. If out_file is set, the old file
   is unlinked and a new one is created. Otherwise, out_fd is rewound and
   truncated. */

static void write_to_testcase(void *mem, u32 len)
{

  // AFLNet sends data via network so it does not need this function
}

static void show_stats(void);

/* Calibrate a new test case. This is done when processing the input directory
   to warn about flaky or otherwise problematic test cases early on; and when
   new paths are discovered to detect variable behavior and so on. */

static u8 calibrate_case(char **argv, struct queue_entry *q, u8 *use_mem,
                         u32 handicap, u8 from_queue)
{

  static u8 first_trace[MAP_SIZE];

  /* MQTT Persistent Mode: disable child-reuse during calibration so
   * that each run_target() forks a clean child.  This ensures
   * deterministic coverage for accurate stability measurement. */
  if (mqtt_persistent_mode) {
    /* If a persistent child is alive, kill it and drain forkserver. */
    if (mqtt_persistent_active && mqtt_persistent_pid > 0) {
      kill(mqtt_persistent_pid, SIGKILL);
      s32 res;
      int _status;
      res = read(fsrv_st_fd, &_status, 4);
      (void)res;
      mqtt_persistent_active = 0;
      mqtt_persistent_count  = 0;
      mqtt_persistent_pid    = 0;
    }
    mqtt_in_calibration = 1;
  }

  u8 fault = 0, new_bits = 0, var_detected = 0,
     first_run = (q->exec_cksum == 0);

  u64 start_us, stop_us;

  s32 old_sc = stage_cur, old_sm = stage_max;
  u32 use_tmout = exec_tmout;
  u8 *old_sn = stage_name;

  /* Be a bit more generous about timeouts when resuming sessions, or when
     trying to calibrate already-added finds. This helps avoid trouble due
     to intermittent latency. */

  if (!from_queue || resuming_fuzz)
    use_tmout = MAX(exec_tmout + CAL_TMOUT_ADD,
                    exec_tmout * CAL_TMOUT_PERC / 100);

  q->cal_failed++;

  stage_name = "calibration";
  stage_max = fast_cal ? 3 : CAL_CYCLES;

  /* Make sure the forkserver is up before we do anything, and let's not
     count its spin-up time toward binary calibration. */

  if (dumb_mode != 1 && !no_forkserver && !forksrv_pid)
    init_forkserver(argv);

  if (q->exec_cksum)
    memcpy(first_trace, trace_bits, MAP_SIZE);

  start_us = get_cur_time_us();

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++)
  {

    u32 cksum;

    if (!first_run && !(stage_cur % stats_update_freq))
      show_stats();

    write_to_testcase(use_mem, q->len);

    fault = run_target(argv, use_tmout);

    /* stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. */

    if (stop_soon || fault != crash_mode)
      goto abort_calibration;

    if (!dumb_mode && !stage_cur && !count_bytes(trace_bits))
    {
      fault = FAULT_NOINST;
      goto abort_calibration;
    }

    cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

    if (q->exec_cksum != cksum)
    {

      u8 hnb = has_new_bits(virgin_bits);
      if (hnb > new_bits)
        new_bits = hnb;

      if (q->exec_cksum)
      {

        u32 i;

        for (i = 0; i < MAP_SIZE; i++)
        {

          if (!var_bytes[i] && first_trace[i] != trace_bits[i])
          {

            var_bytes[i] = 1;
            stage_max = CAL_CYCLES_LONG;
          }
        }

        var_detected = 1;
      }
      else
      {

        q->exec_cksum = cksum;
        memcpy(first_trace, trace_bits, MAP_SIZE);
      }
    }
  }

  stop_us = get_cur_time_us();

  total_cal_us += stop_us - start_us;
  total_cal_cycles += stage_max;

  /* OK, let's collect some stats about the performance of this test case.
     This is used for fuzzing air time calculations in calculate_score(). */

  q->exec_us = (stop_us - start_us) / stage_max;
  q->bitmap_size = count_bytes(trace_bits);
  q->handicap = handicap;
  q->cal_failed = 0;

  total_bitmap_size += q->bitmap_size;
  total_bitmap_entries++;

  update_bitmap_score(q);

  /* If this case didn't result in new output from the instrumentation, tell
     parent. This is a non-critical problem, but something to warn the user
     about. */

  if (!dumb_mode && first_run && !fault && !new_bits)
    fault = FAULT_NOBITS;

abort_calibration:

  if (new_bits == 2 && !q->has_new_cov)
  {
    q->has_new_cov = 1;
    queued_with_cov++;
  }

  /* Mark variable paths. */

  if (var_detected)
  {

    var_byte_count = count_bytes(var_bytes);

    if (!q->var_behavior)
    {
      mark_as_variable(q);
      queued_variable++;
    }
  }

  stage_name = old_sn;
  stage_cur = old_sc;
  stage_max = old_sm;

  /* MQTT Persistent Mode: re-enable child-reuse after calibration. */
  if (mqtt_persistent_mode)
    mqtt_in_calibration = 0;

  if (!first_run)
    show_stats();

  return fault;
}

/* Examine map coverage. Called once, for first test case. */

static void check_map_coverage(void)
{

  u32 i;

  if (count_bytes(trace_bits) < 100)
    return;

  for (i = (1 << (MAP_SIZE_POW2 - 1)); i < MAP_SIZE; i++)
    if (trace_bits[i])
      return;

  WARNF("Recompile binary with newer version of afl to improve coverage!");
}

/* ============================================
 * ChatAFL-Opt: Initialize Grammar Hypothesis System
 * ============================================ */
static void init_grammar_hypothesis_system(void)
{
  if (!hypothesis_mode)
  {
    fprintf(stderr, "[!] init_grammar_hypothesis_system called but hypothesis_mode=0\n");
    return;
  }

  ACTF("Initializing Grammar Hypothesis System...");
  fprintf(stderr, "[DEBUG] Protocol: %s, Output dir: %s\n", 
          protocol_name ? protocol_name : "UNKNOWN", out_dir);

  // Collect PCAP samples from seed corpus
  char **pcap_samples = NULL;
  size_t pcap_count = 0;
  size_t queue_length = 0;

  struct queue_entry *q = queue;
  
  // Count queue entries for diagnostics
  struct queue_entry *q_tmp = queue;
  while (q_tmp) {
    queue_length++;
    q_tmp = q_tmp->next;
  }
  
  fprintf(stderr, "[DEBUG] Queue has %zu entries, collecting up to 10 PCAP samples\n", queue_length);
  
  while (q && pcap_count < 10)
  { // Limit to 10 samples
    fprintf(stderr, "[DEBUG] Processing seed: %s (len=%u)\n", q->fname, q->len);
    s32 fd = open(q->fname, O_RDONLY);
    if (fd >= 0)
    {
      u8 *sample = ck_alloc_nozero(q->len + 1);
      if (read(fd, sample, q->len) == (ssize_t)q->len)
      {
        sample[q->len] = '\0';
        pcap_samples = ck_realloc(pcap_samples, (pcap_count + 1) * sizeof(char *));
        pcap_samples[pcap_count++] = (char *)sample;
        fprintf(stderr, "[DEBUG] Added PCAP sample %zu (len=%u)\n", pcap_count, q->len);
      }
      else
      {
        fprintf(stderr, "[!] Failed to read seed file: %s\n", q->fname);
        ck_free(sample);
      }
      close(fd);
    }
    else
    {
      fprintf(stderr, "[!] Failed to open seed file: %s (errno=%d: %s)\n", 
              q->fname, errno, strerror(errno));
    }
    q = q->next;
  }

  fprintf(stderr, "[DEBUG] Collected %zu PCAP samples from %zu queue entries\n", 
          pcap_count, queue_length);

  if (pcap_count == 0)
  {
    WARNF("No PCAP samples collected, hypothesis system disabled");
    hypothesis_mode = 0;
    return;
  }

  // Initialize hypothesis context
  fprintf(stderr, "[DEBUG] Calling init_hypothesis_context with protocol=%s, pcap_count=%zu\n",
          protocol_name ? protocol_name : "UNKNOWN", pcap_count);
  
  hypothesis_ctx = init_hypothesis_context(
      protocol_name ? protocol_name : "UNKNOWN",
      NULL, // RFC text (would be loaded from file in production)
      pcap_samples,
      pcap_count);

  if (!hypothesis_ctx)
  {
    fprintf(stderr, "[!] init_hypothesis_context returned NULL\n");
    FATAL("Failed to initialize hypothesis context");
  }

  fprintf(stderr, "[DEBUG] Hypothesis context initialized successfully\n");

  /* ── Gap-1 fix: Collect server responses from responses-ipsm/ ──
   * By the time lazy init fires (first plateau), the fuzzer has already
   * saved server response files during calibration / early fuzzing.
   * We scan the directory and feed up to 10 sanitized response snippets
   * into hypothesis_ctx so construct_hypothesis_generation_prompt() can
   * inject them into the LLM prompt, giving the model concrete examples
   * of what the server actually returns. */
  {
    char *resp_dir_path = alloc_printf("%s/responses-ipsm", out_dir);
    DIR *resp_dir = opendir(resp_dir_path);
    if (resp_dir) {
      char **srv_responses = NULL;
      size_t srv_count = 0;
      struct dirent *ent;

      while ((ent = readdir(resp_dir)) != NULL && srv_count < 10) {
        if (ent->d_name[0] == '.') continue;          /* skip . / .. */

        char *fpath = alloc_printf("%s/%s", resp_dir_path, ent->d_name);
        u32 *resp_bytes = NULL;
        u32 resp_cnt = 0, buf_len = 0;
        char **raw = get_responses_from_file((u8 *)fpath, &resp_bytes,
                                             &resp_cnt, &buf_len);
        if (raw && resp_cnt > 0) {
          /* Concatenate individual response segments into one string
           * (capped at 2 KB to keep the prompt reasonable). */
          size_t total = 0;
          for (u32 r = 0; r < resp_cnt; r++) {
            u32 seg_len = (r == 0) ? resp_bytes[0]
                                   : resp_bytes[r] - resp_bytes[r - 1];
            total += seg_len;
          }
          if (total > 2048) total = 2048;

          char *concat = (char *)ck_alloc(total + 1);
          size_t off = 0;
          u32 prev = 0;
          for (u32 r = 0; r < resp_cnt && off < total; r++) {
            u32 seg_len = resp_bytes[r] - prev;
            size_t copy = (off + seg_len > total) ? total - off : seg_len;
            memcpy(concat + off, raw[r], copy);
            off += copy;
            prev = resp_bytes[r];
          }
          concat[off] = '\0';

          /* For binary protocols (MQTT etc.), raw bytes sanitized to spaces
           * are useless to the LLM.  Hex-encode them instead so the model
           * can see actual packet content, e.g.:
           *   "HEX[20020000] (4 bytes, MQTT CONNACK)"
           * The LLM knows MQTT wire format and can decode these bytes into
           * meaningful constraints (packet type nibble, return code, etc.).
           *
           * For text protocols the existing printable-sanitize is ideal
           * because the LLM sees readable status lines like
           *   "220 Welcome to ProFTPD\r\n" */
          if (is_binary_protocol(protocol_name)) {
            /* Hex-encode: each byte → 2 hex chars, plus prefix/suffix */
            size_t hex_sz = 4 + off * 2 + 32;  /* "HEX[" + hex + "] (N bytes)\0" */
            char *hex = (char *)ck_alloc(hex_sz);
            int hoff = snprintf(hex, hex_sz, "HEX[");
            for (size_t k = 0; k < off && (size_t)hoff < hex_sz - 20; k++)
              hoff += snprintf(hex + hoff, hex_sz - hoff, "%02x",
                               (unsigned char)concat[k]);
            hoff += snprintf(hex + hoff, hex_sz - hoff, "] (%zu bytes)", off);
            ck_free(concat);
            concat = hex;
          } else {
            /* Text protocol: sanitize non-printable, keep CR/LF/TAB */
            for (size_t k = 0; k < off; k++) {
              unsigned char ch = (unsigned char)concat[k];
              if (ch == '\r' || ch == '\n' || ch == '\t') continue;
              if (!isprint(ch)) concat[k] = ' ';
            }
          }

          srv_responses = (char **)ck_realloc(
              srv_responses, (srv_count + 1) * sizeof(char *));
          srv_responses[srv_count++] = concat;

          /* Free per-file data returned by get_responses_from_file */
          for (u32 r = 0; r < resp_cnt; r++) ck_free(raw[r]);
          ck_free(raw);
          ck_free(resp_bytes);
        }
        ck_free(fpath);
      }
      closedir(resp_dir);

      if (srv_count > 0) {
        hypothesis_ctx->server_responses = srv_responses;
        hypothesis_ctx->response_count   = srv_count;
        fprintf(stderr, "[hypothesis] Gap-1: injected %zu server response "
                        "snippets into hypothesis context\n", srv_count);
      }
    } else {
      fprintf(stderr, "[hypothesis] responses-ipsm/ not found yet — "
                      "hypothesis generation will proceed without server "
                      "response examples\n");
    }
    ck_free(resp_dir_path);
  }

  // Generate initial hypotheses
  fprintf(stderr, "[DEBUG] Calling generate_grammar_hypotheses (max=5)\n");
  int hyp_count = generate_grammar_hypotheses(hypothesis_ctx, 5);
  fprintf(stderr, "[DEBUG] generate_grammar_hypotheses returned %d hypotheses\n", hyp_count);

  if (hyp_count == 0)
  {
    WARNF("No grammar hypotheses generated, continuing in standard mode");
    hypothesis_mode = 0;
    free_hypothesis_context(hypothesis_ctx);
    hypothesis_ctx = NULL;
  }
  else
  {
    OKF("Generated %d grammar hypotheses", hyp_count);

    // Save hypotheses to disk for reproducibility
    char *hyp_dir = alloc_printf("%s/grammar-hypothesis", out_dir);
    fprintf(stderr, "[DEBUG] Creating hypothesis directory: %s\n", hyp_dir);
    
    if (mkdir(hyp_dir, 0700) && errno != EEXIST)
    {
      fprintf(stderr, "[!] Failed to create directory '%s' (errno=%d: %s)\n",
              hyp_dir, errno, strerror(errno));
      PFATAL("Unable to create directory '%s'", hyp_dir);
    }

    fprintf(stderr, "[DEBUG] Saving %zu hypotheses to disk\n", hypothesis_ctx->hypothesis_count);
    for (size_t i = 0; i < hypothesis_ctx->hypothesis_count; i++)
    {
      grammar_hypothesis_t *hyp = hypothesis_ctx->hypotheses[i];
      char *hyp_file = alloc_printf("%s/hypothesis-%llu-%s.json",
                                    hyp_dir, hyp->hypothesis_id, hyp->message_type);
      fprintf(stderr, "[DEBUG] Saving hypothesis %zu to: %s\n", i+1, hyp_file);
      
      int save_result = save_hypothesis_to_file(hyp, hyp_file);
      if (save_result)
      {
        fprintf(stderr, "[+] Successfully saved hypothesis: %s\n", hyp_file);
      }
      else
      {
        fprintf(stderr, "[!] Failed to save hypothesis: %s\n", hyp_file);
      }
      
      ck_free(hyp_file);
    }

    ck_free(hyp_dir);

    // ============================================
    // Fix 1: Integrate hypotheses into protocol_patterns
    // so parse_buffer() can use them during havoc exploit
    // ============================================
    if (protocol_patterns && message_types_set) {
      int integrated = integrate_hypotheses_into_protocol_patterns(
          hypothesis_ctx, protocol_patterns, message_types_set,
          out_dir, protocol_name);
      OKF("Integrated %d hypotheses into protocol_patterns", integrated);
    } else {
      WARNF("protocol_patterns or message_types_set not initialized, "
            "skipping hypothesis integration");
    }
  }

  // Cleanup PCAP samples
  fprintf(stderr, "[DEBUG] Cleaning up %zu PCAP samples\n", pcap_count);
  for (size_t i = 0; i < pcap_count; i++)
  {
    ck_free(pcap_samples[i]);
  }
  ck_free(pcap_samples);

  OKF("Grammar Hypothesis System initialized successfully.");
}

/* ============================================
 * ChatAFL-Opt: Two-Tier Hypothesis Validation (Fix-15)
 *
 * Tier-1: validate_hypothesis_sampled()
 *   Called from common_fuzz_stuff() every HYPOTHESIS_VALIDATION_SAMPLE_RATE-th
 *   execution.  Accepts the ALREADY-PARSED regions — zero extra parsing cost.
 *   Updates fitness / collects counterexamples in O(regions × constraints).
 *
 * Tier-2: periodic_hypothesis_refinement()
 *   Called from the plateau handler path every
 *   HYPOTHESIS_REFINEMENT_CHECK_INTERVAL validations.  Issues at most one
 *   LLM refinement call per invocation.
 *
 * Together they close the "Hypothesis → Validate → Counterexample → Refine"
 * loop that Fix-9b had severed, while keeping hot-path overhead < 0.01%.
 * ============================================ */

/* Tier-1: lightweight sampled validation — reuses pre-parsed regions.
 * Called from common_fuzz_stuff() with regions it already parsed. */
static void validate_hypothesis_sampled(
    u8 *buf, u32 len,
    region_t *regions, u32 region_count)
{
  if (!hypothesis_mode || !hypothesis_ctx || !regions || region_count == 0)
    return;

  hypothesis_validation_count++;

  int binary = is_binary_protocol(protocol_name);

  /* Cap regions scanned per sample to limit worst-case latency.
   * 8 regions × 5 hypotheses × 3 constraints ≈ 120 check_constraint() calls. */
  u32 max_regions = region_count < 8 ? region_count : 8;

  for (u32 r = 0; r < max_regions; r++) {
    u32 rstart = regions[r].start_byte;
    u32 rend   = regions[r].end_byte;
    if (rend >= len) rend = len - 1;
    u32 rlen   = rend - rstart + 1;
    if (rlen < 2) continue;

    /* Determine message type for this region */
    const char *msg_type = NULL;
    char *alloc_type = NULL;

    if (binary && strcasecmp(protocol_name, "MQTT") == 0) {
      unsigned char type_nibble = (buf[rstart] >> 4) & 0x0F;
      msg_type = mqtt_type_nibble_to_name(type_nibble);
    } else if (!binary) {
      alloc_type = extract_text_message_type(buf + rstart, rlen);
      msg_type = alloc_type;
    }

    /* Validate against matching hypothesis(es) */
    for (size_t i = 0; i < hypothesis_ctx->hypothesis_count; i++) {
      grammar_hypothesis_t *hyp = hypothesis_ctx->hypotheses[i];
      if (!hyp->message_type) continue;

      if (msg_type && strcasecmp(hyp->message_type, msg_type) != 0)
        continue;

      int valid = validate_message_against_hypothesis(hyp,
                                                      buf + rstart, rlen);
      /* Fix-20b: Collect counterexample with specific constraint violation
       * details instead of generic "Sampled validation failed".
       * Every 10th failure to avoid flooding. */
      if (!valid && hyp->parse_failure % 10 == 0) {
        char *detail = collect_violation_details(hyp, buf + rstart, rlen);
        add_counterexample(hyp, buf + rstart, rlen,
                           detail ? detail : "Validation failed (no constraint detail)");
        if (detail) ck_free(detail);
      }

      if (msg_type) break;  /* Matched type → next region */
    }

    if (alloc_type) ck_free(alloc_type);
  }
}

/* Tier-2: periodic refinement — issues LLM call if any hypothesis
 * has low fitness AND enough counterexamples.  Safe to call from
 * any non-hot-path location (plateau handler, main-loop tail). */
static void periodic_hypothesis_refinement(void)
{
  if (!hypothesis_mode || !hypothesis_ctx)
    return;

  /* Only check every HYPOTHESIS_REFINEMENT_CHECK_INTERVAL validations */
  if (hypothesis_validation_count == 0 ||
      hypothesis_validation_count % HYPOTHESIS_REFINEMENT_CHECK_INTERVAL != 0)
    return;

  fprintf(stderr,
          "[hypothesis-refine] Checking refinement (validations=%u)\n",
          hypothesis_validation_count);

  for (size_t i = 0; i < hypothesis_ctx->hypothesis_count; i++) {
    grammar_hypothesis_t *hyp = hypothesis_ctx->hypotheses[i];

    /* Log current fitness for observability */
    fprintf(stderr,
            "[hypothesis-refine]   %s: fitness=%.3f success=%u fail=%u ce=%zu\n",
            hyp->message_type, hyp->fitness,
            hyp->parse_success, hyp->parse_failure,
            hyp->counterexample_count);

    /* Refine if fitness < threshold AND ≥3 counterexamples accumulated */
    if (hyp->fitness < FITNESS_THRESHOLD && hyp->counterexample_count >= 3) {
      ACTF("Refining hypothesis for %s (fitness: %.3f, counterexamples: %zu)",
           hyp->message_type, hyp->fitness, hyp->counterexample_count);

      if (refine_hypothesis_with_counterexamples(hypothesis_ctx, hyp)) {
        /* Persist refined hypothesis for reproducibility */
        char *hyp_file = alloc_printf(
            "%s/grammar-hypothesis/hypothesis-%llu-%s-refined-%lu.json",
            out_dir, hyp->hypothesis_id, hyp->message_type, time(NULL));
        save_hypothesis_to_file(hyp, hyp_file);
        ck_free(hyp_file);

        /* Re-integrate refined patterns into IPSM matching */
        if (protocol_patterns && message_types_set) {
          integrate_hypotheses_into_protocol_patterns(
              hypothesis_ctx, protocol_patterns, message_types_set,
              out_dir, protocol_name);
        }

        OKF("Hypothesis refined: %s (new fitness: %.3f)",
            hyp->message_type, hyp->fitness);
      }

      /* Refine at most ONE hypothesis per invocation to bound latency */
      break;
    }
  }
}

/* Perform dry run of all test cases to confirm that the app is working as
   expected. This is done only for the initial inputs, and only once. */

static void perform_dry_run(char **argv)
{

  struct queue_entry *q = queue;
  u32 cal_failures = 0;
  u8 *skip_crashes = getenv("AFL_SKIP_CRASHES");

  while (q)
  {

    u8 *use_mem;
    u8 res;
    s32 fd;

    q->is_initial_seed = 1;

    u8 *fn = strrchr(q->fname, '/') + 1;

    ACTF("Attempting dry run with '%s'...", fn);

    fd = open(q->fname, O_RDONLY);
    if (fd < 0)
      PFATAL("Unable to open '%s'", q->fname);

    use_mem = ck_alloc_nozero(q->len);

    if (read(fd, use_mem, q->len) != q->len)
      FATAL("Short read from '%s'", q->fname);

    close(fd);

    /* AFLNet construct the kl_messages linked list for this queue entry*/
    kl_messages = construct_kl_messages(q->fname, q->regions, q->region_count);

    res = calibrate_case(argv, q, use_mem, 0, 1);
    ck_free(use_mem);

    /* Update state-aware variables (e.g., state machine, regions and their annotations */
    if (state_aware_mode)
      update_state_aware_variables(q, 1);

    /* save the seed to file for replaying */
    u8 *fn_replay = alloc_printf("%s/replayable-queue/%s", out_dir, basename(q->fname));
    save_kl_messages_to_file(kl_messages, fn_replay, 1, messages_sent);
    ck_free(fn_replay);

    /* AFLNet delete the kl_messages */
    delete_kl_messages(kl_messages);

    if (stop_soon)
      return;

    if (res == crash_mode || res == FAULT_NOBITS)
      SAYF(cGRA "    len = %u, map size = %u, exec speed = %llu us\n" cRST,
           q->len, q->bitmap_size, q->exec_us);

    switch (res)
    {

    case FAULT_NONE:

      if (q == queue)
        check_map_coverage();

      if (crash_mode)
        FATAL("Test case '%s' does *NOT* crash", fn);

      break;

    case FAULT_TMOUT:

      if (timeout_given)
      {

        /* The -t nn+ syntax in the command line sets timeout_given to '2' and
           instructs afl-fuzz to tolerate but skip queue entries that time
           out. */

        if (timeout_given > 1)
        {
          WARNF("Test case results in a timeout (skipping)");
          q->cal_failed = CAL_CHANCES;
          cal_failures++;
          break;
        }

        SAYF("\n" cLRD "[-] " cRST
             "The program took more than %u ms to process one of the initial test cases.\n"
             "    Usually, the right thing to do is to relax the -t option - or to delete it\n"
             "    altogether and allow the fuzzer to auto-calibrate. That said, if you know\n"
             "    what you are doing and want to simply skip the unruly test cases, append\n"
             "    '+' at the end of the value passed to -t ('-t %u+').\n",
             exec_tmout,
             exec_tmout);

        FATAL("Test case '%s' results in a timeout", fn);
      }
      else
      {

        SAYF("\n" cLRD "[-] " cRST
             "The program took more than %u ms to process one of the initial test cases.\n"
             "    This is bad news; raising the limit with the -t option is possible, but\n"
             "    will probably make the fuzzing process extremely slow.\n\n"

             "    If this test case is just a fluke, the other option is to just avoid it\n"
             "    altogether, and find one that is less of a CPU hog.\n",
             exec_tmout);

        FATAL("Test case '%s' results in a timeout", fn);
      }

    case FAULT_CRASH:

      if (crash_mode)
        break;

      if (skip_crashes)
      {
        WARNF("Test case results in a crash (skipping)");
        q->cal_failed = CAL_CHANCES;
        cal_failures++;
        break;
      }

      if (mem_limit)
      {

        SAYF("\n" cLRD "[-] " cRST
             "Oops, the program crashed with one of the test cases provided. There are\n"
             "    several possible explanations:\n\n"

             "    - The test case causes known crashes under normal working conditions. If\n"
             "      so, please remove it. The fuzzer should be seeded with interesting\n"
             "      inputs - but not ones that cause an outright crash.\n\n"

             "    - The current memory limit (%s) is too low for this program, causing\n"
             "      it to die due to OOM when parsing valid files. To fix this, try\n"
             "      bumping it up with the -m setting in the command line. If in doubt,\n"
             "      try something along the lines of:\n\n"

#ifdef RLIMIT_AS
             "      ( ulimit -Sv $[%llu << 10]; /path/to/binary [...] <testcase )\n\n"
#else
             "      ( ulimit -Sd $[%llu << 10]; /path/to/binary [...] <testcase )\n\n"
#endif /* ^RLIMIT_AS */

             "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
             "      estimate the required amount of virtual memory for the binary. Also,\n"
             "      if you are using ASAN, see %s/notes_for_asan.txt.\n\n"

#ifdef __APPLE__

             "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
             "      break afl-fuzz performance optimizations when running platform-specific\n"
             "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

             "    - Least likely, there is a horrible bug in the fuzzer. If other options\n"
             "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
             DMS(mem_limit << 20), mem_limit - 1, doc_path);
      }
      else
      {

        SAYF("\n" cLRD "[-] " cRST
             "Oops, the program crashed with one of the test cases provided. There are\n"
             "    several possible explanations:\n\n"

             "    - The test case causes known crashes under normal working conditions. If\n"
             "      so, please remove it. The fuzzer should be seeded with interesting\n"
             "      inputs - but not ones that cause an outright crash.\n\n"

#ifdef __APPLE__

             "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
             "      break afl-fuzz performance optimizations when running platform-specific\n"
             "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

             "    - Least likely, there is a horrible bug in the fuzzer. If other options\n"
             "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");
      }

      FATAL("Test case '%s' results in a crash", fn);

    case FAULT_ERROR:

      FATAL("Unable to execute target application ('%s')", argv[0]);

    case FAULT_NOINST:

      FATAL("No instrumentation detected");

    case FAULT_NOBITS:

      useless_at_start++;

      if (!in_bitmap && !shuffle_queue)
        WARNF("No new instrumentation output, test case may be useless.");

      break;
    }

    if (q->var_behavior)
      WARNF("Instrumentation output varies across runs.");

    q = q->next;
  }

  if (cal_failures)
  {

    if (cal_failures == queued_paths)
      FATAL("All test cases time out%s, giving up!",
            skip_crashes ? " or crash" : "");

    WARNF("Skipped %u test cases (%0.02f%%) due to timeouts%s.", cal_failures,
          ((double)cal_failures) * 100 / queued_paths,
          skip_crashes ? " or crashes" : "");

    if (cal_failures * 5 > queued_paths)
      WARNF(cLRD "High percentage of rejected test cases, check settings!");
  }

  OKF("All test cases processed.");
}

/* Helper function: link() if possible, copy otherwise. */

static void link_or_copy(u8 *old_path, u8 *new_path)
{

  s32 i = link(old_path, new_path);
  s32 sfd, dfd;
  u8 *tmp;

  if (!i)
    return;

  sfd = open(old_path, O_RDONLY);
  if (sfd < 0)
    PFATAL("Unable to open '%s'", old_path);

  dfd = open(new_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (dfd < 0)
    PFATAL("Unable to create '%s'", new_path);

  tmp = ck_alloc(64 * 1024);

  while ((i = read(sfd, tmp, 64 * 1024)) > 0)
    ck_write(dfd, tmp, i, new_path);

  if (i < 0)
    PFATAL("read() failed");

  ck_free(tmp);
  close(sfd);
  close(dfd);
}

static void nuke_resume_dir(void);

/* Create hard links for input test cases in the output directory, choosing
   good names and pivoting accordingly. */

static void pivot_inputs(void)
{

  struct queue_entry *q = queue;
  u32 id = 0;

  ACTF("Creating hard links for all input files...");

  while (q)
  {

    u8 *nfn, *rsl = strrchr(q->fname, '/');
    u32 orig_id;

    if (!rsl)
      rsl = q->fname;
    else
      rsl++;

      /* If the original file name conforms to the syntax and the recorded
         ID matches the one we'd assign, just use the original file name.
         This is valuable for resuming fuzzing runs. */

#ifndef SIMPLE_FILES
#define CASE_PREFIX "id:"
#else
#define CASE_PREFIX "id_"
#endif /* ^!SIMPLE_FILES */

    if (!strncmp(rsl, CASE_PREFIX, 3) &&
        sscanf(rsl + 3, "%06u", &orig_id) == 1 && orig_id == id)
    {

      u8 *src_str;
      u32 src_id;

      resuming_fuzz = 1;
      nfn = alloc_printf("%s/queue/%s", out_dir, rsl);

      /* Since we're at it, let's also try to find parent and figure out the
         appropriate depth for this entry. */

      src_str = strchr(rsl + 3, ':');

      if (src_str && sscanf(src_str + 1, "%06u", &src_id) == 1)
      {

        struct queue_entry *s = queue;
        while (src_id-- && s)
          s = s->next;
        if (s)
          q->depth = s->depth + 1;

        if (max_depth < q->depth)
          max_depth = q->depth;
      }
    }
    else
    {

      /* No dice - invent a new name, capturing the original one as a
         substring. */

#ifndef SIMPLE_FILES

      u8 *use_name = strstr(rsl, ",orig:");

      if (use_name)
        use_name += 6;
      else
        use_name = rsl;
      nfn = alloc_printf("%s/queue/id:%06u,orig:%s", out_dir, id, use_name);

#else

      nfn = alloc_printf("%s/queue/id_%06u", out_dir, id);

#endif /* ^!SIMPLE_FILES */
    }

    /* Pivot to the new queue entry. */

    link_or_copy(q->fname, nfn);
    ck_free(q->fname);
    q->fname = nfn;

    /* Make sure that the passed_det value carries over, too. */

    if (q->passed_det)
      mark_as_det_done(q);

    q = q->next;
    id++;
  }

  if (in_place_resume)
    nuke_resume_dir();
}

#ifndef SIMPLE_FILES

/* Construct a file name for a new test case, capturing the operation
   that led to its discovery. Uses a static buffer. */

static u8 *describe_op(u8 hnb)
{

  static u8 ret[256];

  if (syncing_party)
  {

    sprintf(ret, "sync:%s,src:%06u", syncing_party, syncing_case);
  }
  else
  {

    sprintf(ret, "src:%06u", current_entry);

    if (splicing_with >= 0)
      sprintf(ret + strlen(ret), "+%06u", splicing_with);

    sprintf(ret + strlen(ret), ",op:%s", stage_short);

    if (stage_cur_byte >= 0)
    {

      sprintf(ret + strlen(ret), ",pos:%u", stage_cur_byte);

      if (stage_val_type != STAGE_VAL_NONE)
        sprintf(ret + strlen(ret), ",val:%s%+d",
                (stage_val_type == STAGE_VAL_BE) ? "be:" : "",
                stage_cur_val);
    }
    else
      sprintf(ret + strlen(ret), ",rep:%u", stage_cur_val);
  }

  if (hnb == 2)
    strcat(ret, ",+cov");

  return ret;
}

#endif /* !SIMPLE_FILES */

/* Write a message accompanying the crash directory :-) */

static void write_crash_readme(void)
{

  u8 *fn = alloc_printf("%s/replayable-crashes/README.txt", out_dir);
  s32 fd;
  FILE *f;

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  ck_free(fn);

  /* Do not die on errors here - that would be impolite. */

  if (fd < 0)
    return;

  f = fdopen(fd, "w");

  if (!f)
  {
    close(fd);
    return;
  }

  fprintf(f, "Command line used to find this crash:\n\n"

             "%s\n\n"

             "If you can't reproduce a bug outside of afl-fuzz, be sure to set the same\n"
             "memory limit. The limit used for this fuzzing session was %s.\n\n"

             "Need a tool to minimize test cases before investigating the crashes or sending\n"
             "them to a vendor? Check out the afl-tmin that comes with the fuzzer!\n\n"

             "Found any cool bugs in open-source tools using afl-fuzz? If yes, please drop\n"
             "me a mail at <lcamtuf@coredump.cx> once the issues are fixed - I'd love to\n"
             "add your finds to the gallery at:\n\n"

             "  http://lcamtuf.coredump.cx/afl/\n\n"

             "Thanks :-)\n",

          orig_cmdline, DMS(mem_limit << 20)); /* ignore errors */

  fclose(f);
}

/* Check if the result of an execve() during routine fuzzing is interesting,
   save or queue the input test case for further analysis if so. Returns 1 if
   entry is saved, 0 otherwise. */

static u8 save_if_interesting(char **argv, void *mem, u32 len, u8 fault)
{

  u8 *fn = "";
  u8 hnb;
  // s32 fd;
  u8 keeping = 0, res;

  if (fault == crash_mode)
  {

    /* Keep only if there are new bits in the map, add to queue for
       future fuzzing, etc. */

    if (!(hnb = has_new_bits(virgin_bits)))
    {
      if (crash_mode)
        total_crashes++;
      /* P6: Record state stall (no new coverage from this execution) */
      mqtt_record_state_stall();
      return 0;
    }

#ifndef SIMPLE_FILES

    fn = alloc_printf("%s/queue/id:%06u,%s", out_dir, queued_paths,
                      describe_op(hnb));

#else

    fn = alloc_printf("%s/queue/id_%06u", out_dir, queued_paths);

#endif /* ^!SIMPLE_FILES */

    u32 full_len = save_kl_messages_to_file(kl_messages, fn, 0, messages_sent);

    /* We use the actual length of all messages (full_len), not the len of the mutated message subsequence (len)*/
    add_to_queue(fn, full_len, 0);

    if (state_aware_mode)
      update_state_aware_variables(queue_top, 0);

    /* save the seed to file for replaying */
    u8 *fn_replay = alloc_printf("%s/replayable-queue/%s", out_dir, basename(queue_top->fname));
    save_kl_messages_to_file(kl_messages, fn_replay, 1, messages_sent);
    ck_free(fn_replay);

    if (hnb == 2)
    {
      queue_top->has_new_cov = 1;
      queued_with_cov++;
    }

    queue_top->exec_cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

    /* ════════════════════════════════════════════════════════════════
     * P5: Annotate queue entry with MQTT differential score.
     *
     * If multi-broker execution detected field-level divergence,
     * transfer the score to the queue entry so calculate_score()
     * can boost its energy on future fuzzing cycles.
     *
     * Also reset state-stall counter (new path discovered).
     * ════════════════════════════════════════════════════════════════ */
    if (mqtt_last_field_diff_valid && protocol_name &&
        strcasecmp(protocol_name, "MQTT") == 0) {
      int dscore = mqtt_diff_score_from_result(&mqtt_last_field_diff);
      queue_top->mqtt_diff_score = (u8)(dscore > 100 ? 100 : dscore);

      /* Track promotion for observability */
      if (dscore > 0 &&
          mqtt_is_new_divergence_pattern(mqtt_last_field_diff.pattern_hash)) {
        mqtt_diff_queue_promotions++;
      }
    }
    mqtt_reset_state_stall();

    /* Try to calibrate inline; this also calls update_bitmap_score() when
       successful. */

    res = calibrate_case(argv, queue_top, mem, queue_cycle - 1, 0);

    if (res == FAULT_ERROR)
      FATAL("Unable to execute target application");

    /*fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    ck_write(fd, mem, len, fn);
    close(fd);*/

    keeping = 1;
  }

  switch (fault)
  {

  case FAULT_TMOUT:

    /* Timeouts are not very interesting, but we're still obliged to keep
       a handful of samples. We use the presence of new bits in the
       hang-specific bitmap as a signal of uniqueness. In "dumb" mode, we
       just keep everything. */

    total_tmouts++;

    if (unique_hangs >= KEEP_UNIQUE_HANG)
      return keeping;

    if (!dumb_mode)
    {

#ifdef WORD_SIZE_64
      simplify_trace((u64 *)trace_bits);
#else
      simplify_trace((u32 *)trace_bits);
#endif /* ^WORD_SIZE_64 */

      if (!has_new_bits(virgin_tmout))
        return keeping;
    }

    unique_tmouts++;

    /* Before saving, we make sure that it's a genuine hang by re-running
       the target with a more generous timeout (unless the default timeout
       is already generous). */

    if (exec_tmout < hang_tmout)
    {

      u8 new_fault;
      write_to_testcase(mem, len);
      new_fault = run_target(argv, hang_tmout);

      /* A corner case that one user reported bumping into: increasing the
         timeout actually uncovers a crash. Make sure we don't discard it if
         so. */

      if (!stop_soon && new_fault == FAULT_CRASH)
        goto keep_as_crash;

      if (stop_soon || new_fault != FAULT_TMOUT)
        return keeping;
    }

#ifndef SIMPLE_FILES

    fn = alloc_printf("%s/replayable-hangs/id:%06llu,%s", out_dir,
                      unique_hangs, describe_op(0));

#else

    fn = alloc_printf("%s/replayable-hangs/id_%06llu", out_dir,
                      unique_hangs);

#endif /* ^!SIMPLE_FILES */

    unique_hangs++;

    last_hang_time = get_cur_time();

    break;

  case FAULT_CRASH:

  keep_as_crash:

    /* This is handled in a manner roughly similar to timeouts,
       except for slightly different limits and no need to re-run test
       cases. */

    total_crashes++;

    if (unique_crashes >= KEEP_UNIQUE_CRASH)
      return keeping;

    if (!dumb_mode)
    {

#ifdef WORD_SIZE_64
      simplify_trace((u64 *)trace_bits);
#else
      simplify_trace((u32 *)trace_bits);
#endif /* ^WORD_SIZE_64 */

      if (!has_new_bits(virgin_crash))
        return keeping;
    }

    if (!unique_crashes)
      write_crash_readme();

#ifndef SIMPLE_FILES

    fn = alloc_printf("%s/replayable-crashes/id:%06llu,sig:%02u,%s", out_dir,
                      unique_crashes, kill_signal, describe_op(0));

#else

    fn = alloc_printf("%s/replayable-crashes/id_%06llu_%02u", out_dir, unique_crashes,
                      kill_signal);

#endif /* ^!SIMPLE_FILES */

    unique_crashes++;

    last_crash_time = get_cur_time();
    last_crash_execs = total_execs;

    break;

  case FAULT_ERROR:
    FATAL("Unable to execute target application");

  default:
    return keeping;
  }

  /* If we're here, we apparently want to save the crash or hang
     test case, too. */

  save_kl_messages_to_file(kl_messages, fn, 1, messages_sent);

  /*fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  ck_write(fd, mem, len, fn);
  close(fd);*/

  ck_free(fn);

  return keeping;
}

/* When resuming, try to find the queue position to start from. This makes sense
   only when resuming, and when we can find the original fuzzer_stats. */

static u32 find_start_position(void)
{

  static u8 tmp[4096]; /* Ought to be enough for anybody. */

  u8 *fn, *off;
  s32 fd, i;
  u32 ret;

  if (!resuming_fuzz)
    return 0;

  if (in_place_resume)
    fn = alloc_printf("%s/fuzzer_stats", out_dir);
  else
    fn = alloc_printf("%s/../fuzzer_stats", in_dir);

  fd = open(fn, O_RDONLY);
  ck_free(fn);

  if (fd < 0)
    return 0;

  i = read(fd, tmp, sizeof(tmp) - 1);
  (void)i; /* Ignore errors */
  close(fd);

  off = strstr(tmp, "cur_path          : ");
  if (!off)
    return 0;

  ret = atoi(off + 20);
  if (ret >= queued_paths)
    ret = 0;
  return ret;
}

/* The same, but for timeouts. The idea is that when resuming sessions without
   -t given, we don't want to keep auto-scaling the timeout over and over
   again to prevent it from growing due to random flukes. */

static void find_timeout(void)
{

  static u8 tmp[4096]; /* Ought to be enough for anybody. */

  u8 *fn, *off;
  s32 fd, i;
  u32 ret;

  if (!resuming_fuzz)
    return;

  if (in_place_resume)
    fn = alloc_printf("%s/fuzzer_stats", out_dir);
  else
    fn = alloc_printf("%s/../fuzzer_stats", in_dir);

  fd = open(fn, O_RDONLY);
  ck_free(fn);

  if (fd < 0)
    return;

  i = read(fd, tmp, sizeof(tmp) - 1);
  (void)i; /* Ignore errors */
  close(fd);

  off = strstr(tmp, "exec_timeout      : ");
  if (!off)
    return;

  ret = atoi(off + 20);
  if (ret <= 4)
    return;

  exec_tmout = ret;
  timeout_given = 3;
}

/* Update stats file for unattended monitoring. */

static void write_stats_file(double bitmap_cvg, double stability, double eps)
{

  static double last_bcvg, last_stab, last_eps;
  static struct rusage usage;

  u8 *fn = alloc_printf("%s/fuzzer_stats", out_dir);
  s32 fd;
  FILE *f;

  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0)
    PFATAL("Unable to create '%s'", fn);

  ck_free(fn);

  f = fdopen(fd, "w");

  if (!f)
    PFATAL("fdopen() failed");

  /* Keep last values in case we're called from another context
     where exec/sec stats and such are not readily available. */

  if (!bitmap_cvg && !stability && !eps)
  {
    bitmap_cvg = last_bcvg;
    stability = last_stab;
    eps = last_eps;
  }
  else
  {
    last_bcvg = bitmap_cvg;
    last_stab = stability;
    last_eps = eps;
  }

  fprintf(f, "start_time        : %llu\n"
             "last_update       : %llu\n"
             "fuzzer_pid        : %u\n"
             "cycles_done       : %llu\n"
             "execs_done        : %llu\n"
             "execs_per_sec     : %0.02f\n"
             "paths_total       : %u\n"
             "paths_favored     : %u\n"
             "paths_found       : %u\n"
             "paths_imported    : %u\n"
             "max_depth         : %u\n"
             "cur_path          : %u\n" /* Must match find_start_position() */
             "pending_favs      : %u\n"
             "pending_total     : %u\n"
             "variable_paths    : %u\n"
             "stability         : %0.02f%%\n"
             "bitmap_cvg        : %0.02f%%\n"
             "unique_crashes    : %llu\n"
             "unique_hangs      : %llu\n"
             "last_path         : %llu\n"
             "last_crash        : %llu\n"
             "last_hang         : %llu\n"
             "execs_since_crash : %llu\n"
             "exec_timeout      : %u\n" /* Must match find_timeout() */
             "afl_banner        : %s\n"
             "afl_version       : " VERSION "\n"
             "target_mode       : %s%s%s%s%s%s%s\n"
             "command_line      : %s\n"
             "slowest_exec_ms   : %llu\n"
             "forced_kills      : %u\n",
          start_time / 1000, get_cur_time() / 1000, getpid(),
          queue_cycle ? (queue_cycle - 1) : 0, total_execs, eps,
          queued_paths, queued_favored, queued_discovered, queued_imported,
          max_depth, current_entry, pending_favored, pending_not_fuzzed,
          queued_variable, stability, bitmap_cvg, unique_crashes,
          unique_hangs, last_path_time / 1000, last_crash_time / 1000,
          last_hang_time / 1000, total_execs - last_crash_execs,
          exec_tmout, use_banner,
          qemu_mode ? "qemu " : "", dumb_mode ? " dumb " : "",
          no_forkserver ? "no_forksrv " : "", crash_mode ? "crash " : "",
          persistent_mode ? "persistent " : "", deferred_mode ? "deferred " : "",
          (qemu_mode || dumb_mode || no_forkserver || crash_mode ||
           persistent_mode || deferred_mode)
              ? ""
              : "default",
          orig_cmdline, slowest_exec_ms, forced_kills);
  /* ignore errors */

  /* Get rss value from the children
     We must have killed the forkserver process and called waitpid
     before calling getrusage */
  if (getrusage(RUSAGE_CHILDREN, &usage))
  {
    WARNF("getrusage failed");
  }
  else if (usage.ru_maxrss == 0)
  {
    fprintf(f, "peak_rss_mb       : not available while afl is running\n");
  }
  else
  {
#ifdef __APPLE__
    fprintf(f, "peak_rss_mb       : %zu\n", usage.ru_maxrss >> 20);
#else
    fprintf(f, "peak_rss_mb       : %zu\n", usage.ru_maxrss >> 10);
#endif /* ^__APPLE__ */
  }

  /* ============================================
   * ChatAFL-Opt: Hypothesis & Plateau Statistics
   * ============================================ */
  if (hypothesis_ctx && hypothesis_ctx->hypothesis_count > 0) {
    u32 total_parse_success = 0;
    u32 total_parse_failure = 0;
    double avg_fitness = 0.0;
    
    for (size_t i = 0; i < hypothesis_ctx->hypothesis_count; i++) {
      grammar_hypothesis_t *hyp = hypothesis_ctx->hypotheses[i];
      if (hyp) {
        total_parse_success += hyp->parse_success;
        total_parse_failure += hyp->parse_failure;
        avg_fitness += hyp->fitness;
      }
    }
    avg_fitness /= hypothesis_ctx->hypothesis_count;
    
    fprintf(f, "hypothesis_count   : %zu\n"
               "hypothesis_parse_success : %u\n"
               "hypothesis_parse_failure : %u\n"
               "hypothesis_avg_fitness   : %0.03f\n",
            hypothesis_ctx->hypothesis_count,
            total_parse_success,
            total_parse_failure,
            avg_fitness);
  }
  
  fprintf(f, "plateau_calls      : %u\n"
             "plateau_threshold  : %u\n"
             "edges_growth_rate  : %0.02f\n"
             "llm_total_calls    : %llu\n"
             "llm_prompt_tokens  : %llu\n"
             "llm_completion_tok : %llu\n"
             "llm_dedup_hits     : %llu\n",
          chat_times,
          adaptive_plateau_threshold,
          edges_growth_rate,
          (unsigned long long)llm_total_calls,
          (unsigned long long)llm_total_prompt_tokens,
          (unsigned long long)llm_total_completion_tokens,
          (unsigned long long)llm_dedup_hits);

  fprintf(f, "mp_multi_ok        : %u\n"
             "mp_multi_fallback  : %u\n"
             "mp_multi_hshake_fail : %u\n",
          mp_multi_ok, mp_multi_fallback, mp_multi_hshake_fail);

  fprintf(f, "mqtt_diff_enabled  : %u\n"
             "mqtt_diff_obs      : %llu\n"
             "mqtt_diff_pos      : %llu\n"
             "mqtt_diff_avg      : %0.06f\n"
             "mqtt_diff_last     : %0.06f\n"
             "mqtt_cluster_brokers : %u\n"
             "mqtt_cluster_unique_sigs : %u\n"
             "mqtt_cluster_diverged : %u\n"
             "mqtt_diff_type_div : %llu\n"
             "mqtt_diff_code_div : %llu\n"
             "mqtt_diff_payload_div : %llu\n"
             "mqtt_diff_fwd_div  : %llu\n"
             "mqtt_diff_queue_promo : %llu\n"
             "mqtt_deep_state_promo : %llu\n"
             "mqtt_state_stall_resets : %llu\n"
             "unique_diffs       : %llu\n",
          mqtt_diff_feedback_enabled,
          (unsigned long long)mqtt_diff_obs_count,
          (unsigned long long)mqtt_diff_pos_count,
          mqtt_diff_signal_avg(),
          mqtt_last_diff_signal,
          mqtt_cluster_broker_count,
          mqtt_cluster_unique_signatures,
          mqtt_cluster_diverged,
          (unsigned long long)mqtt_diff_type_divergences,
          (unsigned long long)mqtt_diff_code_divergences,
          (unsigned long long)mqtt_diff_payload_divergences,
          (unsigned long long)mqtt_diff_fwd_divergences,
          (unsigned long long)mqtt_diff_queue_promotions,
          (unsigned long long)mqtt_deep_state_promotions,
          (unsigned long long)mqtt_state_stall_resets,
          (unsigned long long)unique_diffs);

  /* V6: Granular energy scheduling observability */
  fprintf(f, "mqtt_p5_energy_boosts : %llu\n"
             "mqtt_p6_deep_boosts : %llu\n"
             "mqtt_p6_stall_boosts : %llu\n",
          (unsigned long long)mqtt_p5_energy_boosts,
          (unsigned long long)mqtt_p6_deep_state_boosts,
          (unsigned long long)mqtt_p6_stall_boosts);

  fclose(f);
}

/* Update the plot file if there is a reason to. */

static void maybe_update_plot_file(double bitmap_cvg, double eps)
{

  static u32 prev_qp, prev_pf, prev_pnf, prev_ce, prev_md, prev_nodes, prev_edges, prev_chat_times;
  static u64 prev_qc, prev_uc, prev_uh, prev_llm_calls, prev_mqtt_diff_pos;

  if (prev_qp == queued_paths && prev_pf == pending_favored &&
      prev_pnf == pending_not_fuzzed && prev_ce == current_entry &&
      prev_qc == queue_cycle && prev_uc == unique_crashes &&
      prev_uh == unique_hangs && prev_md == max_depth &&
      prev_nodes == agnnodes(ipsm) && prev_edges == agnedges(ipsm) &&
      prev_chat_times == chat_times && prev_llm_calls == llm_total_calls &&
      prev_mqtt_diff_pos == mqtt_diff_pos_count)
    return;

  prev_qp = queued_paths;
  prev_pf = pending_favored;
  prev_pnf = pending_not_fuzzed;
  prev_ce = current_entry;
  prev_qc = queue_cycle;
  prev_uc = unique_crashes;
  prev_uh = unique_hangs;
  prev_md = max_depth;
  prev_nodes = agnnodes(ipsm);
  prev_edges = agnedges(ipsm);
  prev_chat_times = chat_times;
  prev_llm_calls = llm_total_calls;
  prev_mqtt_diff_pos = mqtt_diff_pos_count;

  /* Compute hypothesis aggregate metrics for plot row */
  double hyp_fitness = 0.0;
  u32 hyp_success = 0, hyp_failure = 0;
  if (hypothesis_ctx && hypothesis_ctx->hypothesis_count > 0) {
    for (size_t i = 0; i < hypothesis_ctx->hypothesis_count; i++) {
      grammar_hypothesis_t *hyp = hypothesis_ctx->hypotheses[i];
      if (hyp) {
        hyp_success += hyp->parse_success;
        hyp_failure += hyp->parse_failure;
        hyp_fitness += hyp->fitness;
      }
    }
    hyp_fitness /= hypothesis_ctx->hypothesis_count;
  }

  /* Fields in the file:

     unix_time, cycles_done, cur_path, paths_total, paths_not_fuzzed,
     favored_not_fuzzed, unique_crashes, unique_hangs, max_depth,
     execs_per_sec, n_nodes, n_edges, chat_times,
     llm_calls, llm_prompt_tok, llm_compl_tok, llm_dedup,
    hyp_fitness, hyp_success, hyp_failure,
    mqtt_diff_avg, mqtt_diff_last, mqtt_diff_pos,
    mqtt_type_div, mqtt_code_div, mqtt_payload_div, mqtt_diff_promo, mqtt_deep_promo, mqtt_stall_resets */

  fprintf(plot_file,
      "%llu, %llu, %u, %u, %u, %u, %0.02f%%, %llu, %llu, %u, %0.02f, %d, %d, %d, "
      "%llu, %llu, %llu, %llu, %0.03f, %u, %u, %0.06f, %0.06f, %llu, "
      "%llu, %llu, %llu, %llu, %llu, %llu, %llu\n",
          get_cur_time() / 1000, queue_cycle - 1, current_entry, queued_paths,
          pending_not_fuzzed, pending_favored, bitmap_cvg, unique_crashes,
          unique_hangs, max_depth, eps, agnnodes(ipsm), agnedges(ipsm), chat_times,
          (unsigned long long)llm_total_calls,
          (unsigned long long)llm_total_prompt_tokens,
          (unsigned long long)llm_total_completion_tokens,
          (unsigned long long)llm_dedup_hits,
      hyp_fitness, hyp_success, hyp_failure,
      mqtt_diff_signal_avg(), mqtt_last_diff_signal,
      (unsigned long long)mqtt_diff_pos_count,
      (unsigned long long)mqtt_diff_type_divergences,
      (unsigned long long)mqtt_diff_code_divergences,
      (unsigned long long)mqtt_diff_payload_divergences,
      (unsigned long long)mqtt_diff_queue_promotions,
      (unsigned long long)mqtt_deep_state_promotions,
      (unsigned long long)mqtt_state_stall_resets,
      (unsigned long long)mqtt_diff_fwd_divergences); /* O2 */

  fflush(plot_file);
}

/* A helper function for maybe_delete_out_dir(), deleting all prefixed
   files in a directory. */

static u8 delete_files(u8 *path, u8 *prefix)
{

  DIR *d;
  struct dirent *d_ent;

  d = opendir(path);

  if (!d)
    return 0;

  while ((d_ent = readdir(d)))
  {

    if (d_ent->d_name[0] != '.' && (!prefix ||
                                    !strncmp(d_ent->d_name, prefix, strlen(prefix))))
    {

      u8 *fname = alloc_printf("%s/%s", path, d_ent->d_name);
      if (unlink(fname))
        PFATAL("Unable to delete '%s'", fname);
      ck_free(fname);
    }
  }

  closedir(d);

  return !!rmdir(path);
}

/* Get the number of runnable processes, with some simple smoothing. */

static double get_runnable_processes(void)
{

  static double res;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)

  /* I don't see any portable sysctl or so that would quickly give us the
     number of runnable processes; the 1-minute load average can be a
     semi-decent approximation, though. */

  if (getloadavg(&res, 1) != 1)
    return 0;

#else

  /* On Linux, /proc/stat is probably the best way; load averages are
     computed in funny ways and sometimes don't reflect extremely short-lived
     processes well. */

  FILE *f = fopen("/proc/stat", "r");
  u8 tmp[1024];
  u32 val = 0;

  if (!f)
    return 0;

  while (fgets(tmp, sizeof(tmp), f))
  {

    if (!strncmp(tmp, "procs_running ", 14) ||
        !strncmp(tmp, "procs_blocked ", 14))
      val += atoi(tmp + 14);
  }

  fclose(f);

  if (!res)
  {

    res = val;
  }
  else
  {

    res = res * (1.0 - 1.0 / AVG_SMOOTHING) +
          ((double)val) * (1.0 / AVG_SMOOTHING);
  }

#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  return res;
}

/* Delete the temporary directory used for in-place session resume. */

static void nuke_resume_dir(void)
{

  u8 *fn;

  fn = alloc_printf("%s/_resume/.state/deterministic_done", out_dir);
  if (delete_files(fn, CASE_PREFIX))
    goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/auto_extras", out_dir);
  if (delete_files(fn, "auto_"))
    goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/redundant_edges", out_dir);
  if (delete_files(fn, CASE_PREFIX))
    goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/variable_behavior", out_dir);
  if (delete_files(fn, CASE_PREFIX))
    goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state", out_dir);
  if (rmdir(fn) && errno != ENOENT)
    goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume", out_dir);
  if (delete_files(fn, CASE_PREFIX))
    goto dir_cleanup_failed;
  ck_free(fn);

  return;

dir_cleanup_failed:

  FATAL("_resume directory cleanup failed");
}

/* Delete fuzzer output directory if we recognize it as ours, if the fuzzer
   is not currently running, and if the last run time isn't too great. */

static void maybe_delete_out_dir(void)
{

  FILE *f;
  u8 *fn = alloc_printf("%s/fuzzer_stats", out_dir);

  /* See if the output directory is locked. If yes, bail out. If not,
     create a lock that will persist for the lifetime of the process
     (this requires leaving the descriptor open).*/

  out_dir_fd = open(out_dir, O_RDONLY);
  if (out_dir_fd < 0)
    PFATAL("Unable to open '%s'", out_dir);

#ifndef __sun

  if (flock(out_dir_fd, LOCK_EX | LOCK_NB) && errno == EWOULDBLOCK)
  {

    SAYF("\n" cLRD "[-] " cRST
         "Looks like the job output directory is being actively used by another\n"
         "    instance of afl-fuzz. You will need to choose a different %s\n"
         "    or stop the other process first.\n",
         sync_id ? "fuzzer ID" : "output location");

    FATAL("Directory '%s' is in use", out_dir);
  }

#endif /* !__sun */

  f = fopen(fn, "r");

  if (f)
  {

    u64 start_time, last_update;

    if (fscanf(f, "start_time     : %llu\n"
                  "last_update    : %llu\n",
               &start_time, &last_update) != 2)
      FATAL("Malformed data in '%s'", fn);

    fclose(f);

    /* Let's see how much work is at stake. */

    if (!in_place_resume && last_update - start_time > OUTPUT_GRACE * 60)
    {

      SAYF("\n" cLRD "[-] " cRST
           "The job output directory already exists and contains the results of more\n"
           "    than %u minutes worth of fuzzing. To avoid data loss, afl-fuzz will *NOT*\n"
           "    automatically delete this data for you.\n\n"

           "    If you wish to start a new session, remove or rename the directory manually,\n"
           "    or specify a different output location for this job. To resume the old\n"
           "    session, put '-' as the input directory in the command line ('-i -') and\n"
           "    try again.\n",
           OUTPUT_GRACE);

      FATAL("At-risk data found in '%s'", out_dir);
    }
  }

  ck_free(fn);

  /* The idea for in-place resume is pretty simple: we temporarily move the old
     queue/ to a new location that gets deleted once import to the new queue/
     is finished. If _resume/ already exists, the current queue/ may be
     incomplete due to an earlier abort, so we want to use the old _resume/
     dir instead, and we let rename() fail silently. */

  if (in_place_resume)
  {

    u8 *orig_q = alloc_printf("%s/queue", out_dir);

    in_dir = alloc_printf("%s/_resume", out_dir);

    rename(orig_q, in_dir); /* Ignore errors */

    OKF("Output directory exists, will attempt session resume.");

    ck_free(orig_q);
  }
  else
  {

    OKF("Output directory exists but deemed OK to reuse.");
  }

  ACTF("Deleting old session data...");

  /* Okay, let's get the ball rolling! First, we need to get rid of the entries
     in <out_dir>/.synced/.../id:*, if any are present. */

  if (!in_place_resume)
  {

    fn = alloc_printf("%s/.synced", out_dir);
    if (delete_files(fn, NULL))
      goto dir_cleanup_failed;
    ck_free(fn);
  }

  /* Next, we need to clean up <out_dir>/queue/.state/ subdirectories: */

  fn = alloc_printf("%s/queue/.state/deterministic_done", out_dir);
  if (delete_files(fn, CASE_PREFIX))
    goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/auto_extras", out_dir);
  if (delete_files(fn, "auto_"))
    goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/redundant_edges", out_dir);
  if (delete_files(fn, CASE_PREFIX))
    goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/variable_behavior", out_dir);
  if (delete_files(fn, CASE_PREFIX))
    goto dir_cleanup_failed;
  ck_free(fn);

  /* Then, get rid of the .state subdirectory itself (should be empty by now)
     and everything matching <out_dir>/queue/id:*. */

  fn = alloc_printf("%s/queue/.state", out_dir);
  if (rmdir(fn) && errno != ENOENT)
    goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue", out_dir);
  if (delete_files(fn, CASE_PREFIX))
    goto dir_cleanup_failed;
  ck_free(fn);

  /* All right, let's do <out_dir>/replayable-crashes/id:* and <out_dir>/replayable-hangs/id:*. */

  if (!in_place_resume)
  {

    fn = alloc_printf("%s/replayable-crashes/README.txt", out_dir);
    unlink(fn); /* Ignore errors */
    ck_free(fn);
  }

  fn = alloc_printf("%s/replayable-crashes", out_dir);

  /* Make backup of the crashes directory if it's not empty and if we're
     doing in-place resume. */

  if (in_place_resume && rmdir(fn))
  {

    time_t cur_t = time(0);
    struct tm *t = localtime(&cur_t);

#ifndef SIMPLE_FILES

    u8 *nfn = alloc_printf("%s.%04u-%02u-%02u-%02u:%02u:%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#else

    u8 *nfn = alloc_printf("%s_%04u%02u%02u%02u%02u%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#endif /* ^!SIMPLE_FILES */

    rename(fn, nfn); /* Ignore errors. */
    ck_free(nfn);
  }

  if (delete_files(fn, CASE_PREFIX))
    goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/replayable-hangs", out_dir);

  /* Backup hangs, too. */

  if (in_place_resume && rmdir(fn))
  {

    time_t cur_t = time(0);
    struct tm *t = localtime(&cur_t);

#ifndef SIMPLE_FILES

    u8 *nfn = alloc_printf("%s.%04u-%02u-%02u-%02u:%02u:%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#else

    u8 *nfn = alloc_printf("%s_%04u%02u%02u%02u%02u%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#endif /* ^!SIMPLE_FILES */

    rename(fn, nfn); /* Ignore errors. */
    ck_free(nfn);
  }

  if (delete_files(fn, CASE_PREFIX))
    goto dir_cleanup_failed;
  ck_free(fn);

  /* Delete regions. */

  fn = alloc_printf("%s/regions", out_dir);
  if (delete_files(fn, ""))
    goto dir_cleanup_failed;
  ck_free(fn);

  /* Delete replayable-queue. */

  fn = alloc_printf("%s/replayable-queue", out_dir);
  if (delete_files(fn, ""))
    goto dir_cleanup_failed;
  ck_free(fn);

  /* Delete the old ipsm.dot */
  fn = alloc_printf("%s/ipsm.dot", out_dir);
  if (unlink(fn) && errno != ENOENT)
    goto dir_cleanup_failed;
  ck_free(fn);

  /* Delete the old replayable-new-ipsm-paths folder */
  fn = alloc_printf("%s/replayable-new-ipsm-paths", out_dir);
  if (delete_files(fn, ""))
    goto dir_cleanup_failed;
  ck_free(fn);

  /* Delete the old responses-ipsm folder */
  fn = alloc_printf("%s/responses-ipsm", out_dir);
  if (delete_files(fn, ""))
    goto dir_cleanup_failed;
  ck_free(fn);

  /* Delete the old protocol-grammars folder */
  fn = alloc_printf("%s/protocol-grammars", out_dir);
  if (delete_files(fn, ""))
    goto dir_cleanup_failed;
  ck_free(fn);

  /* Delete the old stall-interactions folder */
  fn = alloc_printf("%s/stall-interactions", out_dir);
  if (delete_files(fn, ""))
    goto dir_cleanup_failed;
  ck_free(fn);

  /* And now, for some finishing touches. */

  fn = alloc_printf("%s/.cur_input", out_dir);
  if (unlink(fn) && errno != ENOENT)
    goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/fuzz_bitmap", out_dir);
  if (unlink(fn) && errno != ENOENT)
    goto dir_cleanup_failed;
  ck_free(fn);

  if (!in_place_resume)
  {
    fn = alloc_printf("%s/fuzzer_stats", out_dir);
    if (unlink(fn) && errno != ENOENT)
      goto dir_cleanup_failed;
    ck_free(fn);
  }

  fn = alloc_printf("%s/plot_data", out_dir);
  if (unlink(fn) && errno != ENOENT)
    goto dir_cleanup_failed;
  ck_free(fn);

  OKF("Output dir cleanup successful.");

  /* Wow... is that all? If yes, celebrate! */

  return;

dir_cleanup_failed:

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, the fuzzer tried to reuse your output directory, but bumped into\n"
       "    some files that shouldn't be there or that couldn't be removed - so it\n"
       "    decided to abort! This happened while processing this path:\n\n"

       "    %s\n\n"
       "    Please examine and manually delete the files, or specify a different\n"
       "    output location for the tool.\n",
       fn);

  FATAL("Output directory cleanup failed");
}

static void check_term_size(void);

/* A spiffy retro stats screen! This is called every stats_update_freq
   execve() calls, plus in several other circumstances. */

static void show_stats(void)
{

  static u64 last_stats_ms, last_plot_ms, last_ms, last_execs;
  static double avg_exec;
  double t_byte_ratio, stab_ratio;

  u64 cur_ms;
  u32 t_bytes, t_bits;

  u32 banner_len, banner_pad;
  u8 tmp[256];

  cur_ms = get_cur_time();

  /* If not enough time has passed since last UI update, bail out. */

  if (cur_ms - last_ms < 1000 / UI_TARGET_HZ)
    return;

  /* Check if we're past the 10 minute mark. */

  if (cur_ms - start_time > 10 * 60 * 1000)
    run_over10m = 1;

  /* Calculate smoothed exec speed stats. */

  if (!last_execs)
  {

    avg_exec = ((double)total_execs) * 1000 / (cur_ms - start_time);
  }
  else
  {

    double cur_avg = ((double)(total_execs - last_execs)) * 1000 /
                     (cur_ms - last_ms);

    /* If there is a dramatic (5x+) jump in speed, reset the indicator
       more quickly. */

    if (cur_avg * 5 < avg_exec || cur_avg / 5 > avg_exec)
      avg_exec = cur_avg;

    avg_exec = avg_exec * (1.0 - 1.0 / AVG_SMOOTHING) +
               cur_avg * (1.0 / AVG_SMOOTHING);
  }

  last_ms = cur_ms;
  last_execs = total_execs;

  /* Tell the callers when to contact us (as measured in execs). */

  stats_update_freq = avg_exec / (UI_TARGET_HZ * 10);
  if (!stats_update_freq)
    stats_update_freq = 1;

  /* Do some bitmap stats. */

  t_bytes = count_non_255_bytes(virgin_bits);
  t_byte_ratio = ((double)t_bytes * 100) / MAP_SIZE;

  if (t_bytes)
    stab_ratio = 100 - ((double)var_byte_count) * 100 / t_bytes;
  else
    stab_ratio = 100;

  /* Roughly every minute, update fuzzer stats and save auto tokens. */

  if (cur_ms - last_stats_ms > STATS_UPDATE_SEC * 1000)
  {

    last_stats_ms = cur_ms;
    write_stats_file(t_byte_ratio, stab_ratio, avg_exec);
    save_auto();
    write_bitmap();

    /* D1: Coverage stagnation detection — check if queued_paths grew
     * since last check (roughly every stats interval ≈ 1 min).
     * When stagnant, perf_score will be boosted for diff-triggering
     * seeds in calculate_score() to push past coverage plateaus. */
    if (mqtt_diff_feedback_enabled && total_execs > last_cov_check_execs + 2000) {
      if (queued_paths <= last_cov_check_paths) {
        mqtt_cov_stagnant = 1;
      } else {
        mqtt_cov_stagnant = 0;
      }
      last_cov_check_execs = total_execs;
      last_cov_check_paths = queued_paths;
    }
  }

  /* Every now and then, write plot data. */

  if (cur_ms - last_plot_ms > PLOT_UPDATE_SEC * 1000)
  {

    last_plot_ms = cur_ms;
    maybe_update_plot_file(t_byte_ratio, avg_exec);
  }

  /* Honor AFL_EXIT_WHEN_DONE and AFL_BENCH_UNTIL_CRASH. */

  if (!dumb_mode && cycles_wo_finds > 100 && !pending_not_fuzzed &&
      getenv("AFL_EXIT_WHEN_DONE"))
    stop_soon = 2;

  if (total_crashes && getenv("AFL_BENCH_UNTIL_CRASH"))
    stop_soon = 2;

  /* If we're not on TTY, bail out. */

  if (not_on_tty)
    return;

  /* Compute some mildly useful bitmap stats. */

  t_bits = (MAP_SIZE << 3) - count_bits(virgin_bits);

  /* Now, for the visuals... */

  if (clear_screen)
  {

    SAYF(TERM_CLEAR CURSOR_HIDE);
    clear_screen = 0;

    check_term_size();
  }

  SAYF(TERM_HOME);

  if (term_too_small)
  {

    SAYF(cBRI "Your terminal is too small to display the UI.\n"
              "Please resize terminal window to at least 80x25.\n" cRST);

    return;
  }

  /* Let's start by drawing a centered banner. */

  banner_len = (crash_mode ? 24 : 22) + strlen(VERSION) + strlen(use_banner);
  banner_pad = (80 - banner_len) / 2;
  memset(tmp, ' ', banner_pad);

  sprintf(tmp + banner_pad, "%s " cLCY VERSION cLGN " (%s)", crash_mode ? cPIN "peruvian were-rabbit" : cYEL "american fuzzy lop", use_banner);

  SAYF("\n%s\n\n", tmp);

  /* "Handy" shortcuts for drawing boxes... */

#define bSTG bSTART cGRA
#define bH2 bH bH
#define bH5 bH2 bH2 bH
#define bH10 bH5 bH5
#define bH20 bH10 bH10
#define bH30 bH20 bH10
#define SP5 "     "
#define SP10 SP5 SP5
#define SP20 SP10 SP10

  /* Lord, forgive me this. */

  SAYF(SET_G1 bSTG bLT bH bSTOP cCYA " process timing " bSTG bH30 bH5 bH2 bHB
           bH bSTOP cCYA " overall results " bSTG bH5 bRT "\n");

  if (dumb_mode)
  {

    strcpy(tmp, cRST);
  }
  else
  {

    u64 min_wo_finds = (cur_ms - last_path_time) / 1000 / 60;

    /* First queue cycle: don't stop now! */
    if (queue_cycle == 1 || min_wo_finds < 15)
      strcpy(tmp, cMGN);
    else

      /* Subsequent cycles, but we're still making finds. */
      if (cycles_wo_finds < 25 || min_wo_finds < 30)
        strcpy(tmp, cYEL);
      else

        /* No finds for a long time and no test cases to try. */
        if (cycles_wo_finds > 100 && !pending_not_fuzzed && min_wo_finds > 120)
          strcpy(tmp, cLGN);

        /* Default: cautiously OK to stop? */
        else
          strcpy(tmp, cLBL);
  }

  SAYF(bV bSTOP "        run time : " cRST "%-34s " bSTG bV bSTOP
                "  cycles done : %s%-5s  " bSTG bV "\n",
       DTD(cur_ms, start_time), tmp, DI(queue_cycle - 1));

  /* We want to warn people about not seeing new paths after a full cycle,
     except when resuming fuzzing or running in non-instrumented mode. */

  if (!dumb_mode && (last_path_time || resuming_fuzz || queue_cycle == 1 ||
                     in_bitmap || crash_mode))
  {

    SAYF(bV bSTOP "   last new path : " cRST "%-34s ",
         DTD(cur_ms, last_path_time));
  }
  else
  {

    if (dumb_mode)

      SAYF(bV bSTOP "   last new path : " cPIN "n/a" cRST
                    " (non-instrumented mode)        ");

    else

      SAYF(bV bSTOP "   last new path : " cRST "none yet " cLRD
                    "(odd, check syntax!)      ");
  }

  SAYF(bSTG bV bSTOP "  total paths : " cRST "%-5s  " bSTG bV "\n",
       DI(queued_paths));

  /* Highlight crashes in red if found, denote going over the KEEP_UNIQUE_CRASH
     limit with a '+' appended to the count. */

  sprintf(tmp, "%s%s", DI(unique_crashes),
          (unique_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  SAYF(bV bSTOP " last uniq crash : " cRST "%-34s " bSTG bV bSTOP
                " uniq crashes : %s%-6s " bSTG bV "\n",
       DTD(cur_ms, last_crash_time), unique_crashes ? cLRD : cRST,
       tmp);

  sprintf(tmp, "%s%s", DI(unique_hangs),
          (unique_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  SAYF(bV bSTOP "  last uniq hang : " cRST "%-34s " bSTG bV bSTOP
                "   uniq hangs : " cRST "%-6s " bSTG bV "\n",
       DTD(cur_ms, last_hang_time), tmp);

  SAYF(bVR bH bSTOP cCYA " cycle progress " bSTG bH20 bHB bH bSTOP cCYA
                         " map coverage " bSTG bH bHT bH20 bH2 bH bVL "\n");

  /* This gets funny because we want to print several variable-length variables
     together, but then cram them into a fixed-width field - so we need to
     put them in a temporary buffer first. */

  sprintf(tmp, "%s%s (%0.02f%%)", DI(current_entry),
          queue_cur->favored ? "" : "*",
          ((double)current_entry * 100) / queued_paths);

  SAYF(bV bSTOP "  now processing : " cRST "%-17s " bSTG bV bSTOP, tmp);

  sprintf(tmp, "%0.02f%% / %0.02f%%", ((double)queue_cur->bitmap_size) * 100 / MAP_SIZE, t_byte_ratio);

  SAYF("    map density : %s%-21s " bSTG bV "\n", t_byte_ratio > 70 ? cLRD : ((t_bytes < 200 && !dumb_mode) ? cPIN : cRST), tmp);

  sprintf(tmp, "%s (%0.02f%%)", DI(cur_skipped_paths),
          ((double)cur_skipped_paths * 100) / queued_paths);

  SAYF(bV bSTOP " paths timed out : " cRST "%-17s " bSTG bV, tmp);

  sprintf(tmp, "%0.02f bits/tuple",
          t_bytes ? (((double)t_bits) / t_bytes) : 0);

  SAYF(bSTOP " count coverage : " cRST "%-21s " bSTG bV "\n", tmp);

  SAYF(bVR bH bSTOP cCYA " stage progress " bSTG bH20 bX bH bSTOP cCYA
                         " findings in depth " bSTG bH20 bVL "\n");

  sprintf(tmp, "%s (%0.02f%%)", DI(queued_favored),
          ((double)queued_favored) * 100 / queued_paths);

  /* Yeah... it's still going on... halp? */

  SAYF(bV bSTOP "  now trying : " cRST "%-21s " bSTG bV bSTOP
                " favored paths : " cRST "%-22s " bSTG bV "\n",
       stage_name, tmp);

  if (!stage_max)
  {

    sprintf(tmp, "%s/-", DI(stage_cur));
  }
  else
  {

    sprintf(tmp, "%s/%s (%0.02f%%)", DI(stage_cur), DI(stage_max),
            ((double)stage_cur) * 100 / stage_max);
  }

  SAYF(bV bSTOP " stage execs : " cRST "%-21s " bSTG bV bSTOP, tmp);

  sprintf(tmp, "%s (%0.02f%%)", DI(queued_with_cov),
          ((double)queued_with_cov) * 100 / queued_paths);

  SAYF("  new edges on : " cRST "%-22s " bSTG bV "\n", tmp);

  sprintf(tmp, "%s (%s%s unique)", DI(total_crashes), DI(unique_crashes),
          (unique_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  if (crash_mode)
  {

    SAYF(bV bSTOP " total execs : " cRST "%-21s " bSTG bV bSTOP
                  "   new crashes : %s%-22s " bSTG bV "\n",
         DI(total_execs),
         unique_crashes ? cLRD : cRST, tmp);
  }
  else
  {

    SAYF(bV bSTOP " total execs : " cRST "%-21s " bSTG bV bSTOP
                  " total crashes : %s%-22s " bSTG bV "\n",
         DI(total_execs),
         unique_crashes ? cLRD : cRST, tmp);
  }

  /* Show a warning about slow execution. */

  if (avg_exec < 100)
  {

    sprintf(tmp, "%s/sec (%s)", DF(avg_exec), avg_exec < 20 ? "zzzz..." : "slow!");

    SAYF(bV bSTOP "  exec speed : " cLRD "%-21s ", tmp);
  }
  else
  {

    sprintf(tmp, "%s/sec", DF(avg_exec));
    SAYF(bV bSTOP "  exec speed : " cRST "%-21s ", tmp);
  }

  sprintf(tmp, "%s (%s%s unique)", DI(total_tmouts), DI(unique_tmouts),
          (unique_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  SAYF(bSTG bV bSTOP "  total tmouts : " cRST "%-22s " bSTG bV "\n", tmp);

  /* Aaaalmost there... hold on! */

  SAYF(bVR bH cCYA bSTOP " fuzzing strategy yields " bSTG bH10 bH bHT bH10
           bH5 bHB bH bSTOP cCYA " path geometry " bSTG bH5 bH2 bH bVL "\n");

  if (skip_deterministic)
  {

    strcpy(tmp, "n/a, n/a, n/a");
  }
  else
  {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_FLIP1]), DI(stage_cycles[STAGE_FLIP1]),
            DI(stage_finds[STAGE_FLIP2]), DI(stage_cycles[STAGE_FLIP2]),
            DI(stage_finds[STAGE_FLIP4]), DI(stage_cycles[STAGE_FLIP4]));
  }

  SAYF(bV bSTOP "   bit flips : " cRST "%-37s " bSTG bV bSTOP "    levels : " cRST "%-10s " bSTG bV "\n", tmp, DI(max_depth));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_FLIP8]), DI(stage_cycles[STAGE_FLIP8]),
            DI(stage_finds[STAGE_FLIP16]), DI(stage_cycles[STAGE_FLIP16]),
            DI(stage_finds[STAGE_FLIP32]), DI(stage_cycles[STAGE_FLIP32]));

  SAYF(bV bSTOP "  byte flips : " cRST "%-37s " bSTG bV bSTOP "   pending : " cRST "%-10s " bSTG bV "\n", tmp, DI(pending_not_fuzzed));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_ARITH8]), DI(stage_cycles[STAGE_ARITH8]),
            DI(stage_finds[STAGE_ARITH16]), DI(stage_cycles[STAGE_ARITH16]),
            DI(stage_finds[STAGE_ARITH32]), DI(stage_cycles[STAGE_ARITH32]));

  SAYF(bV bSTOP " arithmetics : " cRST "%-37s " bSTG bV bSTOP "  pend fav : " cRST "%-10s " bSTG bV "\n", tmp, DI(pending_favored));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_INTEREST8]), DI(stage_cycles[STAGE_INTEREST8]),
            DI(stage_finds[STAGE_INTEREST16]), DI(stage_cycles[STAGE_INTEREST16]),
            DI(stage_finds[STAGE_INTEREST32]), DI(stage_cycles[STAGE_INTEREST32]));

  SAYF(bV bSTOP "  known ints : " cRST "%-37s " bSTG bV bSTOP " own finds : " cRST "%-10s " bSTG bV "\n", tmp, DI(queued_discovered));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_EXTRAS_UO]), DI(stage_cycles[STAGE_EXTRAS_UO]),
            DI(stage_finds[STAGE_EXTRAS_UI]), DI(stage_cycles[STAGE_EXTRAS_UI]),
            DI(stage_finds[STAGE_EXTRAS_AO]), DI(stage_cycles[STAGE_EXTRAS_AO]));

  SAYF(bV bSTOP "  dictionary : " cRST "%-37s " bSTG bV bSTOP
                "  imported : " cRST "%-10s " bSTG bV "\n",
       tmp,
       sync_id ? DI(queued_imported) : (u8 *)"n/a");

  sprintf(tmp, "%s/%s, %s/%s",
          DI(stage_finds[STAGE_HAVOC]), DI(stage_cycles[STAGE_HAVOC]),
          DI(stage_finds[STAGE_SPLICE]), DI(stage_cycles[STAGE_SPLICE]));

  SAYF(bV bSTOP "       havoc : " cRST "%-37s " bSTG bV bSTOP, tmp);

  if (t_bytes)
    sprintf(tmp, "%0.02f%%", stab_ratio);
  else
    strcpy(tmp, "n/a");

  SAYF(" stability : %s%-10s " bSTG bV "\n", (stab_ratio < 85 && var_byte_count > 40) ? cLRD : ((queued_variable && (!persistent_mode || var_byte_count > 20)) ? cMGN : cRST), tmp);

  if (!bytes_trim_out)
  {

    sprintf(tmp, "n/a, ");
  }
  else
  {

    sprintf(tmp, "%0.02f%%/%s, ",
            ((double)(bytes_trim_in - bytes_trim_out)) * 100 / bytes_trim_in,
            DI(trim_execs));
  }

  if (!blocks_eff_total)
  {

    u8 tmp2[128];

    sprintf(tmp2, "n/a");
    strcat(tmp, tmp2);
  }
  else
  {

    u8 tmp2[128];

    sprintf(tmp2, "%0.02f%%",
            ((double)(blocks_eff_total - blocks_eff_select)) * 100 /
                blocks_eff_total);

    strcat(tmp, tmp2);
  }

  SAYF(bV bSTOP "        trim : " cRST "%-37s " bSTG bVR bH20 bH2 bH2 bRB "\n" bLB bH30 bH20 bH2 bH bRB bSTOP cRST RESET_G1, tmp);

  /* MQTT differential effectiveness warning (status bar).
   * Trigger when we have many diff observations but almost-zero avg signal,
   * which usually indicates multi-broker configured but no useful divergence. */
  u8 mqtt_diff_warn = 0;
  if (mqtt_diff_feedback_enabled && protocol_name &&
      strcasecmp(protocol_name, "MQTT") == 0 &&
      getenv("CHATAFL_MQTT_BROKERS") && *getenv("CHATAFL_MQTT_BROKERS") &&
      mqtt_cluster_broker_count > 1 &&
      mqtt_diff_obs_count >= mqtt_diff_warn_obs_threshold &&
      mqtt_diff_signal_avg() <= mqtt_diff_warn_avg_threshold) {
    mqtt_diff_warn = 1;
  }

  /* Provide some CPU utilization stats. */

  if (cpu_core_count)
  {

    double cur_runnable = get_runnable_processes();
    u32 cur_utilization = cur_runnable * 100 / cpu_core_count;

    u8 *cpu_color = cCYA;

    /* If we could still run one or more processes, use green. */

    if (cpu_core_count > 1 && cur_runnable + 1 <= cpu_core_count)
      cpu_color = cLGN;

    /* If we're clearly oversubscribed, use red. */

    if (!no_cpu_meter_red && cur_utilization >= 150)
      cpu_color = cLRD;

#ifdef HAVE_AFFINITY

    if (cpu_aff >= 0)
    {

       SAYF(SP10 cGRA "[cpu%03u:%s%3u%%" cGRA "]%s\r" cRST,
           MIN(cpu_aff, 999), cpu_color,
         MIN(cur_utilization, 999),
         mqtt_diff_warn ? "  [mqtt-diff:obs-high avg~0 -> check brokers]" : "");
    }
    else
    {

       SAYF(SP10 cGRA "   [cpu:%s%3u%%" cGRA "]%s\r" cRST,
         cpu_color, MIN(cur_utilization, 999),
         mqtt_diff_warn ? "  [mqtt-diff:obs-high avg~0 -> check brokers]" : "");
    }

#else

        SAYF(SP10 cGRA "   [cpu:%s%3u%%" cGRA "]%s\r" cRST,
          cpu_color, MIN(cur_utilization, 999),
          mqtt_diff_warn ? "  [mqtt-diff:obs-high avg~0 -> check brokers]" : "");

#endif /* ^HAVE_AFFINITY */
  }
  else
    SAYF("%s\r", mqtt_diff_warn ? "[mqtt-diff:obs-high avg~0 -> check brokers]" : "");

  /* Show debugging stats for AFLNet only when AFLNET_DEBUG environment variable is set */
  if (getenv("AFLNET_DEBUG") && (atoi(getenv("AFLNET_DEBUG")) == 1) && state_aware_mode)
  {
    SAYF(cRST "\n\nMax_seed_region_count: %-4s, current_kl_messages_size: %-4s\n\n", DI(max_seed_region_count), DI(kl_messages->size));
    SAYF(cRST "State IDs and its #selected_times," cCYA "#fuzzs," cLRD "#discovered_paths," cGRA "#excersing_paths:\n");

    khint_t k;
    state_info_t *state;
    u32 i = 0;

    for (i = 0; i < state_ids_count; i++)
    {
      u32 state_id = state_ids[i];

      k = kh_get(hms, khms_states, state_id);
      if (k != kh_end(khms_states))
      {
        state = kh_val(khms_states, k);
        SAYF(cRST "S%-3s:%-4s," cCYA "%-5s," cLRD "%-5s," cGRA "%-5s", DI(state->id), DI(state->selected_times), DI(state->fuzzs), DI(state->paths_discovered), DI(state->paths));
        if ((i + 1) % 3 == 0)
          SAYF("\n");
      }
    }
  }

  /* P5/P6 field-level differential & deep-path metrics (always shown for MQTT) */
  if (mqtt_diff_feedback_enabled && protocol_name &&
      strcasecmp(protocol_name, "MQTT") == 0) {
    SAYF(cRST "\n" cYEL "[P5-diff] " cRST
         "type_div:" cLRD "%-4s " cRST
         "code_div:" cLRD "%-4s " cRST
         "pay_div:" cLRD "%-4s " cRST
         "fwd_div:" cLRD "%-4s " cRST
         "promo:" cLGN "%-4s " cRST
         "diffs:" cLRD "%-4s " cRST
         "p5e:" cLGN "%-4s " cRST
         cYEL "[P6] " cRST
         "deep:" cLGN "%-4s " cRST
         "stall:" cCYA "%-4s " cRST
         "rst:" cCYA "%-4s" cRST "\n",
         DI(mqtt_diff_type_divergences),
         DI(mqtt_diff_code_divergences),
         DI(mqtt_diff_payload_divergences),
         DI(mqtt_diff_fwd_divergences),
         DI(mqtt_diff_queue_promotions),
         DI(unique_diffs),
         DI(mqtt_p5_energy_boosts),
         DI(mqtt_p6_deep_state_boosts),
         DI(mqtt_p6_stall_boosts),
         DI(mqtt_state_stall_resets));
  }

  /* Hallelujah! */

  fflush(0);
}

/* Display quick statistics at the end of processing the input directory,
   plus a bunch of warnings. Some calibration stuff also ended up here,
   along with several hardcoded constants. Maybe clean up eventually. */

static void show_init_stats(void)
{

  struct queue_entry *q = queue;
  u32 min_bits = 0, max_bits = 0;
  u64 min_us = 0, max_us = 0;
  u64 avg_us = 0;
  u32 max_len = 0;

  if (total_cal_cycles)
    avg_us = total_cal_us / total_cal_cycles;

  while (q)
  {

    if (!min_us || q->exec_us < min_us)
      min_us = q->exec_us;
    if (q->exec_us > max_us)
      max_us = q->exec_us;

    if (!min_bits || q->bitmap_size < min_bits)
      min_bits = q->bitmap_size;
    if (q->bitmap_size > max_bits)
      max_bits = q->bitmap_size;

    if (q->len > max_len)
      max_len = q->len;

    q = q->next;
  }

  SAYF("\n");

  if (avg_us > (qemu_mode ? 50000 : 10000))
    WARNF(cLRD "The target binary is pretty slow! See %s/perf_tips.txt.",
          doc_path);

  /* Let's keep things moving with slow binaries. */

  if (avg_us > 50000)
    havoc_div = 10; /* 0-19 execs/sec   */
  else if (avg_us > 20000)
    havoc_div = 5; /* 20-49 execs/sec  */
  else if (avg_us > 10000)
    havoc_div = 2; /* 50-100 execs/sec */

  /* D3: For MQTT network fuzzers, high avg_us is inherent (network latency),
   * not because the target is slow. Cap havoc_div at 5 to preserve more
   * havoc iterations and improve throughput. */
  if (protocol_name && strcasecmp(protocol_name, "MQTT") == 0 && havoc_div > 5)
    havoc_div = 5;

  if (!resuming_fuzz)
  {

    if (max_len > 50 * 1024)
      WARNF(cLRD "Some test cases are huge (%s) - see %s/perf_tips.txt!",
            DMS(max_len), doc_path);
    else if (max_len > 10 * 1024)
      WARNF("Some test cases are big (%s) - see %s/perf_tips.txt.",
            DMS(max_len), doc_path);

    if (useless_at_start && !in_bitmap)
      WARNF(cLRD "Some test cases look useless. Consider using a smaller set.");

    if (queued_paths > 100)
      WARNF(cLRD "You probably have far too many input files! Consider trimming down.");
    else if (queued_paths > 20)
      WARNF("You have lots of input files; try starting small.");
  }

  OKF("Here are some useful stats:\n\n"

      cGRA "    Test case count : " cRST "%u favored, %u variable, %u total\n" cGRA "       Bitmap range : " cRST "%u to %u bits (average: %0.02f bits)\n" cGRA "        Exec timing : " cRST "%s to %s us (average: %s us)\n",
      queued_favored, queued_variable, queued_paths, min_bits, max_bits,
      ((double)total_bitmap_size) / (total_bitmap_entries ? total_bitmap_entries : 1),
      DI(min_us), DI(max_us), DI(avg_us));

  if (!timeout_given)
  {

    /* Figure out the appropriate timeout. The basic idea is: 5x average or
       1x max, rounded up to EXEC_TM_ROUND ms and capped at 1 second.

       If the program is slow, the multiplier is lowered to 2x or 3x, because
       random scheduler jitter is less likely to have any impact, and because
       our patience is wearing thin =) */

    if (avg_us > 50000)
      exec_tmout = avg_us * 2 / 1000;
    else if (avg_us > 10000)
      exec_tmout = avg_us * 3 / 1000;
    else
      exec_tmout = avg_us * 5 / 1000;

    exec_tmout = MAX(exec_tmout, max_us / 1000);
    exec_tmout = (exec_tmout + EXEC_TM_ROUND) / EXEC_TM_ROUND * EXEC_TM_ROUND;

    if (exec_tmout > EXEC_TIMEOUT)
      exec_tmout = EXEC_TIMEOUT;

    ACTF("No -t option specified, so I'll use exec timeout of %u ms.",
         exec_tmout);

    timeout_given = 1;
  }
  else if (timeout_given == 3)
  {

    ACTF("Applying timeout settings from resumed session (%u ms).", exec_tmout);
  }

  /* In dumb mode, re-running every timing out test case with a generous time
     limit is very expensive, so let's select a more conservative default. */

  if (dumb_mode && !getenv("AFL_HANG_TMOUT"))
    hang_tmout = MIN(EXEC_TIMEOUT, exec_tmout * 2 + 100);

  OKF("All set and ready to roll!");
}

/* Write a modified test case, run program, process results. Handle
   error conditions, returning 1 if it's time to bail out. This is
   a helper function for fuzz_one(). */

EXP_ST u8 common_fuzz_stuff(char **argv, u8 *out_buf, u32 len)
{

  u8 fault;

  if (post_handler)
  {

    out_buf = post_handler(out_buf, &len);
    if (!out_buf || !len)
      return 0;
  }

  write_to_testcase(out_buf, len);

  /* ============================================
   * Fix-9b: Removed validate_and_refine_hypotheses() from hot path.
   *
   * Previously called on EVERY execution, this caused:
   * 1. Double extract_requests(): parsing buffer here AND again below
   *    → ~2x parsing overhead on every test case
   * 2. Per-region × per-hypothesis validation loops → 67K+ calls
   *    with zero refinements triggered for text protocols (RTSP/FTP)
   *    because hypothesis fitness stayed at 1.000
   * 3. Measurable impact on exec_speed (22K execs vs baseline 30K)
   *
   * The grammar-hypothesis system remains initialized and available
   * for the plateau handler's LLM-driven enrichment, but is no
   * longer invoked on the critical per-execution path.
   * ============================================ */

  /* AFLNet update kl_messages linked list */

  // parse the out_buf into messages
  u32 region_count = 0;
  region_t *regions = (*extract_requests)(out_buf, len, &region_count);
  if (!region_count)
    PFATAL("AFLNet Region count cannot be Zero");

  // update kl_messages linked list
  u32 i;
  kliter_t(lms) * prev_last_message, *cur_last_message;
  prev_last_message = get_last_message(kl_messages);

  // limit the #messages based on max_seed_region_count to reduce overhead
  for (i = 0; i < region_count; i++)
  {
    u32 len;
    // Identify region size
    if (i == max_seed_region_count)
    {
      len = regions[region_count - 1].end_byte - regions[i].start_byte + 1;
    }
    else
    {
      len = regions[i].end_byte - regions[i].start_byte + 1;
    }

    // Create a new message
    message_t *m = (message_t *)ck_alloc(sizeof(message_t));
    m->mdata = (char *)ck_alloc(len);
    m->msize = len;
    if (m->mdata == NULL)
      PFATAL("Unable to allocate memory region to store new message");
    memcpy(m->mdata, &out_buf[regions[i].start_byte], len);

    // Insert the message to the linked list
    *kl_pushp(lms, kl_messages) = m;

    // Update M2_next in case it points to the tail (M3 is empty)
    // because the tail in klist is updated once a new entry is pushed into it
    // in fact, the old tail storage is used to store the newly added entry and a new tail is created
    if (M2_next->next == kl_end(kl_messages))
    {
      M2_next = kl_end(kl_messages);
    }

    if (i == max_seed_region_count)
      break;
  }
  /* ============================================
   * Fix-15 Tier-1: Sampled hypothesis validation.
   * Reuses the regions already parsed above — NO double extract_requests().
   * Runs every HYPOTHESIS_VALIDATION_SAMPLE_RATE-th execution.
   * At exec_speed ≈ 25 K/s this is ~50 calls/s × ~1 µs = <0.01% overhead.
   * ============================================ */
  if (hypothesis_mode && hypothesis_ctx &&
      (total_execs % HYPOTHESIS_VALIDATION_SAMPLE_RATE == 0)) {
    validate_hypothesis_sampled(out_buf, len, regions, region_count);
  }

  ck_free(regions);

  cur_last_message = get_last_message(kl_messages);

  // update the linked list with the new M2 & free the previous M2

  // detach the head of previous M2 from the list
  kliter_t(lms) * old_M2_start;
  if (M2_prev == NULL)
  {
    old_M2_start = kl_begin(kl_messages);
    kl_begin(kl_messages) = kl_next(prev_last_message);
    kl_next(cur_last_message) = M2_next;
    kl_next(prev_last_message) = kl_end(kl_messages);
  }
  else
  {
    old_M2_start = kl_next(M2_prev);
    kl_next(M2_prev) = kl_next(prev_last_message);
    kl_next(cur_last_message) = M2_next;
    kl_next(prev_last_message) = kl_end(kl_messages);
  }

  // free the previous M2
  kliter_t(lms) * cur_it, *next_it;
  cur_it = old_M2_start;
  next_it = kl_next(cur_it);
  do
  {
    ck_free(kl_val(cur_it)->mdata);
    ck_free(kl_val(cur_it));
    kmp_free(lms, kl_messages->mp, cur_it);
    --kl_messages->size;

    cur_it = next_it;
    next_it = kl_next(next_it);
  } while (cur_it != M2_next);

  /* End of AFLNet code */

  fault = run_target(argv, exec_tmout);

  /* MQTT-only differential signal ingestion.
   * Treat cross-broker signature divergence as an auxiliary reward channel
   * (independent of single-target coverage), then feed it to per-state stats. */
  if (mqtt_diff_feedback_enabled && protocol_name &&
      strcasecmp(protocol_name, "MQTT") == 0) {
    double diff_signal = mqtt_last_diff_signal;

    /* Defensive recompute from current cluster metadata if available */
    if (mqtt_cluster_broker_count > 1 && mqtt_cluster_unique_signatures > 1) {
      double recomputed = (double)(mqtt_cluster_unique_signatures - 1) /
                          (double)(mqtt_cluster_broker_count - 1);
      if (recomputed > diff_signal)
        diff_signal = recomputed;
    }

    if (diff_signal < 0.0) diff_signal = 0.0;
    if (diff_signal > 1.0) diff_signal = 1.0;
    mqtt_last_diff_signal = diff_signal;

    /* Runtime telemetry for validation in fuzzer_stats / plot_data. */
    mqtt_diff_obs_count++;
    mqtt_diff_signal_sum += diff_signal;
    if (diff_signal > 0.0)
      mqtt_diff_pos_count++;

    mqtt_record_diff_signal_for_target_state(diff_signal);
  }

  // Update fuzz count, no matter whether the generated test is interesting or not
  if (state_aware_mode)
    update_fuzzs();

  if (stop_soon)
    return 1;

  if (fault == FAULT_TMOUT)
  {

    if (subseq_tmouts++ > TMOUT_LIMIT)
    {
      cur_skipped_paths++;
      return 1;
    }
  }
  else
    subseq_tmouts = 0;

  /* Users can hit us with SIGUSR1 to request the current input
     to be abandoned. */

  if (skip_requested)
  {

    skip_requested = 0;
    cur_skipped_paths++;
    return 1;
  }

  /* This handles FAULT_ERROR for us: */

  u8 is_interesting = save_if_interesting(argv, out_buf, len, fault);

  if (is_interesting)
  {
    uninteresting_times = 0;
  }
  else
  {
    uninteresting_times++;
  }

  queued_discovered += is_interesting;

  if (!(stage_cur % stats_update_freq) || stage_cur + 1 == stage_max)
    show_stats();

  return 0;
}

/* Helper to choose random block len for block operations in fuzz_one().
   Doesn't return zero, provided that max_len is > 0. */

static u32 choose_block_len(u32 limit)
{

  u32 min_value, max_value;
  u32 rlim = MIN(queue_cycle, 3);

  if (!run_over10m)
    rlim = 1;

  switch (UR(rlim))
  {

  case 0:
    min_value = 1;
    max_value = HAVOC_BLK_SMALL;
    break;

  case 1:
    min_value = HAVOC_BLK_SMALL;
    max_value = HAVOC_BLK_MEDIUM;
    break;

  default:

    if (UR(10))
    {

      min_value = HAVOC_BLK_MEDIUM;
      max_value = HAVOC_BLK_LARGE;
    }
    else
    {

      min_value = HAVOC_BLK_LARGE;
      max_value = HAVOC_BLK_XL;
    }
  }

  if (min_value >= limit)
    min_value = 1;

  return min_value + UR(MIN(max_value, limit) - min_value + 1);
}

/* Calculate case desirability score to adjust the length of havoc fuzzing.
   A helper function for fuzz_one(). Maybe some of these constants should
   go into config.h. */

static u32 calculate_score(struct queue_entry *q)
{

  u32 avg_exec_us = total_cal_us / total_cal_cycles;
  u32 avg_bitmap_size = total_bitmap_size / total_bitmap_entries;
  u32 perf_score = 100;

  /* Adjust score based on execution speed of this path, compared to the
     global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
     less expensive to fuzz, so we're giving them more air time. */

  if (q->exec_us * 0.1 > avg_exec_us)
    perf_score = 10;
  else if (q->exec_us * 0.25 > avg_exec_us)
    perf_score = 25;
  else if (q->exec_us * 0.5 > avg_exec_us)
    perf_score = 50;
  else if (q->exec_us * 0.75 > avg_exec_us)
    perf_score = 75;
  else if (q->exec_us * 4 < avg_exec_us)
    perf_score = 300;
  else if (q->exec_us * 3 < avg_exec_us)
    perf_score = 200;
  else if (q->exec_us * 2 < avg_exec_us)
    perf_score = 150;

  /* Adjust score based on bitmap size. The working theory is that better
     coverage translates to better targets. Multiplier from 0.25x to 3x. */

  if (q->bitmap_size * 0.3 > avg_bitmap_size)
    perf_score *= 3;
  else if (q->bitmap_size * 0.5 > avg_bitmap_size)
    perf_score *= 2;
  else if (q->bitmap_size * 0.75 > avg_bitmap_size)
    perf_score *= 1.5;
  else if (q->bitmap_size * 3 < avg_bitmap_size)
    perf_score *= 0.25;
  else if (q->bitmap_size * 2 < avg_bitmap_size)
    perf_score *= 0.5;
  else if (q->bitmap_size * 1.5 < avg_bitmap_size)
    perf_score *= 0.75;

  /* Adjust score based on handicap. Handicap is proportional to how late
     in the game we learned about this path. Latecomers are allowed to run
     for a bit longer until they catch up with the rest. */

  if (q->handicap >= 4)
  {

    perf_score *= 4;
    q->handicap -= 4;
  }
  else if (q->handicap)
  {

    perf_score *= 2;
    q->handicap--;
  }

  /* Final adjustment based on input depth, under the assumption that fuzzing
     deeper test cases is more likely to reveal stuff that can't be
     discovered with traditional fuzzers. */

  switch (q->depth)
  {

  case 0 ... 3:
    break;
  case 4 ... 7:
    perf_score *= 2;
    break;
  case 8 ... 13:
    perf_score *= 3;
    break;
  case 14 ... 25:
    perf_score *= 4;
    break;
  default:
    perf_score *= 5;
  }

  /* ════════════════════════════════════════════════════════════════════
   * P5: MQTT differential divergence bonus.
   *
   * Inputs that trigger cross-broker behavioral divergence receive an
   * energy multiplier, directing more fuzzing effort toward divergence-
   * triggering message sequences.  This is the AFL-native equivalent
   * of MBFuzzer's queue-prioritization-by-differential-novelty.
   *
   * Rationale (ICSE 2025, MBFuzzer §4.3): specification ambiguity
   * typically manifests as field-level response divergence; boosting
   * energy for such inputs amplifies divergence-driven exploration.
   *
   * Severity    Multiplier   Justification
   * ──────────  ──────────   ──────────────────────────────────────
   * diff ≥ 70   ×4          Type/missing divergence → high-value bug
   * diff ≥ 40   ×3          Return-code divergence → semantic bug
   * diff ≥ 10   ×2          Payload divergence → behavioral diff
   * diff == 0   ×1          No divergence → standard energy
   *
   * Gated: MQTT protocol only. Non-MQTT queue entries have diff_score=0.
   * ════════════════════════════════════════════════════════════════════ */
  if (mqtt_diff_feedback_enabled && q->mqtt_diff_score >= 70) {
    perf_score *= 4;
    mqtt_p5_energy_boosts++;
    mqtt_deep_state_promotions++;  /* reuse counter for observability */
  } else if (mqtt_diff_feedback_enabled && q->mqtt_diff_score >= 40) {
    perf_score *= 3;
    mqtt_p5_energy_boosts++;
  } else if (mqtt_diff_feedback_enabled && q->mqtt_diff_score >= 10) {
    perf_score *= 2;
    mqtt_p5_energy_boosts++;
  }

  /* D1: Coverage-stagnation boost — ROLLED BACK (A7).
   * Experiment showed 1.5× boost caused cycles_done to drop from 13→4
   * (−69%), reducing coverage by 5.7%.  The stagnation detection itself
   * is kept (mqtt_cov_stagnant flag) for observability and future use,
   * but we no longer inflate perf_score here. */
  /* if (mqtt_cov_stagnant && mqtt_diff_feedback_enabled &&
      q->mqtt_diff_score > 0) {
    perf_score = (perf_score * 3) / 2;
  } */

  /* ════════════════════════════════════════════════════════════════════
   * P6: MQTT deep-path state promotion.
   *
   * When a queue entry reaches a deep state (unique_state_count ≥ 5)
   * AND it has been generated at a state that is currently stalled
   * (consecutive zero-discovery execs ≥ MQTT_STALL_THRESHOLD), give
   * extra energy to push past the plateau.
   *
   * Rationale: AFLNet's state scoring assigns scores based on
   * paths_discovered/selected_times, which asymptotes to zero for
   * well-explored states.  But deep protocol states (e.g., retained
   * message handling, session resume, will message delivery) need
   * sustained energy even when short-term discovery is flat.
   *
   * Gated: MQTT protocol only.
   * ════════════════════════════════════════════════════════════════════ */
  if (protocol_name && strcasecmp(protocol_name, "MQTT") == 0 &&
      mqtt_diff_feedback_enabled && state_aware_mode) {
    /* Deep-state bonus: unique_state_count reflects how many distinct
     * protocol states this input traverses. Higher = deeper. */
    if (q->unique_state_count >= 8) {
      perf_score *= 3;
      mqtt_p6_deep_state_boosts++;
    } else if (q->unique_state_count >= 5) {
      perf_score *= 2;
      mqtt_p6_deep_state_boosts++;
    }

    /* Stall-aware boost: if the generating state is stalled,
     * boost this input so the fuzzer keeps trying to break through. */
    if (state_ids_count > 0 && mqtt_state_stall_counter) {
      u32 gen_idx = get_state_index(q->generating_state_id);
      if (gen_idx < mqtt_state_stall_cap &&
          mqtt_state_stall_counter[gen_idx] >= MQTT_STALL_THRESHOLD / 2) {
        perf_score *= 2;
        mqtt_p6_stall_boosts++;
      }
    }
  }

  /* Make sure that we don't go over limit. */

  if (perf_score > HAVOC_MAX_MULT * 100)
    perf_score = HAVOC_MAX_MULT * 100;

  return perf_score;
}

/* Helper function to see if a particular change (xor_val = old ^ new) could
   be a product of deterministic bit flips with the lengths and stepovers
   attempted by afl-fuzz. This is used to avoid dupes in some of the
   deterministic fuzzing operations that follow bit flips. We also
   return 1 if xor_val is zero, which implies that the old and attempted new
   values are identical and the exec would be a waste of time. */

static u8 could_be_bitflip(u32 xor_val)
{

  u32 sh = 0;

  if (!xor_val)
    return 1;

  /* Shift left until first bit set. */

  while (!(xor_val & 1))
  {
    sh++;
    xor_val >>= 1;
  }

  /* 1-, 2-, and 4-bit patterns are OK anywhere. */

  if (xor_val == 1 || xor_val == 3 || xor_val == 15)
    return 1;

  /* 8-, 16-, and 32-bit patterns are OK only if shift factor is
     divisible by 8, since that's the stepover for these ops. */

  if (sh & 7)
    return 0;

  if (xor_val == 0xff || xor_val == 0xffff || xor_val == 0xffffffff)
    return 1;

  return 0;
}

/* Helper function to see if a particular value is reachable through
   arithmetic operations. Used for similar purposes. */

static u8 could_be_arith(u32 old_val, u32 new_val, u8 blen)
{

  u32 i, ov = 0, nv = 0, diffs = 0;

  if (old_val == new_val)
    return 1;

  /* See if one-byte adjustments to any byte could produce this result. */

  for (i = 0; i < blen; i++)
  {

    u8 a = old_val >> (8 * i),
       b = new_val >> (8 * i);

    if (a != b)
    {
      diffs++;
      ov = a;
      nv = b;
    }
  }

  /* If only one byte differs and the values are within range, return 1. */

  if (diffs == 1)
  {

    if ((u8)(ov - nv) <= ARITH_MAX ||
        (u8)(nv - ov) <= ARITH_MAX)
      return 1;
  }

  if (blen == 1)
    return 0;

  /* See if two-byte adjustments to any byte would produce this result. */

  diffs = 0;

  for (i = 0; i < blen / 2; i++)
  {

    u16 a = old_val >> (16 * i),
        b = new_val >> (16 * i);

    if (a != b)
    {
      diffs++;
      ov = a;
      nv = b;
    }
  }

  /* If only one word differs and the values are within range, return 1. */

  if (diffs == 1)
  {

    if ((u16)(ov - nv) <= ARITH_MAX ||
        (u16)(nv - ov) <= ARITH_MAX)
      return 1;

    ov = SWAP16(ov);
    nv = SWAP16(nv);

    if ((u16)(ov - nv) <= ARITH_MAX ||
        (u16)(nv - ov) <= ARITH_MAX)
      return 1;
  }

  /* Finally, let's do the same thing for dwords. */

  if (blen == 4)
  {

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX)
      return 1;

    new_val = SWAP32(new_val);
    old_val = SWAP32(old_val);

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX)
      return 1;
  }

  return 0;
}

/* Last but not least, a similar helper to see if insertion of an
   interesting integer is redundant given the insertions done for
   shorter blen. The last param (check_le) is set if the caller
   already executed LE insertion for current blen and wants to see
   if BE variant passed in new_val is unique. */

static u8 could_be_interest(u32 old_val, u32 new_val, u8 blen, u8 check_le)
{

  u32 i, j;

  if (old_val == new_val)
    return 1;

  /* See if one-byte insertions from interesting_8 over old_val could
     produce new_val. */

  for (i = 0; i < blen; i++)
  {

    for (j = 0; j < sizeof(interesting_8); j++)
    {

      u32 tval = (old_val & ~(0xff << (i * 8))) |
                 (((u8)interesting_8[j]) << (i * 8));

      if (new_val == tval)
        return 1;
    }
  }

  /* Bail out unless we're also asked to examine two-byte LE insertions
     as a preparation for BE attempts. */

  if (blen == 2 && !check_le)
    return 0;

  /* See if two-byte insertions over old_val could give us new_val. */

  for (i = 0; i < blen - 1; i++)
  {

    for (j = 0; j < sizeof(interesting_16) / 2; j++)
    {

      u32 tval = (old_val & ~(0xffff << (i * 8))) |
                 (((u16)interesting_16[j]) << (i * 8));

      if (new_val == tval)
        return 1;

      /* Continue here only if blen > 2. */

      if (blen > 2)
      {

        tval = (old_val & ~(0xffff << (i * 8))) |
               (SWAP16(interesting_16[j]) << (i * 8));

        if (new_val == tval)
          return 1;
      }
    }
  }

  if (blen == 4 && check_le)
  {

    /* See if four-byte insertions could produce the same result
       (LE only). */

    for (j = 0; j < sizeof(interesting_32) / 4; j++)
      if (new_val == (u32)interesting_32[j])
        return 1;
  }

  return 0;
}

/* ============================================
 * O6: Adaptive Field Mutation Scheduler
 *
 * Per-field mutation probabilities that adapt based on reward signal.
 * Inspired by MBFuzzer's FieldMutationScheduler: each mutation type
 * maintains its own probability, which increases when that mutation
 * leads to new coverage or differential divergence, and decays
 * otherwise.
 *
 * 8 mutation types indexed 0-7 (matching the switch cases below).
 * ============================================ */
#define MQTT_FIELD_MUT_COUNT 8
static double mqtt_field_mut_prob[MQTT_FIELD_MUT_COUNT];
static u32    mqtt_field_mut_hits[MQTT_FIELD_MUT_COUNT];
static u32    mqtt_field_mut_tries[MQTT_FIELD_MUT_COUNT];
static u8     mqtt_field_mut_initialized = 0;
static u32    mqtt_field_mut_last_selected = 0;  /* for reward attribution */

static void mqtt_field_mut_init(void) {
  if (mqtt_field_mut_initialized) return;
  for (u32 i = 0; i < MQTT_FIELD_MUT_COUNT; i++) {
    mqtt_field_mut_prob[i]  = 1.0 / MQTT_FIELD_MUT_COUNT;  /* uniform start */
    mqtt_field_mut_hits[i]  = 1;  /* pseudocount to prevent zero division */
    mqtt_field_mut_tries[i] = MQTT_FIELD_MUT_COUNT;
  }
  mqtt_field_mut_initialized = 1;
}

/* Select mutation type using adaptive probabilities */
static u32 mqtt_field_mut_select(void) {
  double r = (double)(UR(10000)) / 10000.0;
  double cumul = 0.0;
  for (u32 i = 0; i < MQTT_FIELD_MUT_COUNT; i++) {
    cumul += mqtt_field_mut_prob[i];
    if (r <= cumul) {
      mqtt_field_mut_last_selected = i;
      return i;
    }
  }
  mqtt_field_mut_last_selected = MQTT_FIELD_MUT_COUNT - 1;
  return MQTT_FIELD_MUT_COUNT - 1;
}

/* Update probabilities: reward the mutation that led to new path/diff */
static void mqtt_field_mut_reward(u32 mut_idx, double reward) {
  if (mut_idx >= MQTT_FIELD_MUT_COUNT) return;
  mqtt_field_mut_tries[mut_idx]++;
  if (reward > 0.0) mqtt_field_mut_hits[mut_idx]++;

  /* Recompute probabilities using success ratio with smoothing */
  double sum = 0.0;
  for (u32 i = 0; i < MQTT_FIELD_MUT_COUNT; i++) {
    mqtt_field_mut_prob[i] = (double)mqtt_field_mut_hits[i] /
                             (double)mqtt_field_mut_tries[i];
    /* Floor: ensure every mutation retains at least 3% probability */
    if (mqtt_field_mut_prob[i] < 0.03) mqtt_field_mut_prob[i] = 0.03;
    sum += mqtt_field_mut_prob[i];
  }
  /* Normalize to sum=1 */
  if (sum > 0.0) {
    for (u32 i = 0; i < MQTT_FIELD_MUT_COUNT; i++)
      mqtt_field_mut_prob[i] /= sum;
  }
}

/* ============================================
 * B3-fix: MQTT-Structured Havoc Ranges
 *
 * For MQTT binary protocol, both explore and exploit havoc modes
 * previously used a single flat range (explore) or LLM grammar
 * ranges (exploit — useless for binary MQTT, returns single range).
 * This means byte-level mutations (cases 0-14) operate across
 * packet boundaries, corrupting packet framing and wasting execs.
 *
 * This function parses the buffer into individual MQTT packets and
 * returns each packet as a separate range.  Havoc mutations then
 * operate WITHIN packet boundaries, producing structurally valid
 * variants much more often.
 *
 * MQTT-only; zero impact on text protocols.
 * ============================================ */
static range_list mqtt_parse_havoc_ranges(u8 *buf, u32 len) {
  range_list rl;
  kv_init(rl);

  u32 pos = 0;
  while (pos < len) {
    u32 pkt_start = pos;
    if (pos + 2 > len) break;
    pos++; /* fixed header byte */

    /* Decode remaining length (variable-length encoding, 1-4 bytes) */
    u32 rem_len = 0, mult = 1;
    u32 rl_bytes = 0;
    while (pos < len && rl_bytes < 4) {
      u8 byte = buf[pos];
      rem_len += (byte & 0x7F) * mult;
      mult *= 128;
      pos++;
      rl_bytes++;
      if (!(byte & 0x80)) break;
    }

    u32 pkt_end = pos + rem_len;
    if (pkt_end > len) pkt_end = len;
    if (pkt_end <= pkt_start) break; /* avoid zero/negative-length */

    range r;
    r.start = pkt_start;
    r.len = pkt_end - pkt_start;
    r.mutable = 1;
    kv_push(range, rl, r);

    pos = pkt_end;
  }

  /* Fallback: if no valid packets found, use whole buffer as one range */
  if (kv_size(rl) == 0) {
    range r;
    r.start = 0;
    r.len = len;
    r.mutable = 1;
    kv_push(range, rl, r);
  }

  return rl;
}

/* ============================================
 * P2a: MQTT Field-Aware Mutation
 *
 * Applied as a post-havoc pass with 25% probability when protocol is
 * MQTT.  Understands MQTT v3.1.1 packet structure and performs
 * targeted mutations that generic byte-level havoc rarely produces:
 *
 *   - Packet type nibble swap (e.g., SUBSCRIBE→UNSUBSCRIBE)
 *   - QoS / DUP / Retain flag mutation for PUBLISH
 *   - Packet ID corruption (triggers broker duplicate handling)
 *   - Topic content mutation (exercises ACL / wildcard matching)
 *   - Wildcard injection in SUBSCRIBE topics
 *   - Remaining-length corruption (boundary conditions)
 *   - Invalid QoS 3 in SUBSCRIBE (spec violation)
 *
 * O6: Now uses adaptive per-field mutation selection instead of
 * uniform UR(8).  Mutation types that lead to coverage/diff are
 * selected more frequently.
 *
 * Returns: number of mutations applied.
 * ============================================ */
static u32 mqtt_field_aware_mutate(u8 *buf, u32 len) {
  if (len < 2) return 0;
  mqtt_field_mut_init();
  u32 mutations_applied = 0;
  u32 pos = 0;

  while (pos < len - 1) {
    u8 type_nibble = (buf[pos] >> 4) & 0x0F;
    u8 flags       = buf[pos] & 0x0F;

    /* Decode MQTT remaining length (variable-length encoding) */
    u32 rem_len = 0, multiplier = 1;
    u32 rl_pos = pos + 1;
    while (rl_pos < len) {
      u8 byte = buf[rl_pos];
      rem_len += (byte & 0x7F) * multiplier;
      multiplier *= 128;
      rl_pos++;
      if (!(byte & 0x80)) break;
      if (multiplier > 128u * 128 * 128 * 128) break; /* max 4 bytes */
    }

    u32 pkt_end  = rl_pos + rem_len;
    if (pkt_end > len) pkt_end = len;
    u32 payload_start = rl_pos;  /* first byte after header */

    /* O6: Pick mutation type using adaptive probabilities instead of UR(8) */
    switch (mqtt_field_mut_select()) {

    case 0: /* Swap packet type to a related type */
    {
      /* Prefer valid MQTT types 1-14; 0 and 15 are reserved → good
       * for testing error paths */
      static const u8 type_pool[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
      buf[pos] = (u8)((type_pool[UR(sizeof(type_pool))] << 4) | flags);
      mutations_applied++;
      break;
    }

    case 1: /* Mutate PUBLISH flags: DUP/QoS/Retain */
      if (type_nibble == 3) {
        u8 new_qos    = UR(4);  /* 0,1,2 valid; 3 = spec violation → error path */
        u8 new_dup    = UR(2);
        u8 new_retain = UR(2);
        buf[pos] = (u8)((3 << 4) | (new_dup << 3) | (new_qos << 1) | new_retain);
        mutations_applied++;
      }
      break;

    case 2: /* Corrupt packet ID (for QoS>0 PUBLISH, SUB, UNSUB, etc.) */
      if (type_nibble >= 3 && type_nibble <= 11 && payload_start + 1 < pkt_end) {
        u32 pid_offset = payload_start;
        if (type_nibble == 3) {
          /* PUBLISH: skip topic-length (2B) + topic before packet ID */
          if (payload_start + 2 <= pkt_end) {
            u32 topic_len = ((u32)buf[payload_start] << 8) | buf[payload_start + 1];
            pid_offset = payload_start + 2 + topic_len;
          }
        }
        if (pid_offset + 1 < pkt_end) {
          buf[pid_offset]     = (u8)UR(256);
          buf[pid_offset + 1] = (u8)UR(256);
          mutations_applied++;
        }
      }
      break;

    case 3: /* Mutate topic content in PUBLISH / SUBSCRIBE */
      if ((type_nibble == 3 || type_nibble == 8) && payload_start + 2 < pkt_end) {
        u32 topic_off = payload_start;
        if (type_nibble == 8) topic_off += 2;  /* skip packet ID */
        if (topic_off + 2 < pkt_end) {
          u32 topic_len = ((u32)buf[topic_off] << 8) | buf[topic_off + 1];
          if (topic_off + 2 + topic_len <= pkt_end && topic_len > 0) {
            u32 idx = topic_off + 2 + UR(topic_len);
            buf[idx] = (u8)UR(256);
            mutations_applied++;
          }
        }
      }
      break;

    case 4: /* Inject MQTT wildcard in SUBSCRIBE topic */
      if (type_nibble == 8 && payload_start + 4 < pkt_end) {
        u32 topic_off = payload_start + 2; /* after packet ID */
        if (topic_off + 2 < pkt_end) {
          u32 topic_len = ((u32)buf[topic_off] << 8) | buf[topic_off + 1];
          if (topic_off + 2 + topic_len <= pkt_end && topic_len > 0) {
            u32 idx = topic_off + 2 + UR(topic_len);
            buf[idx] = UR(2) ? '#' : '+';
            mutations_applied++;
          }
        }
      }
      break;

    case 5: /* Corrupt remaining length → boundary conditions */
      if (pos + 1 < len) {
        switch (UR(4)) {
          case 0: buf[pos + 1] = 0;    break; /* zero-length payload */
          case 1: buf[pos + 1] = 0x01; break; /* minimal */
          case 2: buf[pos + 1] = 0x7F; break; /* max single-byte (127) */
          case 3: buf[pos + 1] = 0xFF; break; /* requires continuation byte */
        }
        mutations_applied++;
      }
      break;

    case 6: /* Inject zero-length CONNECT or malformed DISCONNECT */
    {
      /* Overwrite current packet header to test error handling */
      static const u8 trap_headers[][2] = {
        {0x10, 0x00},  /* CONNECT with 0 remaining length */
        {0xE0, 0x00},  /* DISCONNECT */
        {0xC0, 0x00},  /* PINGREQ */
        {0x00, 0x00},  /* Reserved type 0 → error path */
        {0xF0, 0x00},  /* Reserved type 15 → error path */
      };
      u32 choice = UR(sizeof(trap_headers) / sizeof(trap_headers[0]));
      buf[pos]     = trap_headers[choice][0];
      buf[pos + 1] = trap_headers[choice][1];
      mutations_applied++;
      break;
    }

    case 7: /* Set invalid QoS 3 in SUBSCRIBE topic filter */
      if (type_nibble == 8 && pkt_end > payload_start + 4) {
        /* Last byte in each topic filter entry is the QoS byte */
        buf[pkt_end - 1] = 3; /* Invalid QoS → SUBACK error code */
        mutations_applied++;
      }
      break;
    }

    /* Advance to next packet */
    pos = pkt_end;
    if (pos <= rl_pos && pos > 0) break; /* safety: avoid infinite loop */
  }

  return mutations_applied;
}

/* Take the current entry from the queue, fuzz it for a while. This
   function is a tad too long... returns 0 if fuzzed successfully, 1 if
   skipped or bailed out. */

static u8 fuzz_one(char **argv)
{

  s32 len, fd, temp_len, i, j;
  u8 *in_buf = NULL, *out_buf, *orig_in, *ex_tmp, *eff_map = 0;
  u64 havoc_queued, orig_hit_cnt, new_hit_cnt;
  u32 splice_cycle = 0, perf_score = 100, orig_perf, prev_cksum, eff_cnt = 1, M2_len;

  u8 ret_val = 1, doing_det = 0;

  u8 a_collect[MAX_AUTO_EXTRA];
  u32 a_len = 0;

#ifdef IGNORE_FINDS

  /* In IGNORE_FINDS mode, skip any entries that weren't in the
     initial data set. */

  if (queue_cur->depth > 1)
    return 1;

#else

  // Skip some steps if in state_aware_mode because in this mode
  // the seed is selected based on state-aware algorithms
  if (state_aware_mode)
    goto AFLNET_REGIONS_SELECTION;

  if (pending_favored)
  {

    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. */

    if ((queue_cur->was_fuzzed || !queue_cur->favored) &&
        UR(100) < SKIP_TO_NEW_PROB)
      return 1;
  }
  else if (!dumb_mode && !queue_cur->favored && queued_paths > 10)
  {

    /* Otherwise, still possibly skip non-favored cases, albeit less often.
       The odds of skipping stuff are higher for already-fuzzed inputs and
       lower for never-fuzzed entries. */

    if (queue_cycle > 1 && !queue_cur->was_fuzzed)
    {

      if (UR(100) < SKIP_NFAV_NEW_PROB)
        return 1;
    }
    else
    {

      if (UR(100) < SKIP_NFAV_OLD_PROB)
        return 1;
    }
  }

#endif /* ^IGNORE_FINDS */

  if (not_on_tty)
  {
    ACTF("Fuzzing test case #%u (%u total, %llu uniq crashes found)...",
         current_entry, queued_paths, unique_crashes);
    fflush(stdout);
  }

AFLNET_REGIONS_SELECTION:;

  subseq_tmouts = 0;

  cur_depth = queue_cur->depth;

  u32 M2_start_region_ID = 0, M2_region_count = 0;
  /* Identify the prefix M1, the candidate subsequence M2, and the suffix M3. See AFLNet paper */
  /* In this implementation, we only need to indentify M2_start_region_ID which is the first region of M2
  and M2_region_count which is the total number of regions in M2. How the information is identified is
  state aware dependent. However, once the information is clear, the code for fuzzing preparation is the same */

  if (state_aware_mode)
  {
    /* In state aware mode, select M2 based on the targeted state ID */
    u32 total_region = queue_cur->region_count;
    if (total_region == 0)
      PFATAL("0 region found for %s", queue_cur->fname);

    if (target_state_id == 0)
    {
      // No prefix subsequence (M1 is empty)
      M2_start_region_ID = 0;
      M2_region_count = 0;

      // To compute M2_region_count, we identify the first region which has a different annotation
      // Now we quickly compare the state count, we could make it more fine grained by comparing the exact response codes
      for (i = 0; i < queue_cur->region_count; i++)
      {
        if (queue_cur->regions[i].state_count != queue_cur->regions[0].state_count)
          break;
        M2_region_count++;
      }
    }
    else
    {
      // M1 is unlikely to be empty
      M2_start_region_ID = 0;

      // Identify M2_start_region_ID first based on the target_state_id
      for (i = 0; i < queue_cur->region_count; i++)
      {
        u32 regionalStateCount = queue_cur->regions[i].state_count;
        if (regionalStateCount > 0)
        {
          // reachableStateID is the last ID in the state_sequence
          u32 reachableStateID = queue_cur->regions[i].state_sequence[regionalStateCount - 1];
          M2_start_region_ID++;
          if (reachableStateID == target_state_id)
            break;
        }
        else
        {
          // No annotation for this region
          return 1;
        }
      }

      // Then identify M2_region_count
      for (i = M2_start_region_ID; i < queue_cur->region_count; i++)
      {
        if (queue_cur->regions[i].state_count != queue_cur->regions[M2_start_region_ID].state_count)
          break;
        M2_region_count++;
      }

      // Handle corner case(s) and skip the current queue entry
      if (M2_start_region_ID >= queue_cur->region_count)
        return 1;
    }
  }
  else
  {
    /* Select M2 randomly */
    u32 total_region = queue_cur->region_count;
    if (total_region == 0)
      PFATAL("0 region found for %s", queue_cur->fname);

    M2_start_region_ID = UR(total_region);
    M2_region_count = UR(total_region - M2_start_region_ID);
    if (M2_region_count == 0)
      M2_region_count++; // Mutate one region at least
  }

  /* Construct the kl_messages linked list and identify boundary pointers (M2_prev and M2_next) */
  kl_messages = construct_kl_messages(queue_cur->fname, queue_cur->regions, queue_cur->region_count);

  kliter_t(lms) * it;

  M2_prev = NULL;
  M2_next = kl_end(kl_messages);

  u32 count = 0;
  for (it = kl_begin(kl_messages); it != kl_end(kl_messages); it = kl_next(it))
  {
    if (count == M2_start_region_ID - 1)
    {
      M2_prev = it;
    }

    if (count == M2_start_region_ID + M2_region_count)
    {
      M2_next = it;
    }
    count++;
  }

  /* ============================================
   * Adaptive Plateau Triggering Logic
   * ============================================ */
  
  // Update edges growth rate every 60 seconds
  u64 cur_ms = get_cur_time();
  if (cur_ms - last_edges_check_time >= 60000) {  // 60 seconds
    u32 current_edges = agnedges(ipsm);  // Use IPSM edges (FIXED: was count_bits)
    if (last_edges_count > 0) {
      double time_elapsed_min = (cur_ms - last_edges_check_time) / 60000.0;
      double edges_gained = (double)(current_edges - last_edges_count);
      edges_growth_rate = edges_gained / time_elapsed_min;  // edges per minute
      
      if (!ablation_no_adaptive) {
        // Adaptive threshold adjustment (revised: raised floor to 150):
        // High growth (>5 edges/min): threshold=300 (let fuzzer work undisturbed)
        // Medium growth (1-5 edges/min): threshold=200 (moderate LLM frequency)
        // Low growth (<1 edge/min): threshold=150 (more LLM calls, but bounded)
        //
        // P1-MQTT: For MQTT binary protocol, use higher thresholds to
        // reduce wasteful LLM calls (hypothesis has <10% parse success).
        u32 floor_low  = 150, floor_mid = 200, floor_high = 300;
        if (protocol_name && strcasecmp(protocol_name, "MQTT") == 0) {
          floor_low = 500; floor_mid = 600; floor_high = 800;
        }
        if (edges_growth_rate > 5.0) {
          adaptive_plateau_threshold = floor_high;
        } else if (edges_growth_rate > 1.0) {
          adaptive_plateau_threshold = floor_mid;
        } else {
          adaptive_plateau_threshold = floor_low;
        }
      }
      /* else: ablation_no_adaptive keeps threshold at UNINTERESTING_THRESHOLD */
      
      fprintf(stderr, "[adaptive-plateau] edges_growth_rate=%.2f/min, threshold=%u%s\n",
              edges_growth_rate, adaptive_plateau_threshold,
              ablation_no_adaptive ? " (ABLATION: fixed)" : "");
    }
    last_edges_count = current_edges;
    last_edges_check_time = cur_ms;
  }
  
  if (uninteresting_times >= adaptive_plateau_threshold && chat_times < CHATTING_THRESHOLD)
  {
    uninteresting_times = 0;

    /* Fix-10b: Lazy hypothesis system init — only on first plateau trigger.
     * R9 showed eager init at startup cost 380s + 30MB RSS for exim with
     * zero benefit (hypothesis_parse_success=0). Deferring to first plateau
     * avoids the cost entirely for short runs and delays it until the fuzzer
     * actually needs LLM assistance. */
    if (hypothesis_mode && !hypothesis_ctx) {
      fprintf(stderr, "[hypothesis] Lazy init: first plateau reached, "
                      "initializing grammar hypothesis system now.\n");
      init_grammar_hypothesis_system();
    }

    /* Fix-15 Tier-2: Check if any hypothesis needs refinement.
     * This is a natural place: we are already in the plateau handler
     * which tolerates LLM-level latency.  periodic_hypothesis_refinement()
     * internally checks the validation count modulo gate.
     * Gated by ablation_no_refinement for ablation experiments. */
    if (!ablation_no_refinement) {
      periodic_hypothesis_refinement();
    }

    fprintf(stderr, "[plateau-trigger] Triggering LLM (growth_rate=%.2f, threshold=%u, chat_times=%u)\n",
            edges_growth_rate, adaptive_plateau_threshold, chat_times);

    u32 *response_bytes_temp = NULL;
    u32 buffer_len = 0;
    u32 response_count = 0;
    char *response_fname = alloc_printf("%s/responses-ipsm/id:%s", out_dir, basename(queue_cur->fname));
    char **responses_temp = get_responses_from_file(response_fname, &response_bytes_temp, &response_count, &buffer_len);
    if (responses_temp == NULL)
    {
      ck_free(response_fname);
      goto plateau_done;
    }

    chat_times++;
    ck_free(response_fname);

    char *history = NULL;
    u32 history_len = 0;
    char *examples = NULL;
    int examples_len = 0;
    kliter_t(lms) *it_pref = kl_begin(kl_messages);
    int i = 0;
    int empty = 1;
    int prev_len = 0;
    for (; i < response_count && it_pref != M2_prev; i++, it_pref = kl_next(it_pref))
    {
      empty = 0;

      json_object *request_v = json_object_new_string_len(kl_val(it_pref)->mdata, kl_val(it_pref)->msize);
      char *request = strdup(json_object_to_json_string(request_v));
      json_object_put(request_v);
      int request_len = strlen(request) - 2;
      request++;
      for (int i = 0; i < request_len; i++)
      {
        if (!isprint(request[i]) || request[i] < 0 || request[i] >= 127)
          request[i] = ' ';
      }

      json_object *response_v = json_object_new_string_len(responses_temp[i], response_bytes_temp[i] - prev_len);
      char *response = strdup(json_object_to_json_string(response_v));
      json_object_put(response_v);
      prev_len = response_bytes_temp[i];
      int response_len = strlen(response) - 2;
      response++;

      for (int i = 0; i < response_len; i++)
      {
        if (!isprint(response[i]) || response[i] < 0 || response[i] >= 127)
          response[i] = ' ';
      }

      /* Fix-21: examples used to put the same request in both Request-1 and
       * Request-2 (i==0 branch above), wasting the 400-token budget and
       * giving LLM a misleading "two identical examples".
       * Now Request-1 gets the first request, Request-2 gets the second.
       * We build examples lazily across the first two loop iterations. */
      if (i == 0)
      {
        /* First request → Request-1.  Request-2 filled below on i==1. */
        examples_len = asprintf(&examples, "Request-1:\n%.*s\n", request_len, request);
      }
      else if (i == 1 && examples != NULL)
      {
        /* Second request → append as Request-2 */
        char *old_examples = examples;
        int new_len = asprintf(&examples, "%sRequest-2:\n%.*s\n",
                               old_examples, request_len, request);
        free(old_examples);
        examples_len = new_len;
      }

      history = ck_realloc(history, history_len + request_len);
      memcpy(history + history_len, request, request_len);
      history_len += request_len;

      history = ck_realloc(history, history_len + response_len);
      memcpy(history + history_len, response, response_len);
      history_len += response_len;

      free(request - 1);
      free(response - 1);
    }

    if (!empty)
    {
      history = ck_realloc(history, history_len + 1);
      history[history_len] = '\0';

      if (history_len > HISTORY_PROMPT_LENGTH)
      {
        int offset = history_len - HISTORY_PROMPT_LENGTH;
        if (history[offset - 1] == '\\')
        {
          offset++;
        }
        char *history_temp = ck_strdup(history + offset);
        ck_free(history);
        history = history_temp;
        history_len = history_len - offset;
      }

      if (examples_len > EXAMPLES_PROMPT_LENGTH)
      {
        int offset = examples_len - EXAMPLES_PROMPT_LENGTH;
        if (examples[offset - 1] == '\\')
        {
          offset++;
        }
        char *examples_temp = strdup(examples + offset);
        free(examples);
        examples = examples_temp;
        examples_len = examples_len - offset;
      }

      /* Fork off an isolated helper to call the LLM and extract/format the
       * suggested request. This keeps the main fuzzer process insulated from
       * potential memory issues in network/parsing code. The child writes the
       * result to a temp file which the parent validates and consumes. */
      {
        /* Build rich state-context JSON including per-state coverage details.
         * ABLATION: When CHATAFL_NO_STATE_PROMPT is set, skip state_ctx entirely
         * so the child falls back to the simple ChatAFL-style prompt. */
        char *state_ctx = NULL;
        if (!ablation_no_state_prompt)
        {
          struct json_object *jctx = json_object_new_object();
          json_object_object_add(jctx, "nodes",           json_object_new_int(agnnodes(ipsm)));
          json_object_object_add(jctx, "edges",           json_object_new_int(agnedges(ipsm)));
          json_object_object_add(jctx, "growth_rate",     json_object_new_double(edges_growth_rate));
          json_object_object_add(jctx, "pending_favored", json_object_new_int(pending_favored));
          json_object_object_add(jctx, "queued_paths",    json_object_new_int(queued_paths));
          json_object_object_add(jctx, "chat_times",      json_object_new_int(chat_times));
          json_object_object_add(jctx, "target_state_id", json_object_new_int(target_state_id));
          if (protocol_name && strcasecmp(protocol_name, "MQTT") == 0 && mqtt_cluster_diff_summary)
          {
            json_object_object_add(jctx, "mqtt_cluster_diff", json_object_new_string(mqtt_cluster_diff_summary));
            json_object_object_add(jctx, "mqtt_cluster_brokers", json_object_new_int(mqtt_cluster_broker_count));
            json_object_object_add(jctx, "mqtt_cluster_unique_signatures", json_object_new_int(mqtt_cluster_unique_signatures));
            json_object_object_add(jctx, "mqtt_cluster_diverged", json_object_new_boolean(mqtt_cluster_diverged));
          }

          /* Per-state coverage: sort all states by effectiveness ascending (stuck states first) */
          struct json_object *jstates = json_object_new_array();
          if (state_ids_count > 0) {
            u32 *sorted_sids = malloc(state_ids_count * sizeof(u32));
            if (sorted_sids) {
              memcpy(sorted_sids, state_ids, state_ids_count * sizeof(u32));
              /* Bubble sort by paths_discovered/(selected_times+1) asc (small N, OK) */
              for (u32 a = 0; a < state_ids_count; a++) {
                for (u32 b = a + 1; b < state_ids_count; b++) {
                  khint_t ka = kh_get(hms, khms_states, sorted_sids[a]);
                  khint_t kb = kh_get(hms, khms_states, sorted_sids[b]);
                  if (ka == kh_end(khms_states) || kb == kh_end(khms_states)) continue;
                  state_info_t *sa2 = kh_val(khms_states, ka);
                  state_info_t *sb2 = kh_val(khms_states, kb);
                  double ea = (double)sa2->paths_discovered / (sa2->selected_times + 1.0);
                  double eb = (double)sb2->paths_discovered / (sb2->selected_times + 1.0);
                  if (ea > eb) { u32 tmp = sorted_sids[a]; sorted_sids[a] = sorted_sids[b]; sorted_sids[b] = tmp; }
                }
              }
              u32 max_states = state_ids_count < 8 ? state_ids_count : 8;
              for (u32 si = 0; si < max_states; si++) {
                khint_t k2 = kh_get(hms, khms_states, sorted_sids[si]);
                if (k2 == kh_end(khms_states)) continue;
                state_info_t *st2 = kh_val(khms_states, k2);
                struct json_object *js = json_object_new_object();
                json_object_object_add(js, "id",               json_object_new_int(sorted_sids[si]));
                json_object_object_add(js, "paths",            json_object_new_int(st2->paths));
                json_object_object_add(js, "paths_discovered", json_object_new_int(st2->paths_discovered));
                json_object_object_add(js, "selected_times",   json_object_new_int(st2->selected_times));
                json_object_object_add(js, "fuzzs",            json_object_new_int(st2->fuzzs));
                json_object_object_add(js, "seeds_count",      json_object_new_int(st2->seeds_count));
                /* Fix-19: Expose acceptability metadata to LLM */
                json_object_object_add(js, "is_error",
                    json_object_new_boolean(st2->error_hint == 1));
                json_object_object_add(js, "productivity",
                    json_object_new_double(st2->productivity));
                /* List up to 5 seed indices reachable from this state */
                struct json_object *jsids2 = json_object_new_array();
                u32 max_s = st2->seeds_count < 5 ? st2->seeds_count : 5;
                for (u32 i = 0; i < max_s; i++) {
                  struct queue_entry *sq = (struct queue_entry *)st2->seeds[i];
                  if (sq) json_object_array_add(jsids2, json_object_new_int(sq->index));
                }
                json_object_object_add(js, "seed_ids", jsids2);
                json_object_array_add(jstates, js);
              }
              free(sorted_sids);
            }
          }
          json_object_object_add(jctx, "states", jstates);
          state_ctx = strdup(json_object_to_json_string(jctx));
          json_object_put(jctx);
        }

        char *out_path = alloc_printf("%s/stall-interactions/llm-suggest-%d", out_dir, chat_times);

        /* ---- Prompt-hash dedup: skip redundant LLM calls ---- */
        {
          /* djb2 hash over the concatenation of examples+history+state_ctx */
          u32 h = 5381;
          if (examples) for (const char *p = examples; *p; p++) h = ((h << 5) + h) ^ (u8)*p;
          if (history)  for (const char *p = history;  *p; p++) h = ((h << 5) + h) ^ (u8)*p;
          if (state_ctx) for (const char *p = state_ctx; *p; p++) h = ((h << 5) + h) ^ (u8)*p;
          if (h == 0) h = 1; /* avoid sentinel */
          /* Check ring buffer */
          u8 dup_found = 0;
          for (u32 di = 0; di < LLM_DEDUP_SLOTS; di++) {
            if (llm_prompt_hash_ring[di] == h) { dup_found = 1; break; }
          }
          if (dup_found) {
            llm_dedup_hits++;
            fprintf(stderr, "[plateau] Prompt-hash dedup hit (hash=%08x, total_dedup=%llu) — skipping LLM call\n",
                    h, (unsigned long long)llm_dedup_hits);
            if (state_ctx) { free(state_ctx); state_ctx = NULL; }
            ck_free(out_path);
            goto plateau_done;
          }
          /* Insert into ring */
          llm_prompt_hash_ring[llm_prompt_hash_count % LLM_DEDUP_SLOTS] = h;
          llm_prompt_hash_count++;
        }

        pid_t pid = fork();
        if (pid == 0)
        {
          /* Child — choose prompt strategy based on ablation flag.
           * ablation_no_state_prompt → use ChatAFL's simple construct_prompt_stall
           *                            (no state data, no actions[], suggested_request only)
           * default                  → use rich llm_handle_plateau with state_ctx + actions[] */
          char *res = NULL;
          if (ablation_no_state_prompt) {
            /* Ablation path: use ChatAFL's ORIGINAL prompt template
             * (simple wording, "You are a helpful assistant" system msg)
             * so the delta measures ALL prompt-engineering improvements. */
            char *stall_prompt = construct_prompt_stall_original(
                (char *)protocol_name, (char *)examples, (char *)history);
            char *stall_resp = chat_with_llm(stall_prompt, "gpt-4o-mini", STALL_RETRIES, 1.2);
            free(stall_prompt);
            if (stall_resp) {
              char *stall_msg = extract_stalled_message(stall_resp, strlen(stall_resp));
              free(stall_resp);
              if (stall_msg) {
                char *formatted = format_request_message(stall_msg);
                if (formatted) {
                  /* Wrap into JSON so parent-side validator still works */
                  struct json_object *jwrap = json_object_new_object();
                  json_object_object_add(jwrap, "suggested_request",
                                         json_object_new_string(formatted));
                  res = strdup(json_object_to_json_string(jwrap));
                  json_object_put(jwrap);
                  ck_free(formatted);
                }
              }
            }
          } else {
            res = llm_handle_plateau(protocol_name, examples, history, state_ctx);
          }
          if (res) {
            int fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (fd >= 0) {
              write(fd, res, strlen(res));
              close(fd);
            }
            free(res);
          }
          /* Write sidecar .tokens file with per-call token usage so the
           * parent process can accumulate cost metrics. */
          {
            char tokens_path[4096];
            snprintf(tokens_path, sizeof(tokens_path), "%s.tokens", out_path);
            int tfd = open(tokens_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (tfd >= 0) {
              char tbuf[128];
              int tlen = snprintf(tbuf, sizeof(tbuf), "%llu %llu\n",
                                  llm_last_prompt_tokens, llm_last_completion_tokens);
              write(tfd, tbuf, tlen);
              close(tfd);
            }
          }
          _exit(res ? 0 : 1);
        }

        /* Parent: wait for child with timeout */
        int status = 0;
        int elapsed = 0;
        const int max_wait = 60; /* seconds (was 150 — too much blocking) */
        while (elapsed < max_wait)
        {
          pid_t w = waitpid(pid, &status, WNOHANG);
          if (w == pid) break;
          sleep(1);
          elapsed++;
        }
        if (elapsed >= max_wait)
        {
          kill(pid, SIGKILL);
          waitpid(pid, &status, 0);
          fprintf(stderr, "[plateau] LLM helper timed out and was killed\n");
        }

        if (state_ctx) { free(state_ctx); state_ctx = NULL; }

        /* Try to read the suggested output */
        char *stall_message = NULL;
        int fd = open(out_path, O_RDONLY);
        if (fd >= 0)
        {
          struct stat st;
          if (fstat(fd, &st) == 0 && st.st_size > 0 && st.st_size < 65536)
          {
            stall_message = malloc(st.st_size + 1);
            if (!stall_message) { close(fd); ck_free(out_path); goto plateau_done; }
            memset(stall_message, 0, st.st_size + 1);
            ssize_t r = read(fd, stall_message, st.st_size);
            if (r > 0) stall_message[r] = '\0'; else { free(stall_message); stall_message = NULL; }
          }
          close(fd);
        }

        /* ---- Read sidecar .tokens file and accumulate LLM cost ---- */
        {
          char tokens_path[4096];
          snprintf(tokens_path, sizeof(tokens_path), "%s.tokens", out_path);
          int tfd = open(tokens_path, O_RDONLY);
          if (tfd >= 0) {
            char tbuf[128];
            ssize_t tr = read(tfd, tbuf, sizeof(tbuf) - 1);
            close(tfd);
            unlink(tokens_path); /* clean up */
            if (tr > 0) {
              tbuf[tr] = '\0';
              unsigned long long pt = 0, ct = 0;
              if (sscanf(tbuf, "%llu %llu", &pt, &ct) == 2) {
                llm_total_prompt_tokens     += pt;
                llm_total_completion_tokens += ct;
              }
            }
          }
          llm_total_calls++;
        }

        ck_free(out_path);

        /* Use centralized validator to parse/validate JSON schema and support actions[] */
        struct json_object *jroot = NULL;
        if (stall_message)
        {
          jroot = validate_and_parse_llm_json(stall_message);
          free(stall_message);
          stall_message = NULL;
        }

        if (jroot) {
          /* If it's a simple suggested_request, extract and keep it */
          struct json_object *jsr = NULL;
          if (json_object_object_get_ex(jroot, "suggested_request", &jsr)) {
            const char *req = json_object_get_string(jsr);
            if (req) stall_message = strdup(req);
          } else if (!ablation_no_state_prompt &&
                     json_object_object_get_ex(jroot, "actions", &jsr)) {
            /* Handle actions[] safely here — only when rich prompt is active.
             * ABLATION: ablation_no_state_prompt disables this branch because the
             * simple prompt never produces actions[], and even if it accidentally
             * did, the state IDs would be meaningless without state_ctx. */
            size_t nal = json_object_array_length(jsr);
            for (size_t ai = 0; ai < nal; ai++) {
              struct json_object *act = json_object_array_get_idx(jsr, ai);
              struct json_object *jtype = NULL;
              if (!json_object_object_get_ex(act, "type", &jtype)) continue;
              const char *type = json_object_get_string(jtype);
              if (!type) continue;

              if (strcmp(type, "propose_mutations") == 0) {
                struct json_object *jseed = NULL, *jops = NULL;
                if (!json_object_object_get_ex(act, "seed_id", &jseed)) continue;
                if (!json_object_object_get_ex(act, "ops", &jops)) continue;
                long sid = json_object_get_int(jseed);
                struct queue_entry *qe = find_queue_entry_by_index((u32)sid);
                if (!qe) continue;

                /* Read seed file */
                int sfd = open(qe->fname, O_RDONLY);
                if (sfd < 0) continue;
                struct stat st; if (fstat(sfd, &st) != 0) { close(sfd); continue; }
                if (st.st_size == 0 || st.st_size > 65536) { close(sfd); continue; }
                unsigned char *seedbuf = ck_alloc(st.st_size);
                ssize_t rr = read(sfd, seedbuf, st.st_size);
                close(sfd);
                if (rr <= 0) { ck_free(seedbuf); continue; }

                size_t nop = json_object_array_length(jops);
                for (size_t oi = 0; oi < nop; oi++) {
                  struct json_object *op = json_object_array_get_idx(jops, oi);
                  struct json_object *jop = NULL;
                  json_object_object_get_ex(op, "op", &jop);
                  const char *opname = json_object_get_string(jop);
                  if (!opname) continue;

                  /* Work on a copy */
                  unsigned char *buf = ck_alloc(rr + 512);
                  memcpy(buf, seedbuf, rr);
                  size_t buf_len = rr;

                  if (strcmp(opname, "insert") == 0 || strcmp(opname, "replace") == 0) {
                    struct json_object *jpos=NULL, *jbytes=NULL;
                    json_object_object_get_ex(op, "pos", &jpos);
                    json_object_object_get_ex(op, "bytes_base64", &jbytes);
                    long pos = json_object_get_int(jpos);
                    const char *b64 = json_object_get_string(jbytes);
                    size_t decoded_len = 0;
                    unsigned char *decoded = base64_decode(b64, strlen(b64), &decoded_len);
                    if (!decoded) { ck_free(buf); continue; }
                    if (pos < 0) pos = 0;
                    if ((size_t)pos > buf_len) pos = buf_len;
                    if (strcmp(opname, "insert") == 0) {
                      if (buf_len + decoded_len > 65536) { ck_free(decoded); ck_free(buf); continue; }
                      /* insert */
                      memmove(buf + pos + decoded_len, buf + pos, buf_len - pos);
                      memcpy(buf + pos, decoded, decoded_len);
                      buf_len += decoded_len;
                    } else {
                      /* replace up to decoded_len */
                      size_t tocopy = decoded_len;
                      if ((size_t)pos + tocopy > buf_len) tocopy = buf_len - pos;
                      memcpy(buf + pos, decoded, tocopy);
                    }
                    ck_free(decoded);
                  } else if (strcmp(opname, "flip") == 0) {
                    struct json_object *jpos=NULL, *jlen=NULL;
                    json_object_object_get_ex(op, "pos", &jpos);
                    json_object_object_get_ex(op, "len", &jlen);
                    long pos = json_object_get_int(jpos);
                    long ln = json_object_get_int(jlen);
                    if (pos < 0) pos = 0;
                    if (pos >= (long)buf_len) { ck_free(buf); continue; }
                    if (ln <= 0) ln = 1;
                    if ((size_t)(pos+ln) > buf_len) ln = buf_len - pos;
                    for (long b=0; b<ln; b++) buf[pos+b] = ~buf[pos+b];
                  } else {
                    /* unsupported action */
                    ck_free(buf); continue;
                  }

                  /* Submit mutated candidate safely via common_fuzz_stuff */
                  if (common_fuzz_stuff(argv, (char*)buf, (u32)buf_len)) {
                    /* do nothing extra here */
                  }

                  ck_free(buf);
                }

                ck_free(seedbuf);
              } else if (strcmp(type, "prioritize_seeds") == 0) {
                struct json_object *jsids = NULL;
                if (!json_object_object_get_ex(act, "seed_ids", &jsids) || !json_object_is_type(jsids, json_type_array)) {
                  /* malformed, skip */
                } else {
                  size_t nm = json_object_array_length(jsids);
                  for (size_t k = 0; k < nm; k++) {
                    struct json_object *jid = json_object_array_get_idx(jsids, k);
                    if (!json_object_is_type(jid, json_type_int)) continue;
                    long v = json_object_get_int(jid);
                    if (v < 0) continue;
                    struct queue_entry *qe = find_queue_entry_by_index((u32)v);
                    if (!qe) continue;
                    if (!qe->favored) {
                      qe->favored = 1;
                      queued_favored++;
                      pending_favored++;
                      fprintf(stderr, "[llm-prioritize] Seed id %ld (%s) marked as favored\n",
                              v, qe->fname ? (char*)qe->fname : "<unknown>");
                    } else {
                      fprintf(stderr, "[llm-prioritize] Seed id %ld already favored, skipping\n", v);
                    }
                    /* Update selected_seed_index for EVERY state whose pool contains this
                     * seed. This ensures choose_seed(target_state_id, mode) picks the
                     * LLM-recommended seed regardless of which state was set as target.
                     * Previously only generating_state_id's pool was updated, so any
                     * set_target_state redirect to a different state had no effect. */
                    {
                      u32 _skey; state_info_t *_sval;
                      kh_foreach(khms_states, _skey, _sval, {
                        for (u32 si3 = 0; si3 < _sval->seeds_count; si3++) {
                          if ((struct queue_entry *)_sval->seeds[si3] == qe) {
                            _sval->selected_seed_index = si3;
                            fprintf(stderr, "[llm-prioritize] State %u pool index -> %u (seed %s)\n",
                                    _skey, si3,
                                    qe->fname ? (char*)qe->fname : "?");
                            break;
                          }
                        }
                      });
                    }
                  } /* end for k < nm */
                } /* end else (valid jsids) */
              } else if (strcmp(type, "set_target_state") == 0) {
                struct json_object *jnew_sid = NULL;
                if (json_object_object_get_ex(act, "state_id", &jnew_sid)) {
                  u32 new_sid = (u32)json_object_get_int(jnew_sid);
                  khint_t k3 = kh_get(hms, khms_states, new_sid);
                  if (k3 != kh_end(khms_states)) {
                    fprintf(stderr, "[llm-state] LLM redirecting target_state_id: %u -> %u\n",
                            target_state_id, new_sid);
                    target_state_id = new_sid;
                  } else {
                    fprintf(stderr, "[llm-state] set_target_state: state %u not found, ignoring\n", new_sid);
                  }
                }
              } else if (strcmp(type, "suggest_strategy") == 0) {
                /* noop */
              }
            }
          }
          json_object_put(jroot);
        }

        if (stall_message != NULL)
        {
          /* Proceed with existing behavior: format/attempt to fuzz the suggested message */
          if (common_fuzz_stuff(argv, stall_message, strlen(stall_message)))
          {
            splicing_with = -1;
            if (!stop_soon && !queue_cur->cal_failed && !queue_cur->was_fuzzed)
            {
              queue_cur->was_fuzzed = 1;
              was_fuzzed_map[get_state_index(target_state_id)][queue_cur->index] = 1;
              pending_not_fuzzed--;
              if (queue_cur->favored) pending_favored--;
            }

            free(stall_message);
            delete_kl_messages(kl_messages);
            ck_free(history);
            free(examples);
            return ret_val;
          }

          free(stall_message);
        }

        free(examples);
        ck_free(history);
      }
    }
    else
    {
      /* empty */
    }
  }
plateau_done: ;

  /* Construct the buffer to be mutated and update out_buf */
  if (M2_prev == NULL)
  {
    it = kl_begin(kl_messages);
  }
  else
  {
    it = kl_next(M2_prev);
  }

  u32 in_buf_size = 0;
  while (it != M2_next)
  {
    in_buf = (u8 *)ck_realloc(in_buf, in_buf_size + kl_val(it)->msize);
    if (!in_buf)
      PFATAL("AFLNet cannot allocate memory for in_buf");
    // Retrieve data from kl_messages to populate the in_buf
    memcpy(&in_buf[in_buf_size], kl_val(it)->mdata, kl_val(it)->msize);

    in_buf_size += kl_val(it)->msize;
    it = kl_next(it);
  }

  orig_in = in_buf;

  out_buf = ck_alloc_nozero(in_buf_size);
  memcpy(out_buf, in_buf, in_buf_size);

  // Update len to keep the correct size of the buffer being mutated
  len = in_buf_size;

  // Save the len for later use
  M2_len = len;

  /*********************
   * PERFORMANCE SCORE *
   *********************/

  orig_perf = perf_score = calculate_score(queue_cur);

  /* Skip right away if -d is given, if we have done deterministic fuzzing on
     this entry ourselves (was_fuzzed), or if it has gone through deterministic
     testing in earlier, resumed runs (passed_det). */

  if (skip_deterministic || queue_cur->was_fuzzed || queue_cur->passed_det)
    goto havoc_stage;

  /* Skip deterministic fuzzing if exec path checksum puts this out of scope
     for this master instance. */

  if (master_max && (queue_cur->exec_cksum % master_max) != master_id - 1)
    goto havoc_stage;

  doing_det = 1;

  /*********************************************
   * SIMPLE BITFLIP (+dictionary construction) *
   *********************************************/

#define FLIP_BIT(_ar, _b)                   \
  do                                        \
  {                                         \
    u8 *_arf = (u8 *)(_ar);                 \
    u32 _bf = (_b);                         \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
  } while (0)

  /* Single walking bit. */

  stage_short = "flip1";
  stage_max = len << 3;
  stage_name = "bitflip 1/1";

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = queued_paths + unique_crashes;

  prev_cksum = queue_cur->exec_cksum;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++)
  {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);

    if (common_fuzz_stuff(argv, out_buf, len))
      goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);

    /* While flipping the least significant bit in every byte, pull of an extra
       trick to detect possible syntax tokens. In essence, the idea is that if
       you have a binary blob like this:

       xxxxxxxxIHDRxxxxxxxx

       ...and changing the leading and trailing bytes causes variable or no
       changes in program flow, but touching any character in the "IHDR" string
       always produces the same, distinctive path, it's highly likely that
       "IHDR" is an atomically-checked magic value of special significance to
       the fuzzed format.

       We do this here, rather than as a separate stage, because it's a nice
       way to keep the operation approximately "free" (i.e., no extra execs).

       Empirically, performing the check when flipping the least significant bit
       is advantageous, compared to doing it at the time of more disruptive
       changes, where the program flow may be affected in more violent ways.

       The caveat is that we won't generate dictionaries in the -d mode or -S
       mode - but that's probably a fair trade-off.

       This won't work particularly well with paths that exhibit variable
       behavior, but fails gracefully, so we'll carry out the checks anyway.

      */

    if (!dumb_mode && (stage_cur & 7) == 7)
    {

      u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

      if (stage_cur == stage_max - 1 && cksum == prev_cksum)
      {

        /* If at end of file and we are still collecting a string, grab the
           final character and force output. */

        if (a_len < MAX_AUTO_EXTRA)
          a_collect[a_len] = out_buf[stage_cur >> 3];
        a_len++;

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(a_collect, a_len);
      }
      else if (cksum != prev_cksum)
      {

        /* Otherwise, if the checksum has changed, see if we have something
           worthwhile queued up, and collect that if the answer is yes. */

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(a_collect, a_len);

        a_len = 0;
        prev_cksum = cksum;
      }

      /* Continue collecting string, but only if the bit flip actually made
         any difference - we don't want no-op tokens. */

      if (cksum != queue_cur->exec_cksum)
      {

        if (a_len < MAX_AUTO_EXTRA)
          a_collect[a_len] = out_buf[stage_cur >> 3];
        a_len++;
      }
    }
  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP1] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP1] += stage_max;

  /* Two walking bits. */

  stage_name = "bitflip 2/1";
  stage_short = "flip2";
  stage_max = (len << 3) - 1;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++)
  {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

    if (common_fuzz_stuff(argv, out_buf, len))
      goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP2] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP2] += stage_max;

  /* Four walking bits. */

  stage_name = "bitflip 4/1";
  stage_short = "flip4";
  stage_max = (len << 3) - 3;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++)
  {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

    if (common_fuzz_stuff(argv, out_buf, len))
      goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);
  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP4] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP4] += stage_max;

  /* Effector map setup. These macros calculate:

     EFF_APOS      - position of a particular file offset in the map.
     EFF_ALEN      - length of a map with a particular number of bytes.
     EFF_SPAN_ALEN - map span for a sequence of bytes.

   */

#define EFF_APOS(_p) ((_p) >> EFF_MAP_SCALE2)
#define EFF_REM(_x) ((_x) & ((1 << EFF_MAP_SCALE2) - 1))
#define EFF_ALEN(_l) (EFF_APOS(_l) + !!EFF_REM(_l))
#define EFF_SPAN_ALEN(_p, _l) (EFF_APOS((_p) + (_l)-1) - EFF_APOS(_p) + 1)

  /* Initialize effector map for the next step (see comments below). Always
     flag first and last byte as doing something. */

  eff_map = ck_alloc(EFF_ALEN(len));
  eff_map[0] = 1;

  if (EFF_APOS(len - 1) != 0)
  {
    eff_map[EFF_APOS(len - 1)] = 1;
    eff_cnt++;
  }

  /* Walking byte. */

  stage_name = "bitflip 8/8";
  stage_short = "flip8";
  stage_max = len;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++)
  {

    stage_cur_byte = stage_cur;

    out_buf[stage_cur] ^= 0xFF;

    if (common_fuzz_stuff(argv, out_buf, len))
      goto abandon_entry;

    /* We also use this stage to pull off a simple trick: we identify
       bytes that seem to have no effect on the current execution path
       even when fully flipped - and we skip them during more expensive
       deterministic stages, such as arithmetics or known ints. */

    if (!eff_map[EFF_APOS(stage_cur)])
    {

      u32 cksum;

      /* If in dumb mode or if the file is very short, just flag everything
         without wasting time on checksums. */

      if (!dumb_mode && len >= EFF_MIN_LEN)
        cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
      else
        cksum = ~queue_cur->exec_cksum;

      if (cksum != queue_cur->exec_cksum)
      {
        eff_map[EFF_APOS(stage_cur)] = 1;
        eff_cnt++;
      }
    }

    out_buf[stage_cur] ^= 0xFF;
  }

  /* If the effector map is more than EFF_MAX_PERC dense, just flag the
     whole thing as worth fuzzing, since we wouldn't be saving much time
     anyway. */

  if (eff_cnt != EFF_ALEN(len) &&
      eff_cnt * 100 / EFF_ALEN(len) > EFF_MAX_PERC)
  {

    memset(eff_map, 1, EFF_ALEN(len));

    blocks_eff_select += EFF_ALEN(len);
  }
  else
  {

    blocks_eff_select += eff_cnt;
  }

  blocks_eff_total += EFF_ALEN(len);

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP8] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP8] += stage_max;

  /* Two walking bytes. */

  if (len < 2)
    goto skip_bitflip;

  stage_name = "bitflip 16/8";
  stage_short = "flip16";
  stage_cur = 0;
  stage_max = len - 1;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++)
  {

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)])
    {
      stage_max--;
      continue;
    }

    stage_cur_byte = i;

    *(u16 *)(out_buf + i) ^= 0xFFFF;

    if (common_fuzz_stuff(argv, out_buf, len))
      goto abandon_entry;
    stage_cur++;

    *(u16 *)(out_buf + i) ^= 0xFFFF;
  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP16] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP16] += stage_max;

  if (len < 4)
    goto skip_bitflip;

  /* Four walking bytes. */

  stage_name = "bitflip 32/8";
  stage_short = "flip32";
  stage_cur = 0;
  stage_max = len - 3;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++)
  {

    /* Let's consult the effector map... */
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)])
    {
      stage_max--;
      continue;
    }

    stage_cur_byte = i;

    *(u32 *)(out_buf + i) ^= 0xFFFFFFFF;

    if (common_fuzz_stuff(argv, out_buf, len))
      goto abandon_entry;
    stage_cur++;

    *(u32 *)(out_buf + i) ^= 0xFFFFFFFF;
  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP32] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP32] += stage_max;

skip_bitflip:

  if (no_arith)
    goto skip_arith;

  /**********************
   * ARITHMETIC INC/DEC *
   **********************/

  /* 8-bit arithmetics. */

  stage_name = "arith 8/8";
  stage_short = "arith8";
  stage_cur = 0;
  stage_max = 2 * len * ARITH_MAX;

  stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++)
  {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)])
    {
      stage_max -= 2 * ARITH_MAX;
      continue;
    }

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++)
    {

      u8 r = orig ^ (orig + j);

      /* Do arithmetic operations only if the result couldn't be a product
         of a bitflip. */

      if (!could_be_bitflip(r))
      {

        stage_cur_val = j;
        out_buf[i] = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        stage_cur++;
      }
      else
        stage_max--;

      r = orig ^ (orig - j);

      if (!could_be_bitflip(r))
      {

        stage_cur_val = -j;
        out_buf[i] = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        stage_cur++;
      }
      else
        stage_max--;

      out_buf[i] = orig;
    }
  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH8] += stage_max;

  /* 16-bit arithmetics, both endians. */

  if (len < 2)
    goto skip_arith;

  stage_name = "arith 16/8";
  stage_short = "arith16";
  stage_cur = 0;
  stage_max = 4 * (len - 1) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++)
  {

    u16 orig = *(u16 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)])
    {
      stage_max -= 4 * ARITH_MAX;
      continue;
    }

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++)
    {

      u16 r1 = orig ^ (orig + j),
          r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP16(SWAP16(orig) + j),
          r4 = orig ^ SWAP16(SWAP16(orig) - j);

      /* Try little endian addition and subtraction first. Do it only
         if the operation would affect more than one byte (hence the
         & 0xff overflow checks) and if it couldn't be a product of
         a bitflip. */

      stage_val_type = STAGE_VAL_LE;

      if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1))
      {

        stage_cur_val = j;
        *(u16 *)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        stage_cur++;
      }
      else
        stage_max--;

      if ((orig & 0xff) < j && !could_be_bitflip(r2))
      {

        stage_cur_val = -j;
        *(u16 *)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        stage_cur++;
      }
      else
        stage_max--;

      /* Big endian comes next. Same deal. */

      stage_val_type = STAGE_VAL_BE;

      if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3))
      {

        stage_cur_val = j;
        *(u16 *)(out_buf + i) = SWAP16(SWAP16(orig) + j);

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        stage_cur++;
      }
      else
        stage_max--;

      if ((orig >> 8) < j && !could_be_bitflip(r4))
      {

        stage_cur_val = -j;
        *(u16 *)(out_buf + i) = SWAP16(SWAP16(orig) - j);

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        stage_cur++;
      }
      else
        stage_max--;

      *(u16 *)(out_buf + i) = orig;
    }
  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_ARITH16] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH16] += stage_max;

  /* 32-bit arithmetics, both endians. */

  if (len < 4)
    goto skip_arith;

  stage_name = "arith 32/8";
  stage_short = "arith32";
  stage_cur = 0;
  stage_max = 4 * (len - 3) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++)
  {

    u32 orig = *(u32 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)])
    {
      stage_max -= 4 * ARITH_MAX;
      continue;
    }

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++)
    {

      u32 r1 = orig ^ (orig + j),
          r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP32(SWAP32(orig) + j),
          r4 = orig ^ SWAP32(SWAP32(orig) - j);

      /* Little endian first. Same deal as with 16-bit: we only want to
         try if the operation would have effect on more than two bytes. */

      stage_val_type = STAGE_VAL_LE;

      if ((orig & 0xffff) + j > 0xffff && !could_be_bitflip(r1))
      {

        stage_cur_val = j;
        *(u32 *)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        stage_cur++;
      }
      else
        stage_max--;

      if ((orig & 0xffff) < j && !could_be_bitflip(r2))
      {

        stage_cur_val = -j;
        *(u32 *)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        stage_cur++;
      }
      else
        stage_max--;

      /* Big endian next. */

      stage_val_type = STAGE_VAL_BE;

      if ((SWAP32(orig) & 0xffff) + j > 0xffff && !could_be_bitflip(r3))
      {

        stage_cur_val = j;
        *(u32 *)(out_buf + i) = SWAP32(SWAP32(orig) + j);

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        stage_cur++;
      }
      else
        stage_max--;

      if ((SWAP32(orig) & 0xffff) < j && !could_be_bitflip(r4))
      {

        stage_cur_val = -j;
        *(u32 *)(out_buf + i) = SWAP32(SWAP32(orig) - j);

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        stage_cur++;
      }
      else
        stage_max--;

      *(u32 *)(out_buf + i) = orig;
    }
  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_ARITH32] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH32] += stage_max;

skip_arith:

  /**********************
   * INTERESTING VALUES *
   **********************/

  stage_name = "interest 8/8";
  stage_short = "int8";
  stage_cur = 0;
  stage_max = len * sizeof(interesting_8);

  stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  /* Setting 8-bit integers. */

  for (i = 0; i < len; i++)
  {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)])
    {
      stage_max -= sizeof(interesting_8);
      continue;
    }

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_8); j++)
    {

      /* Skip if the value could be a product of bitflips or arithmetics. */

      if (could_be_bitflip(orig ^ (u8)interesting_8[j]) ||
          could_be_arith(orig, (u8)interesting_8[j], 1))
      {
        stage_max--;
        continue;
      }

      stage_cur_val = interesting_8[j];
      out_buf[i] = interesting_8[j];

      if (common_fuzz_stuff(argv, out_buf, len))
        goto abandon_entry;

      out_buf[i] = orig;
      stage_cur++;
    }
  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_INTEREST8] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST8] += stage_max;

  /* Setting 16-bit integers, both endians. */

  if (no_arith || len < 2)
    goto skip_interest;

  stage_name = "interest 16/8";
  stage_short = "int16";
  stage_cur = 0;
  stage_max = 2 * (len - 1) * (sizeof(interesting_16) >> 1);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++)
  {

    u16 orig = *(u16 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)])
    {
      stage_max -= sizeof(interesting_16);
      continue;
    }

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_16) / 2; j++)
    {

      stage_cur_val = interesting_16[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or single-byte interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&
          !could_be_arith(orig, (u16)interesting_16[j], 2) &&
          !could_be_interest(orig, (u16)interesting_16[j], 2, 0))
      {

        stage_val_type = STAGE_VAL_LE;

        *(u16 *)(out_buf + i) = interesting_16[j];

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        stage_cur++;
      }
      else
        stage_max--;

      if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&
          !could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&
          !could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&
          !could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1))
      {

        stage_val_type = STAGE_VAL_BE;

        *(u16 *)(out_buf + i) = SWAP16(interesting_16[j]);
        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        stage_cur++;
      }
      else
        stage_max--;
    }

    *(u16 *)(out_buf + i) = orig;
  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_INTEREST16] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST16] += stage_max;

  if (len < 4)
    goto skip_interest;

  /* Setting 32-bit integers, both endians. */

  stage_name = "interest 32/8";
  stage_short = "int32";
  stage_cur = 0;
  stage_max = 2 * (len - 3) * (sizeof(interesting_32) >> 2);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++)
  {

    u32 orig = *(u32 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)])
    {
      stage_max -= sizeof(interesting_32) >> 1;
      continue;
    }

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_32) / 4; j++)
    {

      stage_cur_val = interesting_32[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or word interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u32)interesting_32[j]) &&
          !could_be_arith(orig, interesting_32[j], 4) &&
          !could_be_interest(orig, interesting_32[j], 4, 0))
      {

        stage_val_type = STAGE_VAL_LE;

        *(u32 *)(out_buf + i) = interesting_32[j];

        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        stage_cur++;
      }
      else
        stage_max--;

      if ((u32)interesting_32[j] != SWAP32(interesting_32[j]) &&
          !could_be_bitflip(orig ^ SWAP32(interesting_32[j])) &&
          !could_be_arith(orig, SWAP32(interesting_32[j]), 4) &&
          !could_be_interest(orig, SWAP32(interesting_32[j]), 4, 1))
      {

        stage_val_type = STAGE_VAL_BE;

        *(u32 *)(out_buf + i) = SWAP32(interesting_32[j]);
        if (common_fuzz_stuff(argv, out_buf, len))
          goto abandon_entry;
        stage_cur++;
      }
      else
        stage_max--;
    }

    *(u32 *)(out_buf + i) = orig;
  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_INTEREST32] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST32] += stage_max;

skip_interest:

  /********************
   * DICTIONARY STUFF *
   ********************/

  if (!extras_cnt)
    goto skip_user_extras;

  /* Overwrite with user-supplied extras. */

  stage_name = "user extras (over)";
  stage_short = "ext_UO";
  stage_cur = 0;
  stage_max = extras_cnt * len;

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++)
  {

    u32 last_len = 0;

    stage_cur_byte = i;

    /* Extras are sorted by size, from smallest to largest. This means
       that we don't have to worry about restoring the buffer in
       between writes at a particular offset determined by the outer
       loop. */

    for (j = 0; j < extras_cnt; j++)
    {

      /* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
         skip them if there's no room to insert the payload, if the token
         is redundant, or if its entire span has no bytes set in the effector
         map. */

      if ((extras_cnt > MAX_DET_EXTRAS && UR(extras_cnt) >= MAX_DET_EXTRAS) ||
          extras[j].len > len - i ||
          !memcmp(extras[j].data, out_buf + i, extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, extras[j].len)))
      {

        stage_max--;
        continue;
      }

      last_len = extras[j].len;
      memcpy(out_buf + i, extras[j].data, last_len);

      if (common_fuzz_stuff(argv, out_buf, len))
        goto abandon_entry;

      stage_cur++;
    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);
  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_EXTRAS_UO] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_UO] += stage_max;

  /* Insertion of user-supplied extras. */

  stage_name = "user extras (insert)";
  stage_short = "ext_UI";
  stage_cur = 0;
  stage_max = extras_cnt * len;

  orig_hit_cnt = new_hit_cnt;

  ex_tmp = ck_alloc(len + MAX_DICT_FILE);

  for (i = 0; i <= len; i++)
  {

    stage_cur_byte = i;

    for (j = 0; j < extras_cnt; j++)
    {

      if (len + extras[j].len > MAX_FILE)
      {
        stage_max--;
        continue;
      }

      /* Insert token */
      memcpy(ex_tmp + i, extras[j].data, extras[j].len);

      /* Copy tail */
      memcpy(ex_tmp + i + extras[j].len, out_buf + i, len - i);

      if (common_fuzz_stuff(argv, ex_tmp, len + extras[j].len))
      {
        ck_free(ex_tmp);
        goto abandon_entry;
      }

      stage_cur++;
    }

    /* Copy head */
    ex_tmp[i] = out_buf[i];
  }

  ck_free(ex_tmp);

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_EXTRAS_UI] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_UI] += stage_max;

skip_user_extras:

  if (!a_extras_cnt)
    goto skip_extras;

  stage_name = "auto extras (over)";
  stage_short = "ext_AO";
  stage_cur = 0;
  stage_max = MIN(a_extras_cnt, USE_AUTO_EXTRAS) * len;

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++)
  {

    u32 last_len = 0;

    stage_cur_byte = i;

    for (j = 0; j < MIN(a_extras_cnt, USE_AUTO_EXTRAS); j++)
    {

      /* See the comment in the earlier code; extras are sorted by size. */

      if (a_extras[j].len > len - i ||
          !memcmp(a_extras[j].data, out_buf + i, a_extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, a_extras[j].len)))
      {

        stage_max--;
        continue;
      }

      last_len = a_extras[j].len;
      memcpy(out_buf + i, a_extras[j].data, last_len);

      if (common_fuzz_stuff(argv, out_buf, len))
        goto abandon_entry;

      stage_cur++;
    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);
  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_EXTRAS_AO] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_AO] += stage_max;

skip_extras:

  /* If we made this to here without jumping to havoc_stage or abandon_entry,
     we're properly done with deterministic steps and can mark it as such
     in the .state/ directory. */

  if (!queue_cur->passed_det)
    mark_as_det_done(queue_cur);

  /****************
   * RANDOM HAVOC *
   ****************/

havoc_stage:;

  /* O4: Per-havoc generation context for semantic dependency injection.
   * Re-initialised each time we enter the havoc stage so that packets
   * within one pass share topic / client_id / pkt_id / alias state.
   * Declared as local auto (not static) — safe because fuzz_one() is
   * single-threaded and mqtt_gen_ctx_t is <2KB on the stack. */
  mqtt_gen_ctx_t mqtt_havoc_gen_ctx;
  if (mqtt_field_mutate_enabled)
    mqtt_gen_ctx_init(&mqtt_havoc_gen_ctx, 0);

  stage_cur_byte = -1;

  /* The havoc stage mutation code is also invoked when splicing files; if the
     splice_cycle variable is set, generate different descriptions and such. */

  if (!splice_cycle)
  {

    stage_name = "havoc";
    stage_short = "havoc";
    stage_max = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                perf_score / havoc_div / 100;
  }
  else
  {

    static u8 tmp[32];

    perf_score = orig_perf;

    sprintf(tmp, "splice %u", splice_cycle);
    stage_name = tmp;
    stage_short = "splice";
    stage_max = SPLICE_HAVOC * perf_score / havoc_div / 100;
  }

  if (stage_max < HAVOC_MIN)
    stage_max = HAVOC_MIN;

  temp_len = len;

  orig_hit_cnt = queued_paths + unique_crashes;

  havoc_queued = queued_paths;

  /* We essentially just do several thousand runs (depending on perf_score)
     where we take the input file and make random stacked tweaks. */

  // u32 mutable_len = 0;
  // for(int i = 0; i < rc;i++){
  //   mutable_len += ranges[i].len;
  // }
  range_list original_ranges;
  kv_init(original_ranges);

  double epsilon = UR(100) / 100.0;

  int is_exploration = epsilon < EPSILON_CHOICE;

  /* B3-fix: For MQTT, ALWAYS use packet-boundary ranges instead of
   * flat range (explore) or LLM grammar ranges (exploit, useless for
   * binary MQTT).  This makes ALL havoc mutations (cases 0-24)
   * MQTT-structure-aware — each mutation targets a single MQTT packet
   * instead of randomly corrupting cross-packet bytes.
   * Text protocols keep the original explore/exploit logic. */
  u8 mqtt_structured = (protocol_name &&
                        strcasecmp(protocol_name, "MQTT") == 0);

  if (mqtt_structured) {
    stage_name = is_exploration ? "havoc mqtt-explore" : "havoc mqtt-exploit";
    stage_short = is_exploration ? "mqtt_explore" : "mqtt_exploit";
    original_ranges = mqtt_parse_havoc_ranges(out_buf, temp_len);
  } else if (is_exploration)
  {
    stage_name = "havoc explore";
    stage_short = "havoc_explore";
    // exploration - fully random search
    range v = {.len = temp_len, .start = 0, .mutable = 1};
    kv_push(range, original_ranges, v);
  }
  else
  {
    stage_name = "havoc exploit";
    stage_short = "havoc_exploit";
    // exploitation - utilize the grammars we have

    original_ranges = parse_buffer(out_buf, temp_len);
  }

  int rc = kv_size(original_ranges);
  range *ranges = ck_alloc(rc * sizeof(range));
  memcpy(ranges, original_ranges.a, rc * sizeof(range));

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++)
  {

    u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));

    stage_cur_val = use_stacking;

    for (i = 0; i < use_stacking; i++)
    {

      u32 range_choice = UR(rc);
      // while(!ranges[range_choice].mutable){
      //   range_choice = UR(rc);
      // }
      switch (UR(15 + 2 + (region_level_mutation ? 8 : 0)))
      {

      case 0:

        /* Flip a single bit somewhere. Spooky! */
        if (ranges[range_choice].len < 1)
          break;

        FLIP_BIT((out_buf + ranges[range_choice].start), UR(ranges[range_choice].len << 3));

        // FLIP_BIT(out_buf, UR(temp_len << 3));
        break;

      case 1:
        /* Set byte to interesting value. */
        if (ranges[range_choice].len < 1)
          break;

        out_buf[ranges[range_choice].start + UR(ranges[range_choice].len)] = interesting_8[UR(sizeof(interesting_8))];
        break;

      case 2:

        /* Set word to interesting value, randomly choosing endian. */

        if (ranges[range_choice].len < 2)
          break;

        if (UR(2))
        {

          s32 offset = ranges[range_choice].start + UR(ranges[range_choice].len - 1);

          *(u16 *)(out_buf + offset) =
              interesting_16[UR(sizeof(interesting_16) >> 1)];
        }
        else
        {

          s32 offset = ranges[range_choice].start + UR(ranges[range_choice].len - 1);

          *(u16 *)(out_buf + offset) = SWAP16(
              interesting_16[UR(sizeof(interesting_16) >> 1)]);
        }

        break;

      case 3:

        /* Set dword to interesting value, randomly choosing endian. */

        if (ranges[range_choice].len < 4)
          break;

        if (UR(2))
        {
          s32 offset = ranges[range_choice].start + UR(ranges[range_choice].len - 3);
          *(u32 *)(out_buf + offset) =
              interesting_32[UR(sizeof(interesting_32) >> 2)];
        }
        else
        {
          s32 offset = ranges[range_choice].start + UR(ranges[range_choice].len - 3);
          *(u32 *)(out_buf + offset) = SWAP32(
              interesting_32[UR(sizeof(interesting_32) >> 2)]);
        }

        break;

      case 4:
        if (ranges[range_choice].len < 1)
          break;
        /* Randomly subtract from byte. */

        out_buf[ranges[range_choice].start + UR(ranges[range_choice].len)] -= 1 + UR(ARITH_MAX);
        break;

      case 5:
        if (ranges[range_choice].len < 1)
          break;
        /* Randomly add to byte. */

        out_buf[ranges[range_choice].start + UR(ranges[range_choice].len)] += 1 + UR(ARITH_MAX);
        break;

      case 6:

        /* Randomly subtract from word, random endian. */

        if (ranges[range_choice].len < 2)
          break;

        if (UR(2))
        {

          u32 pos = ranges[range_choice].start + UR(ranges[range_choice].len - 1);

          *(u16 *)(out_buf + pos) -= 1 + UR(ARITH_MAX);
        }
        else
        {

          u32 pos = ranges[range_choice].start + UR(ranges[range_choice].len - 1);
          u16 num = 1 + UR(ARITH_MAX);

          *(u16 *)(out_buf + pos) =
              SWAP16(SWAP16(*(u16 *)(out_buf + pos)) - num);
        }

        break;

      case 7:

        /* Randomly add to word, random endian. */

        if (ranges[range_choice].len < 2)
          break;

        if (UR(2))
        {

          u32 pos = ranges[range_choice].start + UR(ranges[range_choice].len - 1);

          *(u16 *)(out_buf + pos) += 1 + UR(ARITH_MAX);
        }
        else
        {

          u32 pos = ranges[range_choice].start + UR(ranges[range_choice].len - 1);
          u16 num = 1 + UR(ARITH_MAX);

          *(u16 *)(out_buf + pos) =
              SWAP16(SWAP16(*(u16 *)(out_buf + pos)) + num);
        }

        break;

      case 8:

        /* Randomly subtract from dword, random endian. */

        if (ranges[range_choice].len < 4)
          break;

        if (UR(2))
        {

          u32 pos = ranges[range_choice].start + UR(ranges[range_choice].len - 3);

          *(u32 *)(out_buf + pos) -= 1 + UR(ARITH_MAX);
        }
        else
        {

          u32 pos = ranges[range_choice].start + UR(ranges[range_choice].len - 3);
          u32 num = 1 + UR(ARITH_MAX);

          *(u32 *)(out_buf + pos) =
              SWAP32(SWAP32(*(u32 *)(out_buf + pos)) - num);
        }

        break;

      case 9:

        /* Randomly add to dword, random endian. */

        if (ranges[range_choice].len < 4)
          break;

        if (UR(2))
        {

          u32 pos = ranges[range_choice].start + UR(ranges[range_choice].len - 3);

          *(u32 *)(out_buf + pos) += 1 + UR(ARITH_MAX);
        }
        else
        {

          u32 pos = ranges[range_choice].start + UR(ranges[range_choice].len - 3);
          u32 num = 1 + UR(ARITH_MAX);

          *(u32 *)(out_buf + pos) =
              SWAP32(SWAP32(*(u32 *)(out_buf + pos)) + num);
        }

        break;

      case 10:
        if (ranges[range_choice].len < 1)
          break;
        /* Just set a random byte to a random value. Because,
           why not. We use XOR with 1-255 to eliminate the
           possibility of a no-op. */

        out_buf[ranges[range_choice].start + UR(ranges[range_choice].len)] ^= 1 + UR(255);
        break;

      case 11 ... 12:
      {

        /* Delete bytes. We're making this a bit more likely
           than insertion (the next option) in hopes of keeping
           files reasonably small. */

        u32 del_from, del_len;

        if (ranges[range_choice].len < 2)
          break;

        /* Don't delete too much. */

        del_len = choose_block_len(ranges[range_choice].len - 1);

        del_from = ranges[range_choice].start + UR(ranges[range_choice].len - del_len + 1);

        memmove(out_buf + del_from, out_buf + del_from + del_len,
                temp_len - del_from - del_len);

        temp_len -= del_len;
        // mutable_len -= del_len;
        for (int i = range_choice + 1; i < rc; i++)
        {
          ranges[i].start -= del_len;
        }
        ranges[range_choice].len -= del_len;
        break;
      }

      case 13:

        if (temp_len + HAVOC_BLK_XL < MAX_FILE)
        {

          /* Clone bytes (75%) or insert a block of constant bytes (25%). */

          u8 actually_clone = UR(4);
          u32 clone_from, clone_to, clone_len;
          u8 *new_buf;

          if (actually_clone)
          {

            clone_len = choose_block_len(temp_len);
            clone_from = UR(temp_len - clone_len + 1);
          }
          else
          {

            clone_len = choose_block_len(HAVOC_BLK_XL);
            clone_from = 0;
          }

          clone_to = ranges[range_choice].start + (ranges[range_choice].len == 0 ? 0 : UR(ranges[range_choice].len));

          new_buf = ck_alloc_nozero(temp_len + clone_len);

          /* Head */

          memcpy(new_buf, out_buf, clone_to);

          /* Inserted part */

          if (actually_clone)
            memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);
          else
            memset(new_buf + clone_to,
                   UR(2) ? UR(256) : out_buf[UR(temp_len)], clone_len);

          /* Tail */
          memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                 temp_len - clone_to);

          ck_free(out_buf);
          out_buf = new_buf;
          temp_len += clone_len;
          // mutable_len += clone_len;

          for (int i = range_choice + 1; i < rc; i++)
          {
            ranges[i].start += clone_len;
          }

          ranges[range_choice].len += clone_len;
        }

        break;

      case 14:
      {

        /* Overwrite bytes with a randomly selected chunk (75%) or fixed
           bytes (25%). */

        u32 copy_from, copy_to, copy_len;

        if (ranges[range_choice].len < 2)
          break;

        copy_len = choose_block_len(ranges[range_choice].len - 1);

        copy_from = UR(temp_len - copy_len + 1);
        copy_to = ranges[range_choice].start + UR(ranges[range_choice].len - copy_len + 1);

        if (UR(4))
        {

          if (copy_from != copy_to)
            memmove(out_buf + copy_to, out_buf + copy_from, copy_len);
        }
        else
          memset(out_buf + copy_to,
                 UR(2) ? UR(256) : out_buf[UR(temp_len)], copy_len);

        break;
      }

        /* Values 15 and 16 can be selected only if there are any extras
           present in the dictionaries. */

      case 15:
      {
        if (extras_cnt + a_extras_cnt == 0)
          break;

        /* Overwrite bytes with an extra. */

        if (!extras_cnt || (a_extras_cnt && UR(2)))
        {

          /* No user-specified extras or odds in our favor. Let's use an
             auto-detected one. */

          u32 use_extra = UR(a_extras_cnt);
          u32 extra_len = a_extras[use_extra].len;
          u32 insert_at;

          if (extra_len > ranges[range_choice].len)
            break;

          insert_at = ranges[range_choice].start + UR(ranges[range_choice].len - extra_len + 1);
          memcpy(out_buf + insert_at, a_extras[use_extra].data, extra_len);
        }
        else
        {

          /* No auto extras or odds in our favor. Use the dictionary. */

          u32 use_extra = UR(extras_cnt);
          u32 extra_len = extras[use_extra].len;
          u32 insert_at;

          if (extra_len > ranges[range_choice].len)
            break;

          insert_at = ranges[range_choice].start + UR(ranges[range_choice].len - extra_len + 1);
          memcpy(out_buf + insert_at, extras[use_extra].data, extra_len);
        }

        break;
      }

      case 16:
      {
        if (extras_cnt + a_extras_cnt == 0)
          break;

        u32 use_extra, extra_len, insert_at = ranges[range_choice].start + UR(ranges[range_choice].len + 1);
        u8 *new_buf;

        /* Insert an extra. Do the same dice-rolling stuff as for the
           previous case. */

        if (!extras_cnt || (a_extras_cnt && UR(2)))
        {

          use_extra = UR(a_extras_cnt);
          extra_len = a_extras[use_extra].len;

          if (temp_len + extra_len >= MAX_FILE)
            break;

          new_buf = ck_alloc_nozero(temp_len + extra_len);

          /* Head */
          memcpy(new_buf, out_buf, insert_at);

          /* Inserted part */
          memcpy(new_buf + insert_at, a_extras[use_extra].data, extra_len);
        }
        else
        {

          use_extra = UR(extras_cnt);
          extra_len = extras[use_extra].len;

          if (temp_len + extra_len >= MAX_FILE)
            break;

          new_buf = ck_alloc_nozero(temp_len + extra_len);

          /* Head */
          memcpy(new_buf, out_buf, insert_at);

          /* Inserted part */
          memcpy(new_buf + insert_at, extras[use_extra].data, extra_len);
        }

        /* Tail */
        memcpy(new_buf + insert_at + extra_len, out_buf + insert_at,
               temp_len - insert_at);

        ck_free(out_buf);
        out_buf = new_buf;
        temp_len += extra_len;

        for (int i = range_choice + 1; i < rc; i++)
        {
          ranges[i].start += extra_len;
        }

        ranges[range_choice].len += extra_len;

        break;
      }
      /* Values 17 to 20 can be selected only if region-level mutations are enabled */

      /* Replace the current region with a random region from a random seed */
      case 17 ... 18:
      {

        u32 src_region_len = 0;
        u8 *new_buf = choose_source_region(&src_region_len);
        if (new_buf == NULL)
          break;

        // replace the current region
        ck_free(out_buf);
        ck_free(ranges);

        out_buf = new_buf;
        temp_len = src_region_len;
        range_list temp_ranges = parse_buffer(out_buf, temp_len);
        rc = kv_size(temp_ranges);
        ranges = temp_ranges.a;
        break;
      }

      /* Insert a random region from a random seed to the beginning of the current region */
      case 19 ... 20:
      {
        u32 src_region_len = 0;
        u8 *src_region = choose_source_region(&src_region_len);
        if (src_region == NULL)
          break;

        if (temp_len + src_region_len >= MAX_FILE)
        {
          ck_free(src_region);
          break;
        }

        u8 *new_buf = ck_alloc_nozero(temp_len + src_region_len);

        memcpy(new_buf, src_region, src_region_len);

        memcpy(&new_buf[src_region_len], out_buf, temp_len);

        ck_free(out_buf);
        ck_free(src_region);
        out_buf = new_buf;
        temp_len += src_region_len;
        for (int i = 0; i < rc; i++)
        {
          ranges[i].start += src_region_len;
        }
        break;
      }

      /* Insert a random region from a random seed to the end of the current region */
      case 21 ... 22:
      {
        u32 src_region_len = 0;
        u8 *src_region = choose_source_region(&src_region_len);
        if (src_region == NULL)
          break;

        if (temp_len + src_region_len >= MAX_FILE)
        {
          ck_free(src_region);
          break;
        }

        u8 *new_buf = ck_alloc_nozero(temp_len + src_region_len);

        memcpy(new_buf, out_buf, temp_len);

        memcpy(new_buf + temp_len, src_region, src_region_len);

        ck_free(out_buf);
        ck_free(src_region);
        out_buf = new_buf;
        temp_len += src_region_len;
        break;
      }

      /* Duplicate the currently selected region */
      case 23 ... 24:
      {
        if (temp_len + ranges[range_choice].len >= MAX_FILE)
          break;

        u8 *new_buf = ck_alloc_nozero(temp_len + ranges[range_choice].len);

        u8 *start_dest = new_buf;
        u8 *start_src = out_buf;

        memcpy(start_dest, start_src, ranges[range_choice].start);

        start_dest += ranges[range_choice].start;
        start_src += ranges[range_choice].start;

        memcpy(start_dest, start_src, ranges[range_choice].len);

        start_dest += ranges[range_choice].len;

        memcpy(start_dest, start_src, ranges[range_choice].len);

        start_dest += ranges[range_choice].len;
        start_src += ranges[range_choice].len;

        memcpy(start_dest, start_src,
               temp_len - (ranges[range_choice].start + ranges[range_choice].len));

        ck_free(out_buf);
        out_buf = new_buf;
        temp_len += ranges[range_choice].len;
        // mutable_len += ranges[range_choice].len;

        for (int i = range_choice + 1; i < rc; i++)
        {
          ranges[i].start += ranges[range_choice].len;
        }
        ranges[range_choice].len *= 2;
        break;
      }
      }
    }

    /* P3: MQTT scheduler-guided generation + field-aware mutation.
     * When mqtt_scheduler_enabled:
     *   - UCB1 bandit selects which arm (replace/insert/field/skip)
     *   - Q-Learning selects which packet type to generate
     *   - Reward signal from queued_paths change updates both schedulers
     * Falls back to static dice probabilities during warmup. */
    u32 mqtt_last_arm = 3;          /* default: skip */
    u8  mqtt_last_pkt_type = 0;
    u32 mqtt_qp_snap = queued_paths;

    if (mqtt_field_mutate_enabled) {
      u32 arm;

      /* O7: Plateau corpus mutation — when the current state is
       * stalling (more than half way to the stall threshold), with
       * increasing probability inject content from a random queue
       * entry (corpus rotation) then apply field-aware mutation.
       * This mimics MBFuzzer's plateau-based corpus switching
       * strategy that feeds fresh genetic material to break through
       * coverage plateaus.
       *
       * When triggered, arm is forced to 4 (new "corpus-splice" arm)
       * which replaces a region of the current buffer with content
       * from a random queue entry, then falls through to field-aware
       * mutation as a post-processing step. */
      u8 plateau_active = 0;
      if (mqtt_diff_feedback_enabled && state_aware_mode &&
          mqtt_state_stall_counter && selected_state_index < mqtt_state_stall_cap) {
        u32 stall = mqtt_state_stall_counter[selected_state_index];
        /* Ramp probability: 0% at stall=0, ~50% at stall=threshold/2, ~80% at threshold */
        if (stall > MQTT_STALL_THRESHOLD / 4 &&
            UR(MQTT_STALL_THRESHOLD) < stall) {
          plateau_active = 1;
        }
      }

      if (plateau_active) {
        arm = 4;  /* O7: corpus-splice arm */
      } else if (mqtt_scheduler_enabled) {
        arm = mqtt_bandit_select(&mqtt_bandit);
      } else {
        /* Static fallback: 25%/15%/20%/10%/10%/20%
         * (B1/B3: reduced skip, added sub-pub pair arm for forwarding path) */
        u32 mqtt_dice = UR(20);
        if      (mqtt_dice < 5)  arm = 0;  /* replace region  25% */
        else if (mqtt_dice < 8)  arm = 1;  /* insert packet   15% */
        else if (mqtt_dice < 12) arm = 2;  /* field-aware     20% */
        else if (mqtt_dice < 14) arm = 3;  /* skip            10% */
        else if (mqtt_dice < 16) arm = 4;  /* corpus-splice   10% */
        else                     arm = 5;  /* sub-pub pair    20% */
      }
      mqtt_last_arm = arm;

      switch (arm) {
      case 0: /* Replace region with generated MQTT packet */ {
        u8 gen_buf[MQTG_MAX_PKT];
        u8 pt = mqtt_scheduler_enabled
                    ? mqtt_ql_select(&mqtt_ql, selected_state_index)
                    : 0;
        mqtt_last_pkt_type = pt;
        /* O4: Use context-aware generation for semantic dependency */
        u32 gen_len = mqtt_gen_packet_ctx(gen_buf, sizeof(gen_buf),
                                          &mqtt_havoc_gen_ctx, pt);
        if (gen_len > 0 && gen_len <= (u32)temp_len) {
          u32 rpos = UR(temp_len - gen_len + 1);
          memcpy(out_buf + rpos, gen_buf, gen_len);
        }
        break;
      }
      case 1: /* Insert generated MQTT packet */ {
        u8 gen_buf[MQTG_MAX_PKT];
        u8 pt = mqtt_scheduler_enabled
                    ? mqtt_ql_select(&mqtt_ql, selected_state_index)
                    : 0;
        mqtt_last_pkt_type = pt;
        /* O4: Use context-aware generation for semantic dependency */
        u32 gen_len = mqtt_gen_packet_ctx(gen_buf, sizeof(gen_buf),
                                          &mqtt_havoc_gen_ctx, pt);
        if (gen_len > 0 && temp_len + (s32)gen_len < MAX_FILE) {
          u32 ipos = UR(temp_len + 1);
          u8 *new_buf = ck_alloc_nozero(temp_len + gen_len);
          memcpy(new_buf, out_buf, ipos);
          memcpy(new_buf + ipos, gen_buf, gen_len);
          memcpy(new_buf + ipos + gen_len, out_buf + ipos, temp_len - ipos);
          ck_free(out_buf);
          out_buf = new_buf;
          temp_len += gen_len;
        }
        break;
      }
      case 2: /* Field-aware byte-level mutation */
        mqtt_field_aware_mutate(out_buf, temp_len);
        break;
      case 3: /* Skip — rely on generic havoc alone */
        break;

      case 4: /* O7: Plateau corpus-splice + field-aware mutation.
       * Pick a random queue entry, copy a region of its content into
       * the current buffer (replacing an equal-length region), then
       * apply field-aware mutation on top.  This injects fresh genetic
       * material from the corpus to break through coverage plateaus. */
      {
        if (queued_paths > 0 && queue && temp_len >= 4) {
          struct queue_entry *donor = queue;
          u32 donor_idx = UR(queued_paths);
          for (u32 di = 0; di < donor_idx && donor->next; di++)
            donor = donor->next;

          if (donor && donor->len >= 4 && donor->fname) {
            int donor_fd = open(donor->fname, O_RDONLY);
            if (donor_fd >= 0) {
              u32 donor_len = donor->len;
              u8 *donor_buf = ck_alloc_nozero(donor_len);
              if (read(donor_fd, donor_buf, donor_len) == (ssize_t)donor_len) {
                /* Splice: replace a random region of out_buf with donor content */
                u32 splice_len = (donor_len < (u32)temp_len)
                                   ? donor_len : (u32)temp_len;
                /* Use at most 1/2 of the buffer to keep some original structure */
                splice_len = splice_len / 2 + 1;
                if (splice_len > (u32)temp_len) splice_len = (u32)temp_len;
                u32 splice_off = UR(temp_len - splice_len + 1);
                u32 donor_off  = (donor_len > splice_len)
                                   ? UR(donor_len - splice_len + 1) : 0;
                memcpy(out_buf + splice_off, donor_buf + donor_off, splice_len);
              }
              ck_free(donor_buf);
              close(donor_fd);
            }
          }
        }
        /* Post-splice: always apply field-aware mutation */
        mqtt_field_aware_mutate(out_buf, temp_len);
        break;
      }

      case 5: /* B1-companion: SUBSCRIBE→PUBLISH pair injection.
       * Generate a coherent SUBSCRIBE + PUBLISH pair where the PUBLISH
       * topic matches the SUBSCRIBE filter, ensuring the broker will
       * forward the message and trigger the delivery code path
       * (subs__send → sub__messages_queue → send__publish).
       * This directly targets MBFuzzer's #1 advantage: forwarding-as-
       * coverage.  Uses the shared mqtt_havoc_gen_ctx so topic
       * dependencies are maintained across the pair. */
      {
        u8 sub_buf[MQTG_MAX_PKT], pub_buf[MQTG_MAX_PKT];
        /* Generate SUBSCRIBE first — records topic in context */
        u32 sub_len = mqtt_gen_packet_ctx(sub_buf, sizeof(sub_buf),
                                          &mqtt_havoc_gen_ctx, MQTG_SUBSCRIBE);
        /* Generate PUBLISH — context ensures topic matches subscription */
        u32 pub_len = mqtt_gen_packet_ctx(pub_buf, sizeof(pub_buf),
                                          &mqtt_havoc_gen_ctx, MQTG_PUBLISH);
        u32 pair_len = sub_len + pub_len;
        if (sub_len > 0 && pub_len > 0 &&
            temp_len + (s32)pair_len < MAX_FILE) {
          /* Insert the pair at a random position */
          u32 ipos = UR(temp_len + 1);
          u8 *new_buf = ck_alloc_nozero(temp_len + pair_len);
          memcpy(new_buf, out_buf, ipos);
          memcpy(new_buf + ipos, sub_buf, sub_len);
          memcpy(new_buf + ipos + sub_len, pub_buf, pub_len);
          memcpy(new_buf + ipos + pair_len, out_buf + ipos, temp_len - ipos);
          ck_free(out_buf);
          out_buf = new_buf;
          temp_len += pair_len;
        }
        mqtt_last_pkt_type = MQTG_SUBSCRIBE; /* attribute to SUBSCRIBE for QL */
        break;
      }

      }
    }

    if (common_fuzz_stuff(argv, out_buf, temp_len))
      goto abandon_entry;

    /* P3/P4: Update schedulers with blended reward.
     *   reward = coverage_gain + λ * differential_signal
     * O1: λ raised from 0.6 to 1.0 — differential divergence is
     * a first-class bug-finding signal, not merely auxiliary.
     * This aligns with MBFuzzer’s core design where divergence IS
     * the primary reward (they use reward=1 for any new diff). */
    if (mqtt_scheduler_enabled) {
      double reward = (queued_paths != mqtt_qp_snap) ? 1.0 : 0.0;
      if (mqtt_diff_feedback_enabled)
        reward += 1.0 * mqtt_last_diff_signal;  /* O1: λ=1.0 (was 0.6) */
      if (reward > 2.0) reward = 2.0;            /* O1: cap=2.0 (was 1.6) */
      mqtt_bandit_update(&mqtt_bandit, mqtt_last_arm, reward);
      if (mqtt_last_pkt_type > 0)
        mqtt_ql_update(&mqtt_ql, selected_state_index, mqtt_last_pkt_type, reward);

      /* O6: Feed reward back to the adaptive per-field mutation scheduler.
       * When arm 2 (field-aware) was selected, attribute the reward to
       * whichever specific mutation type was last applied.  This closes
       * the feedback loop so rarely-useful mutations shrink to the 3%
       * floor while productive ones grow.  */
      if (mqtt_last_arm == 2 && mqtt_field_mut_last_selected < MQTT_FIELD_MUT_COUNT)
        mqtt_field_mut_reward(mqtt_field_mut_last_selected, reward);
    }

    /* out_buf might have been mangled a bit, so let's restore it to its
       original size and shape. */

    if (temp_len < len)
      out_buf = ck_realloc(out_buf, len);
    temp_len = len;

    if (rc != kv_size(original_ranges))
      ranges = ck_realloc(ranges, kv_size(original_ranges) * sizeof(range));
    rc = kv_size(original_ranges);

    memcpy(out_buf, in_buf, len);
    memcpy(ranges, original_ranges.a, rc * sizeof(range));

    /* If we're finding new stuff, let's run for a bit longer, limits
       permitting. */

    if (queued_paths != havoc_queued)
    {

      if (perf_score <= HAVOC_MAX_MULT * 100)
      {
        stage_max *= 2;
        perf_score *= 2;
      }

      havoc_queued = queued_paths;
    }
  }
  kv_destroy(original_ranges);
  ck_free(ranges);

  new_hit_cnt = queued_paths + unique_crashes;

  if (!splice_cycle)
  {
    stage_finds[STAGE_HAVOC] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_HAVOC] += stage_max;
  }
  else
  {
    stage_finds[STAGE_SPLICE] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_SPLICE] += stage_max;
  }

#ifndef IGNORE_FINDS

  /************
   * SPLICING *
   ************/

  /* This is a last-resort strategy triggered by a full round with no findings.
     It takes the current input file, randomly selects another input, and
     splices them together at some offset, then relies on the havoc
     code to mutate that blob. */

retry_splicing:

  if (use_splicing && splice_cycle++ < SPLICE_CYCLES &&
      queued_paths > 1 && M2_len > 1)
  {

    struct queue_entry *target;
    u32 tid, split_at;
    u8 *new_buf;
    s32 f_diff, l_diff;

    /* First of all, if we've modified in_buf for havoc, let's clean that
       up... */

    if (in_buf != orig_in)
    {
      ck_free(in_buf);
      in_buf = orig_in;
      len = M2_len;
    }

    /* Pick a random queue entry and seek to it. Don't splice with yourself.
     * D1 splice bias ROLLED BACK (A7): experiment showed it narrowed
     * exploration, contributing to the 69% drop in cycles_done. */

    do
    {
      tid = UR(queued_paths);

      /* A7: D1 diff-aware splice bias disabled — keep uniform random */
#if 0  /* rolled back: caused 69% drop in cycles_done */
      if (mqtt_cov_stagnant && mqtt_diff_feedback_enabled &&
          UR(2) == 0 && queued_paths > 10) {
        struct queue_entry *scan = queue;
        u32 scan_start = UR(queued_paths);
        u32 scan_idx = scan_start;
        for (u32 skip = 0; skip < scan_start && scan; skip++)
          scan = scan->next;
        for (u32 tries = 0; tries < 8 && scan; tries++, scan = scan->next, scan_idx++) {
          if (scan->mqtt_diff_score > 0 && scan_idx != current_entry) {
            tid = scan_idx;
            break;
          }
        }
      }
#endif
    } while (tid == current_entry);

    splicing_with = tid;
    target = queue;

    while (tid >= 100)
    {
      target = target->next_100;
      tid -= 100;
    }
    while (tid--)
      target = target->next;

    /* Make sure that the target has a reasonable length. */

    while (target && (target->len < 2 || target == queue_cur))
    {
      target = target->next;
      splicing_with++;
    }

    if (!target)
      goto retry_splicing;

    /* Read the testcase into a new buffer. */

    fd = open(target->fname, O_RDONLY);

    if (fd < 0)
      PFATAL("Unable to open '%s'", target->fname);

    new_buf = ck_alloc_nozero(target->len);

    ck_read(fd, new_buf, target->len, target->fname);

    close(fd);

    /* Find a suitable splicing location, somewhere between the first and
       the last differing byte. Bail out if the difference is just a single
       byte or so. */

    locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);

    if (f_diff < 0 || l_diff < 2 || f_diff == l_diff)
    {
      ck_free(new_buf);
      goto retry_splicing;
    }

    /* Split somewhere between the first and last differing byte. */

    split_at = f_diff + UR(l_diff - f_diff);

    /* Do the thing. */

    len = target->len;
    memcpy(new_buf, in_buf, split_at);
    in_buf = new_buf;

    ck_free(out_buf);
    out_buf = ck_alloc_nozero(len);
    memcpy(out_buf, in_buf, len);

    goto havoc_stage;
  }

#endif /* !IGNORE_FINDS */

  ret_val = 0;

abandon_entry:

  splicing_with = -1;

  /* Update pending_not_fuzzed count if we made it through the calibration
     cycle and have not seen this entry before. */

  if (!stop_soon && !queue_cur->cal_failed && !queue_cur->was_fuzzed)
  {
    queue_cur->was_fuzzed = 1;
    was_fuzzed_map[get_state_index(target_state_id)][queue_cur->index] = 1;
    pending_not_fuzzed--;
    if (queue_cur->favored)
      pending_favored--;
  }

  // munmap(orig_in, queue_cur->len);
  ck_free(orig_in);

  if (in_buf != orig_in)
    ck_free(in_buf);
  ck_free(out_buf);
  ck_free(eff_map);

  delete_kl_messages(kl_messages);

  return ret_val;

#undef FLIP_BIT
}

/* Grab interesting test cases from other fuzzers. */

static void sync_fuzzers(char **argv)
{

  DIR *sd;
  struct dirent *sd_ent;
  u32 sync_cnt = 0;

  sd = opendir(sync_dir);
  if (!sd)
    PFATAL("Unable to open '%s'", sync_dir);

  stage_max = stage_cur = 0;
  cur_depth = 0;

  /* Look at the entries created for every other fuzzer in the sync directory. */

  while ((sd_ent = readdir(sd)))
  {

    static u8 stage_tmp[128];

    DIR *qd;
    struct dirent *qd_ent;
    u8 *qd_path, *qd_synced_path;
    u32 min_accept = 0, next_min_accept;

    s32 id_fd;

    /* Skip dot files and our own output directory. */

    if (sd_ent->d_name[0] == '.' || !strcmp(sync_id, sd_ent->d_name))
      continue;

    /* Skip anything that doesn't have a queue/ subdirectory. */

    qd_path = alloc_printf("%s/%s/queue", sync_dir, sd_ent->d_name);

    if (!(qd = opendir(qd_path)))
    {
      ck_free(qd_path);
      continue;
    }

    /* Retrieve the ID of the last seen test case. */

    qd_synced_path = alloc_printf("%s/.synced/%s", out_dir, sd_ent->d_name);

    id_fd = open(qd_synced_path, O_RDWR | O_CREAT, 0600);

    if (id_fd < 0)
      PFATAL("Unable to create '%s'", qd_synced_path);

    if (read(id_fd, &min_accept, sizeof(u32)) > 0)
      lseek(id_fd, 0, SEEK_SET);

    next_min_accept = min_accept;

    /* Show stats */

    sprintf(stage_tmp, "sync %u", ++sync_cnt);
    stage_name = stage_tmp;
    stage_cur = 0;
    stage_max = 0;

    /* For every file queued by this fuzzer, parse ID and see if we have looked at
       it before; exec a test case if not. */

    while ((qd_ent = readdir(qd)))
    {

      u8 *path;
      s32 fd;
      struct stat st;

      if (qd_ent->d_name[0] == '.' ||
          sscanf(qd_ent->d_name, CASE_PREFIX "%06u", &syncing_case) != 1 ||
          syncing_case < min_accept)
        continue;

      /* OK, sounds like a new one. Let's give it a try. */

      if (syncing_case >= next_min_accept)
        next_min_accept = syncing_case + 1;

      path = alloc_printf("%s/%s", qd_path, qd_ent->d_name);

      /* Allow this to fail in case the other fuzzer is resuming or so... */

      fd = open(path, O_RDONLY);

      if (fd < 0)
      {
        ck_free(path);
        continue;
      }

      if (fstat(fd, &st))
        PFATAL("fstat() failed");

      /* Ignore zero-sized or oversized files. */

      if (st.st_size && st.st_size <= MAX_FILE)
      {

        u8 fault;
        u8 *mem = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

        if (mem == MAP_FAILED)
          PFATAL("Unable to mmap '%s'", path);

        /* See what happens. We rely on save_if_interesting() to catch major
           errors and save the test case. */

        write_to_testcase(mem, st.st_size);

        region_t *regions;
        u32 region_count;
        regions = (*extract_requests)(mem, st.st_size, &region_count);
        kl_messages = construct_kl_messages(path, regions, region_count);

        fault = run_target(argv, exec_tmout);

        if (stop_soon)
          return;

        /* AFLNet: set this flag to enable request extractions while adding new seed to the queue */
        corpus_read_or_sync = 2;

        syncing_party = sd_ent->d_name;
        queued_imported += save_if_interesting(argv, mem, st.st_size, fault);
        syncing_party = 0;

        /* AFLNet delete the kl_messages */
        ck_free(regions);
        delete_kl_messages(kl_messages);

        /* AFLNet: unset this flag to disable request extractions while adding new seed to the queue */
        corpus_read_or_sync = 0;

        munmap(mem, st.st_size);

        if (!(stage_cur++ % stats_update_freq))
          show_stats();
      }

      ck_free(path);
      close(fd);
    }

    ck_write(id_fd, &next_min_accept, sizeof(u32), qd_synced_path);

    close(id_fd);
    closedir(qd);
    ck_free(qd_path);
    ck_free(qd_synced_path);
  }

  closedir(sd);
}

/* Handle stop signal (Ctrl-C, etc). */

static void handle_stop_sig(int sig)
{

  stop_soon = 1;

  if (child_pid > 0)
    kill(child_pid, SIGKILL);
  if (forksrv_pid > 0)
    kill(forksrv_pid, SIGKILL);
}

/* Handle skip request (SIGUSR1). */

static void handle_skipreq(int sig)
{

  skip_requested = 1;
}

/* Handle timeout (SIGALRM). */

static void handle_timeout(int sig)
{

  if (child_pid > 0)
  {

    child_timed_out = 1;
    kill(child_pid, SIGKILL);
  }
  else if (child_pid == -1 && forksrv_pid > 0)
  {

    child_timed_out = 1;
    kill(forksrv_pid, SIGKILL);
  }
}

/* Do a PATH search and find target binary to see that it exists and
   isn't a shell script - a common and painful mistake. We also check for
   a valid ELF header and for evidence of AFL instrumentation. */

EXP_ST void check_binary(u8 *fname)
{

  u8 *env_path = 0;
  struct stat st;

  s32 fd;
  u8 *f_data;
  u32 f_len = 0;

  ACTF("Validating target binary...");

  if (strchr(fname, '/') || !(env_path = getenv("PATH")))
  {

    target_path = ck_strdup(fname);
    if (stat(target_path, &st) || !S_ISREG(st.st_mode) ||
        !(st.st_mode & 0111) || (f_len = st.st_size) < 4)
      FATAL("Program '%s' not found or not executable", fname);
  }
  else
  {

    while (env_path)
    {

      u8 *cur_elem, *delim = strchr(env_path, ':');

      if (delim)
      {

        cur_elem = ck_alloc(delim - env_path + 1);
        memcpy(cur_elem, env_path, delim - env_path);
        delim++;
      }
      else
        cur_elem = ck_strdup(env_path);

      env_path = delim;

      if (cur_elem[0])
        target_path = alloc_printf("%s/%s", cur_elem, fname);
      else
        target_path = ck_strdup(fname);

      ck_free(cur_elem);

      if (!stat(target_path, &st) && S_ISREG(st.st_mode) &&
          (st.st_mode & 0111) && (f_len = st.st_size) >= 4)
        break;

      ck_free(target_path);
      target_path = 0;
    }

    if (!target_path)
      FATAL("Program '%s' not found or not executable", fname);
  }

  if (getenv("AFL_SKIP_BIN_CHECK"))
    return;

  /* Check for blatant user errors. */

  if ((!strncmp(target_path, "/tmp/", 5) && !strchr(target_path + 5, '/')) ||
      (!strncmp(target_path, "/var/tmp/", 9) && !strchr(target_path + 9, '/')))
    FATAL("Please don't keep binaries in /tmp or /var/tmp");

  fd = open(target_path, O_RDONLY);

  if (fd < 0)
    PFATAL("Unable to open '%s'", target_path);

  f_data = mmap(0, f_len, PROT_READ, MAP_PRIVATE, fd, 0);

  if (f_data == MAP_FAILED)
    PFATAL("Unable to mmap file '%s'", target_path);

  close(fd);

  if (f_data[0] == '#' && f_data[1] == '!')
  {

    SAYF("\n" cLRD "[-] " cRST
         "Oops, the target binary looks like a shell script. Some build systems will\n"
         "    sometimes generate shell stubs for dynamically linked programs; try static\n"
         "    library mode (./configure --disable-shared) if that's the case.\n\n"

         "    Another possible cause is that you are actually trying to use a shell\n"
         "    wrapper around the fuzzed component. Invoking shell can slow down the\n"
         "    fuzzing process by a factor of 20x or more; it's best to write the wrapper\n"
         "    in a compiled language instead.\n");

    FATAL("Program '%s' is a shell script", target_path);
  }

#ifndef __APPLE__

  if (f_data[0] != 0x7f || memcmp(f_data + 1, "ELF", 3))
    FATAL("Program '%s' is not an ELF binary", target_path);

#else

  if (f_data[0] != 0xCF || f_data[1] != 0xFA || f_data[2] != 0xED)
    FATAL("Program '%s' is not a 64-bit Mach-O binary", target_path);

#endif /* ^!__APPLE__ */

  if (!qemu_mode && !dumb_mode &&
      !memmem(f_data, f_len, SHM_ENV_VAR, strlen(SHM_ENV_VAR) + 1))
  {

    SAYF("\n" cLRD "[-] " cRST
         "Looks like the target binary is not instrumented! The fuzzer depends on\n"
         "    compile-time instrumentation to isolate interesting test cases while\n"
         "    mutating the input data. For more information, and for tips on how to\n"
         "    instrument binaries, please see %s/README.\n\n"

         "    When source code is not available, you may be able to leverage QEMU\n"
         "    mode support. Consult the README for tips on how to enable this.\n"

         "    (It is also possible to use afl-fuzz as a traditional, \"dumb\" fuzzer.\n"
         "    For that, you can use the -n option - but expect much worse results.)\n",
         doc_path);

    FATAL("No instrumentation detected");
  }

  if (qemu_mode &&
      memmem(f_data, f_len, SHM_ENV_VAR, strlen(SHM_ENV_VAR) + 1))
  {

    SAYF("\n" cLRD "[-] " cRST
         "This program appears to be instrumented with afl-gcc, but is being run in\n"
         "    QEMU mode (-Q). This is probably not what you want - this setup will be\n"
         "    slow and offer no practical benefits.\n");

    FATAL("Instrumentation found in -Q mode");
  }

  if (memmem(f_data, f_len, "libasan.so", 10) ||
      memmem(f_data, f_len, "__msan_init", 11))
    uses_asan = 1;

  /* Detect persistent & deferred init signatures in the binary. */

  if (memmem(f_data, f_len, PERSIST_SIG, strlen(PERSIST_SIG) + 1))
  {

    OKF(cPIN "Persistent mode binary detected.");
    setenv(PERSIST_ENV_VAR, "1", 1);
    persistent_mode = 1;
  }
  else if (getenv("AFL_PERSISTENT"))
  {

    WARNF("AFL_PERSISTENT is no longer supported and may misbehave!");
  }

  if (memmem(f_data, f_len, DEFER_SIG, strlen(DEFER_SIG) + 1))
  {

    OKF(cPIN "Deferred forkserver binary detected.");
    setenv(DEFER_ENV_VAR, "1", 1);
    deferred_mode = 1;
  }
  else if (getenv("AFL_DEFER_FORKSRV"))
  {

    WARNF("AFL_DEFER_FORKSRV is no longer supported and may misbehave!");
  }

  if (munmap(f_data, f_len))
    PFATAL("unmap() failed");
}

/* Trim and possibly create a banner for the run. */

static void fix_up_banner(u8 *name)
{

  if (!use_banner)
  {

    if (sync_id)
    {

      use_banner = sync_id;
    }
    else
    {

      u8 *trim = strrchr(name, '/');
      if (!trim)
        use_banner = name;
      else
        use_banner = trim + 1;
    }
  }

  if (strlen(use_banner) > 40)
  {

    u8 *tmp = ck_alloc(44);
    sprintf(tmp, "%.40s...", use_banner);
    use_banner = tmp;
  }
}

/* Check if we're on TTY. */

static void check_if_tty(void)
{

  struct winsize ws;

  if (getenv("AFL_NO_UI"))
  {
    OKF("Disabling the UI because AFL_NO_UI is set.");
    not_on_tty = 1;
    return;
  }

  if (ioctl(1, TIOCGWINSZ, &ws))
  {

    if (errno == ENOTTY)
    {
      OKF("Looks like we're not running on a tty, so I'll be a bit less verbose.");
      not_on_tty = 1;
    }

    return;
  }
}

/* Check terminal dimensions after resize. */

static void check_term_size(void)
{

  struct winsize ws;

  term_too_small = 0;

  if (ioctl(1, TIOCGWINSZ, &ws))
    return;

  if (ws.ws_row == 0 && ws.ws_col == 0)
    return;
  if (ws.ws_row < 25 || ws.ws_col < 80)
    term_too_small = 1;
}

/* Display usage hints. */

static void usage(u8 *argv0)
{

  SAYF("\n%s [ options ] -- /path/to/fuzzed_app [ ... ]\n\n"

       "Required parameters:\n\n"

       "  -i dir        - input directory with test cases\n"
       "  -o dir        - output directory for fuzzer findings\n\n"

       "Execution control settings:\n\n"

       "  -f file       - location read by the fuzzed program (stdin)\n"
       "  -t msec       - timeout for each run (auto-scaled, 50-%u ms)\n"
       "  -m megs       - memory limit for child process (%u MB)\n"
       "  -Q            - use binary-only instrumentation (QEMU mode)\n\n"

       "Fuzzing behavior settings:\n\n"

       "  -d            - quick & dirty mode (skips deterministic steps)\n"
       "  -n            - fuzz without instrumentation (dumb mode)\n"
       "  -x dir        - optional fuzzer dictionary (see README)\n\n"

       "Settings for network protocol fuzzing (AFLNet):\n\n"

       "  -N netinfo    - server information (e.g., tcp://127.0.0.1/8554)\n"
       "  -P protocol   - application protocol to be tested (e.g., RTSP, FTP, DTLS12, DNS, SMTP, SSH, TLS)\n"
       "  -D usec       - waiting time (in micro seconds) for the server to initialize\n"
       "  -W msec       - waiting time (in miliseconds) for receiving the first response to each input sent\n"
       "  -w usec       - waiting time (in micro seconds) for receiving follow-up responses\n"
       "  -e netnsname  - run server in a different network namespace\n"
       "  -K            - send SIGTERM to gracefully terminate the server (see README.md)\n"
       "  -E            - enable state aware mode (see README.md)\n"
       "  -R            - enable region-level mutation operators (see README.md)\n"
       "  -F            - enable false negative reduction mode (see README.md)\n"
       "  -c cleanup    - name or full path to the server cleanup script (see README.md)\n"
       "  -q algo       - state selection algorithm (See aflnet.h for all available options)\n"
       "  -s algo       - seed selection algorithm (See aflnet.h for all available options)\n\n"

       "Other stuff:\n\n"

       "  -T text       - text banner to show on the screen\n"
       "  -M / -S id    - distributed mode (see parallel_fuzzing.txt)\n"
       "  -C            - crash exploration mode (the peruvian rabbit thing)\n\n"

       "For additional tips, please consult %s/README.\n\n",

       argv0, EXEC_TIMEOUT, MEM_LIMIT, doc_path);

  exit(1);
}

/* Prepare output directories and fds. */

EXP_ST void setup_dirs_fds(void)
{

  u8 *tmp;
  s32 fd;

  ACTF("Setting up output directories...");

  if (sync_id && mkdir(sync_dir, 0700) && errno != EEXIST)
    PFATAL("Unable to create '%s'", sync_dir);

  if (mkdir(out_dir, 0700))
  {

    if (errno != EEXIST)
      PFATAL("Unable to create '%s'", out_dir);

    maybe_delete_out_dir();
  }
  else
  {

    if (in_place_resume)
      FATAL("Resume attempted but old output directory not found");

    out_dir_fd = open(out_dir, O_RDONLY);

#ifndef __sun

    if (out_dir_fd < 0 || flock(out_dir_fd, LOCK_EX | LOCK_NB))
      PFATAL("Unable to flock() output directory.");

#endif /* !__sun */
  }

  /* Queue directory for any starting & discovered paths. */

  tmp = alloc_printf("%s/queue", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Top-level directory for queue metadata used for session
     resume and related tasks. */

  tmp = alloc_printf("%s/queue/.state/", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Directory for flagging queue entries that went through
     deterministic fuzzing in the past. */

  tmp = alloc_printf("%s/queue/.state/deterministic_done/", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Directory with the auto-selected dictionary entries. */

  tmp = alloc_printf("%s/queue/.state/auto_extras/", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* The set of paths currently deemed redundant. */

  tmp = alloc_printf("%s/queue/.state/redundant_edges/", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* The set of paths showing variable behavior. */

  tmp = alloc_printf("%s/queue/.state/variable_behavior/", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Sync directory for keeping track of cooperating fuzzers. */

  if (sync_id)
  {

    tmp = alloc_printf("%s/.synced/", out_dir);

    if (mkdir(tmp, 0700) && (!in_place_resume || errno != EEXIST))
      PFATAL("Unable to create '%s'", tmp);

    ck_free(tmp);
  }

  /* All recorded crashes. */

  tmp = alloc_printf("%s/replayable-crashes", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* All recorded hangs. */

  tmp = alloc_printf("%s/replayable-hangs", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* All files keeping extracted regions -- for debugging purpose. */

  tmp = alloc_printf("%s/regions", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* All output from the LLM and resulting grammars -- for debugging purposes. */

  tmp = alloc_printf("%s/protocol-grammars", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* All output from the LLM's help for unblocking the state stall -- for debugging purposes.  */
  tmp = alloc_printf("%s/stall-interactions", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Differential testing reports (D4) — MQTT-only. */
  if (protocol_name && strcasecmp(protocol_name, "MQTT") == 0) {
    tmp = alloc_printf("%s/diffs", out_dir);
    if (mkdir(tmp, 0700))
      PFATAL("Unable to create '%s'", tmp);
    ck_free(tmp);
  }


  /* All recorded new paths exercising the implemented state machine. */

  tmp = alloc_printf("%s/replayable-new-ipsm-paths", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* All recorded responses over the implemented state machine. */
  tmp = alloc_printf("%s/responses-ipsm", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* All recorded paths in structure files. */

  tmp = alloc_printf("%s/replayable-queue", out_dir);
  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Generally useful file descriptors. */

  dev_null_fd = open("/dev/null", O_RDWR);
  if (dev_null_fd < 0)
    PFATAL("Unable to open /dev/null");

  dev_urandom_fd = open("/dev/urandom", O_RDONLY);
  if (dev_urandom_fd < 0)
    PFATAL("Unable to open /dev/urandom");

  /* Gnuplot output file. */

  tmp = alloc_printf("%s/plot_data", out_dir);
  fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0)
    PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  plot_file = fdopen(fd, "w");
  if (!plot_file)
    PFATAL("fdopen() failed");

  fprintf(plot_file, "# unix_time, cycles_done, cur_path, paths_total, "
                     "pending_total, pending_favs, map_size, unique_crashes, "
                     "unique_hangs, max_depth, execs_per_sec, n_nodes, n_edges, "
                     "chat_times, llm_calls, llm_prompt_tok, llm_compl_tok, "
                     "llm_dedup, hyp_fitness, hyp_success, hyp_failure, "
                     "mqtt_diff_avg, mqtt_diff_last, mqtt_diff_pos\n");
  /* ignore errors */
}

/* Setup the output file for fuzzed data, if not using -f. */

EXP_ST void setup_stdio_file(void)
{

  u8 *fn = alloc_printf("%s/.cur_input", out_dir);

  unlink(fn); /* Ignore errors */

  out_fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600);

  if (out_fd < 0)
    PFATAL("Unable to create '%s'", fn);

  ck_free(fn);
}

/* Make sure that core dumps don't go to a program. */

static void check_crash_handling(void)
{

#ifdef __APPLE__

  /* Yuck! There appears to be no simple C API to query for the state of
     loaded daemons on MacOS X, and I'm a bit hesitant to do something
     more sophisticated, such as disabling crash reporting via Mach ports,
     until I get a box to test the code. So, for now, we check for crash
     reporting the awful way. */

  if (system("launchctl list 2>/dev/null | grep -q '\\.ReportCrash$'"))
    return;

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, your system is configured to forward crash notifications to an\n"
       "    external crash reporting utility. This will cause issues due to the\n"
       "    extended delay between the fuzzed binary malfunctioning and this fact\n"
       "    being relayed to the fuzzer via the standard waitpid() API.\n\n"
       "    To avoid having crashes misinterpreted as timeouts, please run the\n"
       "    following commands:\n\n"

       "    SL=/System/Library; PL=com.apple.ReportCrash\n"
       "    launchctl unload -w ${SL}/LaunchAgents/${PL}.plist\n"
       "    sudo launchctl unload -w ${SL}/LaunchDaemons/${PL}.Root.plist\n");

  if (!getenv("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"))
    FATAL("Crash reporter detected");

#else

  /* This is Linux specific, but I don't think there's anything equivalent on
   *BSD, so we can just let it slide for now. */

  s32 fd = open("/proc/sys/kernel/core_pattern", O_RDONLY);
  u8 fchar;

  if (fd < 0)
    return;

  ACTF("Checking core_pattern...");

  if (read(fd, &fchar, 1) == 1 && fchar == '|')
  {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, your system is configured to send core dump notifications to an\n"
         "    external utility. This will cause issues: there will be an extended delay\n"
         "    between stumbling upon a crash and having this information relayed to the\n"
         "    fuzzer via the standard waitpid() API.\n\n"

         "    To avoid having crashes misinterpreted as timeouts, please log in as root\n"
         "    and temporarily modify /proc/sys/kernel/core_pattern, like so:\n\n"

         "    echo core >/proc/sys/kernel/core_pattern\n");

    if (!getenv("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"))
      FATAL("Pipe at the beginning of 'core_pattern'");
  }

  close(fd);

#endif /* ^__APPLE__ */
}

/* Check CPU governor. */

static void check_cpu_governor(void)
{

  FILE *f;
  u8 tmp[128];
  u64 min = 0, max = 0;

  if (getenv("AFL_SKIP_CPUFREQ"))
    return;

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "r");
  if (!f)
    return;

  ACTF("Checking CPU scaling governor...");

  if (!fgets(tmp, 128, f))
    PFATAL("fgets() failed");

  fclose(f);

  if (!strncmp(tmp, "perf", 4))
    return;

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq", "r");

  if (f)
  {
    if (fscanf(f, "%llu", &min) != 1)
      min = 0;
    fclose(f);
  }

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq", "r");

  if (f)
  {
    if (fscanf(f, "%llu", &max) != 1)
      max = 0;
    fclose(f);
  }

  if (min == max)
    return;

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, your system uses on-demand CPU frequency scaling, adjusted\n"
       "    between %llu and %llu MHz. Unfortunately, the scaling algorithm in the\n"
       "    kernel is imperfect and can miss the short-lived processes spawned by\n"
       "    afl-fuzz. To keep things moving, run these commands as root:\n\n"

       "    cd /sys/devices/system/cpu\n"
       "    echo performance | tee cpu*/cpufreq/scaling_governor\n\n"

       "    You can later go back to the original state by replacing 'performance' with\n"
       "    'ondemand'. If you don't want to change the settings, set AFL_SKIP_CPUFREQ\n"
       "    to make afl-fuzz skip this check - but expect some performance drop.\n",
       min / 1024, max / 1024);

  FATAL("Suboptimal CPU scaling governor");
}

/* Count the number of logical CPU cores. */

static void get_core_count(void)
{

  u32 cur_runnable = 0;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)

  size_t s = sizeof(cpu_core_count);

  /* On *BSD systems, we can just use a sysctl to get the number of CPUs. */

#ifdef __APPLE__

  if (sysctlbyname("hw.logicalcpu", &cpu_core_count, &s, NULL, 0) < 0)
    return;

#else

  int s_name[2] = {CTL_HW, HW_NCPU};

  if (sysctl(s_name, 2, &cpu_core_count, &s, NULL, 0) < 0)
    return;

#endif /* ^__APPLE__ */

#else

#ifdef HAVE_AFFINITY

  cpu_core_count = sysconf(_SC_NPROCESSORS_ONLN);

#else

  FILE *f = fopen("/proc/stat", "r");
  u8 tmp[1024];

  if (!f)
    return;

  while (fgets(tmp, sizeof(tmp), f))
    if (!strncmp(tmp, "cpu", 3) && isdigit(tmp[3]))
      cpu_core_count++;

  fclose(f);

#endif /* ^HAVE_AFFINITY */

#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  if (cpu_core_count > 0)
  {

    cur_runnable = (u32)get_runnable_processes();

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)

    /* Add ourselves, since the 1-minute average doesn't include that yet. */

    cur_runnable++;

#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

    OKF("You have %u CPU core%s and %u runnable tasks (utilization: %0.0f%%).",
        cpu_core_count, cpu_core_count > 1 ? "s" : "",
        cur_runnable, cur_runnable * 100.0 / cpu_core_count);

    if (cpu_core_count > 1)
    {

      if (cur_runnable > cpu_core_count * 1.5)
      {

        WARNF("System under apparent load, performance may be spotty.");
      }
      else if (cur_runnable + 1 <= cpu_core_count)
      {

        OKF("Try parallel jobs - see %s/parallel_fuzzing.txt.", doc_path);
      }
    }
  }
  else
  {

    cpu_core_count = 0;
    WARNF("Unable to figure out the number of CPU cores.");
  }
}

/* Validate and fix up out_dir and sync_dir when using -S. */

static void fix_up_sync(void)
{

  u8 *x = sync_id;

  if (dumb_mode)
    FATAL("-S / -M and -n are mutually exclusive");

  if (skip_deterministic)
  {

    if (force_deterministic)
      FATAL("use -S instead of -M -d");
    else
      FATAL("-S already implies -d");
  }

  while (*x)
  {

    if (!isalnum(*x) && *x != '_' && *x != '-')
      FATAL("Non-alphanumeric fuzzer ID specified via -S or -M");

    x++;
  }

  if (strlen(sync_id) > 32)
    FATAL("Fuzzer ID too long");

  x = alloc_printf("%s/%s", out_dir, sync_id);

  sync_dir = out_dir;
  out_dir = x;

  if (!force_deterministic)
  {
    skip_deterministic = 1;
    use_splicing = 1;
  }
}

/* Handle screen resize (SIGWINCH). */

static void handle_resize(int sig)
{
  clear_screen = 1;
}

/* Check ASAN options. */

static void check_asan_opts(void)
{
  u8 *x = getenv("ASAN_OPTIONS");

  if (x)
  {

    if (!strstr(x, "abort_on_error=1"))
      FATAL("Custom ASAN_OPTIONS set without abort_on_error=1 - please fix!");

    if (!strstr(x, "symbolize=0"))
      FATAL("Custom ASAN_OPTIONS set without symbolize=0 - please fix!");
  }

  x = getenv("MSAN_OPTIONS");

  if (x)
  {

    if (!strstr(x, "exit_code=" STRINGIFY(MSAN_ERROR)))
      FATAL("Custom MSAN_OPTIONS set without exit_code=" STRINGIFY(MSAN_ERROR) " - please fix!");

    if (!strstr(x, "symbolize=0"))
      FATAL("Custom MSAN_OPTIONS set without symbolize=0 - please fix!");
  }
}

/* Detect @@ in args. */

EXP_ST void detect_file_args(char **argv)
{

  u32 i = 0;
  u8 *cwd = getcwd(NULL, 0);

  if (!cwd)
    PFATAL("getcwd() failed");

  while (argv[i])
  {

    u8 *aa_loc = strstr(argv[i], "@@");

    if (aa_loc)
    {

      u8 *aa_subst, *n_arg;

      /* If we don't have a file name chosen yet, use a safe default. */

      if (!out_file)
        out_file = alloc_printf("%s/.cur_input", out_dir);

      /* Be sure that we're always using fully-qualified paths. */

      if (out_file[0] == '/')
        aa_subst = out_file;
      else
        aa_subst = alloc_printf("%s/%s", cwd, out_file);

      /* Construct a replacement argv value. */

      *aa_loc = 0;
      n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);
      argv[i] = n_arg;
      *aa_loc = '@';

      if (out_file[0] != '/')
        ck_free(aa_subst);
    }

    i++;
  }

  free(cwd); /* not tracked */
}

/* Set up signal handlers. More complicated that needs to be, because libc on
   Solaris doesn't resume interrupted reads(), sets SA_RESETHAND when you call
   siginterrupt(), and does other unnecessary things. */

EXP_ST void setup_signal_handlers(void)
{

  struct sigaction sa;

  sa.sa_handler = NULL;
  sa.sa_flags = SA_RESTART;
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);

  /* Various ways of saying "stop". */

  sa.sa_handler = handle_stop_sig;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  /* Exec timeout notifications. */

  sa.sa_handler = handle_timeout;
  sigaction(SIGALRM, &sa, NULL);

  /* Window resize */

  sa.sa_handler = handle_resize;
  sigaction(SIGWINCH, &sa, NULL);

  /* SIGUSR1: skip entry */

  sa.sa_handler = handle_skipreq;
  sigaction(SIGUSR1, &sa, NULL);

  /* Things we don't care about. */

  sa.sa_handler = SIG_IGN;
  sigaction(SIGTSTP, &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);
}

/* Rewrite argv for QEMU. */

static char **get_qemu_argv(u8 *own_loc, char **argv, int argc)
{

  char **new_argv = ck_alloc(sizeof(char *) * (argc + 4));
  u8 *tmp, *cp, *rsl, *own_copy;

  /* Workaround for a QEMU stability glitch. */

  setenv("QEMU_LOG", "nochain", 1);

  memcpy(new_argv + 3, argv + 1, sizeof(char *) * argc);

  new_argv[2] = target_path;
  new_argv[1] = "--";

  /* Now we need to actually find the QEMU binary to put in argv[0]. */

  tmp = getenv("AFL_PATH");

  if (tmp)
  {

    cp = alloc_printf("%s/afl-qemu-trace", tmp);

    if (access(cp, X_OK))
      FATAL("Unable to find '%s'", tmp);

    target_path = new_argv[0] = cp;
    return new_argv;
  }

  own_copy = ck_strdup(own_loc);
  rsl = strrchr(own_copy, '/');

  if (rsl)
  {

    *rsl = 0;

    cp = alloc_printf("%s/afl-qemu-trace", own_copy);
    ck_free(own_copy);

    if (!access(cp, X_OK))
    {

      target_path = new_argv[0] = cp;
      return new_argv;
    }
  }
  else
    ck_free(own_copy);

  if (!access(BIN_PATH "/afl-qemu-trace", X_OK))
  {

    target_path = new_argv[0] = ck_strdup(BIN_PATH "/afl-qemu-trace");
    return new_argv;
  }

  SAYF("\n" cLRD "[-] " cRST
       "Oops, unable to find the 'afl-qemu-trace' binary. The binary must be built\n"
       "    separately by following the instructions in qemu_mode/README.qemu. If you\n"
       "    already have the binary installed, you may need to specify AFL_PATH in the\n"
       "    environment.\n\n"

       "    Of course, even without QEMU, afl-fuzz can still work with binaries that are\n"
       "    instrumented at compile time with afl-gcc. It is also possible to use it as a\n"
       "    traditional \"dumb\" fuzzer by specifying '-n' in the command line.\n");

  FATAL("Failed to locate 'afl-qemu-trace'.");
}

/* Make a copy of the current command line. */

static void save_cmdline(u32 argc, char **argv)
{

  u32 len = 1, i;
  u8 *buf;

  for (i = 0; i < argc; i++)
    len += strlen(argv[i]) + 1;

  buf = orig_cmdline = ck_alloc(len);

  for (i = 0; i < argc; i++)
  {

    u32 l = strlen(argv[i]);

    memcpy(buf, argv[i], l);
    buf += l;

    if (i != argc - 1)
      *(buf++) = ' ';
  }

  *buf = 0;
}

/* Check that afl-fuzz (file/process) has some effective and permitted capability */

static int check_ep_capability(cap_value_t cap, const char *filename)
{
  cap_t file_cap, proc_cap;
  cap_flag_value_t cap_flag_value;
  int no_capability = 1;
  int pid = getpid();

  file_cap = cap_get_file(filename);
  proc_cap = cap_get_proc();

  if (!file_cap && !proc_cap)
    return no_capability;

  if (file_cap)
  {
    if (cap_get_flag(file_cap, cap, CAP_EFFECTIVE, &cap_flag_value))
      PFATAL("Could not get CAP_EFFECTIVE flag value from file \"%s\"", filename);

    if (cap_flag_value != CAP_SET)
      return no_capability;

    if (cap_get_flag(file_cap, cap, CAP_PERMITTED, &cap_flag_value))
      PFATAL("Could not get CAP_PERMITTED flag value from file \"%s\"", filename);

    if (cap_flag_value != CAP_SET)
      return no_capability;
  }

  if (proc_cap)
  {
    if (cap_get_flag(proc_cap, cap, CAP_EFFECTIVE, &cap_flag_value))
      PFATAL("Could not get CAP_EFFECTIVE flag value from process id %d", pid);

    if (cap_flag_value != CAP_SET)
      return no_capability;

    if (cap_get_flag(proc_cap, cap, CAP_PERMITTED, &cap_flag_value))
      PFATAL("Could not get CAP_PERMITTED flag value from process id %d", pid);

    if (cap_flag_value != CAP_SET)
      return no_capability;
  }

  return 0;
}

#ifndef AFL_LIB

/* Main entry point */

int main(int argc, char **argv)
{

  s32 opt;
  u64 prev_queued = 0;
  u32 sync_interval_cnt = 0, seek_to;
  u8 *extras_dir = 0;
  u8 mem_limit_given = 0;
  u8 exit_1 = !!getenv("AFL_BENCH_JUST_ONE");
  // char** use_argv;

  struct timeval tv;
  struct timezone tz;

  SAYF(cCYA "afl-fuzz " cBRI VERSION cRST " by <lcamtuf@google.com>\n");

  doc_path = access(DOC_PATH, F_OK) ? "docs" : DOC_PATH;

  gettimeofday(&tv, &tz);
  srandom(tv.tv_sec ^ tv.tv_usec ^ getpid());

  while ((opt = getopt(argc, argv, "+i:o:f:m:t:T:dnCB:S:M:x:QN:D:W:w:e:P:KEq:s:RFc:l:")) > 0)

    switch (opt)
    {

    case 'i': /* input dir */

      if (in_dir)
        FATAL("Multiple -i options not supported");
      in_dir = optarg;

      if (!strcmp(in_dir, "-"))
        in_place_resume = 1;

      break;

    case 'o': /* output dir */

      if (out_dir)
        FATAL("Multiple -o options not supported");
      out_dir = optarg;
      break;

    case 'M':
    { /* master sync ID */

      u8 *c;

      if (sync_id)
        FATAL("Multiple -S or -M options not supported");
      sync_id = ck_strdup(optarg);

      if ((c = strchr(sync_id, ':')))
      {

        *c = 0;

        if (sscanf(c + 1, "%u/%u", &master_id, &master_max) != 2 ||
            !master_id || !master_max || master_id > master_max ||
            master_max > 1000000)
          FATAL("Bogus master ID passed to -M");
      }

      force_deterministic = 1;
    }

    break;

    case 'S':

      if (sync_id)
        FATAL("Multiple -S or -M options not supported");
      sync_id = ck_strdup(optarg);
      break;

    case 'f': /* target file */

      if (out_file)
        FATAL("Multiple -f options not supported");
      out_file = optarg;
      break;

    case 'x': /* dictionary */

      if (extras_dir)
        FATAL("Multiple -x options not supported");
      extras_dir = optarg;
      break;

    case 't':
    { /* timeout */

      u8 suffix = 0;

      if (timeout_given)
        FATAL("Multiple -t options not supported");

      if (sscanf(optarg, "%u%c", &exec_tmout, &suffix) < 1 ||
          optarg[0] == '-')
        FATAL("Bad syntax used for -t");

      if (exec_tmout < 5)
        FATAL("Dangerously low value of -t");

      if (suffix == '+')
        timeout_given = 2;
      else
        timeout_given = 1;

      break;
    }

    case 'm':
    { /* mem limit */

      u8 suffix = 'M';

      if (mem_limit_given)
        FATAL("Multiple -m options not supported");
      mem_limit_given = 1;

      if (!strcmp(optarg, "none"))
      {

        mem_limit = 0;
        break;
      }

      if (sscanf(optarg, "%llu%c", &mem_limit, &suffix) < 1 ||
          optarg[0] == '-')
        FATAL("Bad syntax used for -m");

      switch (suffix)
      {

      case 'T':
        mem_limit *= 1024 * 1024;
        break;
      case 'G':
        mem_limit *= 1024;
        break;
      case 'k':
        mem_limit /= 1024;
        break;
      case 'M':
        break;

      default:
        FATAL("Unsupported suffix or bad syntax for -m");
      }

      if (mem_limit < 5)
        FATAL("Dangerously low value of -m");

      if (sizeof(rlim_t) == 4 && mem_limit > 2000)
        FATAL("Value of -m out of range on 32-bit systems");
    }

    break;

    case 'd': /* skip deterministic */

      if (skip_deterministic)
        FATAL("Multiple -d options not supported");
      skip_deterministic = 1;
      use_splicing = 1;
      break;

    case 'B': /* load bitmap */

      /* This is a secret undocumented option! It is useful if you find
         an interesting test case during a normal fuzzing process, and want
         to mutate it without rediscovering any of the test cases already
         found during an earlier run.

         To use this mode, you need to point -B to the fuzz_bitmap produced
         by an earlier run for the exact same binary... and that's it.

         I only used this once or twice to get variants of a particular
         file, so I'm not making this an official setting. */

      if (in_bitmap)
        FATAL("Multiple -B options not supported");

      in_bitmap = optarg;
      read_bitmap(in_bitmap);
      break;

    case 'C': /* crash mode */

      if (crash_mode)
        FATAL("Multiple -C options not supported");
      crash_mode = FAULT_CRASH;
      break;

    case 'n': /* dumb mode */

      if (dumb_mode)
        FATAL("Multiple -n options not supported");
      if (getenv("AFL_DUMB_FORKSRV"))
        dumb_mode = 2;
      else
        dumb_mode = 1;

      break;

    case 'T': /* banner */

      if (use_banner)
        FATAL("Multiple -T options not supported");
      use_banner = optarg;
      break;

    case 'Q': /* QEMU mode */

      if (qemu_mode)
        FATAL("Multiple -Q options not supported");
      qemu_mode = 1;

      if (!mem_limit_given)
        mem_limit = MEM_LIMIT_QEMU;

      break;

    case 'N': /* Network configuration */
      if (use_net)
        FATAL("Multiple -N options not supported");
      if (parse_net_config(optarg, &net_protocol, &net_ip, &net_port))
        FATAL("Bad syntax used for -N. Check the network setting. [tcp/udp]://127.0.0.1/port");

      use_net = 1;
      break;

    case 'D': /* waiting time for the server initialization */
      if (server_wait)
        FATAL("Multiple -D options not supported");

      if (sscanf(optarg, "%u", &server_wait_usecs) < 1 || optarg[0] == '-')
        FATAL("Bad syntax used for -D");
      server_wait = 1;
      break;

    case 'W': /* polling timeout determining maximum amount of time waited before concluding that no responses are forthcoming*/
      if (socket_timeout)
        FATAL("Multiple -W options not supported");

      if (sscanf(optarg, "%u", &poll_wait_msecs) < 1 || optarg[0] == '-')
        FATAL("Bad syntax used for -W");
      poll_wait = 1;
      break;

    case 'w': /* receive/send socket timeout determining time waited for each response */
      if (socket_timeout)
        FATAL("Multiple -w options not supported");

      if (sscanf(optarg, "%u", &socket_timeout_usecs) < 1 || optarg[0] == '-')
        FATAL("Bad syntax used for -w");
      socket_timeout = 1;
      break;

    case 'e': /* network namespace name */
      if (netns_name)
        FATAL("Multiple -e options not supported");

      netns_name = optarg;
      break;

    case 'P': /* protocol to be tested */
      if (protocol_selected)
        FATAL("Multiple -P options not supported");

      if (!strcmp(optarg, "RTSP"))
      {
        extract_requests = &extract_requests_rtsp;
        extract_response_codes = &extract_response_codes_rtsp;
      }
      else if (!strcmp(optarg, "FTP"))
      {
        extract_requests = &extract_requests_ftp;
        extract_response_codes = &extract_response_codes_ftp;
      }
      else if (!strcmp(optarg, "MQTT"))
      {
        extract_requests = &extract_requests_mqtt;
        extract_response_codes = &extract_response_codes_mqtt;
      }
      else if (!strcmp(optarg, "DTLS12"))
      {
        extract_requests = &extract_requests_dtls12;
        extract_response_codes = &extract_response_codes_dtls12;
      }
      else if (!strcmp(optarg, "DNS"))
      {
        extract_requests = &extract_requests_dns;
        extract_response_codes = &extract_response_codes_dns;
      }
      else if (!strcmp(optarg, "DICOM"))
      {
        extract_requests = &extract_requests_dicom;
        extract_response_codes = &extract_response_codes_dicom;
      }
      else if (!strcmp(optarg, "SMTP"))
      {
        extract_requests = &extract_requests_smtp;
        extract_response_codes = &extract_response_codes_smtp;
      }
      else if (!strcmp(optarg, "SSH"))
      {
        extract_requests = &extract_requests_ssh;
        extract_response_codes = &extract_response_codes_ssh;
      }
      else if (!strcmp(optarg, "TLS"))
      {
        extract_requests = &extract_requests_tls;
        extract_response_codes = &extract_response_codes_tls;
      }
      else if (!strcmp(optarg, "SIP"))
      {
        extract_requests = &extract_requests_sip;
        extract_response_codes = &extract_response_codes_sip;
      }
      else if (!strcmp(optarg, "HTTP"))
      {
        extract_requests = &extract_requests_http;
        extract_response_codes = &extract_response_codes_http;
      }
      else if (!strcmp(optarg, "IPP"))
      {
        extract_requests = &extract_requests_ipp;
        extract_response_codes = &extract_response_codes_ipp;
      }
      else
      {
        FATAL("%s protocol is not supported yet!", optarg);
      }
      protocol_name = ck_strdup(optarg);
      protocol_selected = 1;

      break;

    case 'K':
      if (terminate_child)
        FATAL("Multiple -K options not supported");
      terminate_child = 1;
      break;

    case 'E':
      if (state_aware_mode)
        FATAL("Multiple -E options not supported");
      state_aware_mode = 1;
      break;

    case 'q': /* state selection option */
      if (sscanf(optarg, "%hhu", &state_selection_algo) < 1 || optarg[0] == '-')
        FATAL("Bad syntax used for -q");
      break;

    case 's': /* seed selection option */
      if (sscanf(optarg, "%hhu", &seed_selection_algo) < 1 || optarg[0] == '-')
        FATAL("Bad syntax used for -s");
      break;

    case 'R':
      if (region_level_mutation)
        FATAL("Multiple -R options not supported");
      region_level_mutation = 1;
      break;

    case 'F':
      if (false_negative_reduction)
        FATAL("Multiple -F options not supported");
      false_negative_reduction = 1;
      break;

    case 'c': /* cleanup script */

      if (cleanup_script)
        FATAL("Multiple -c options not supported");
      cleanup_script = optarg;
      break;

    case 'l': /* local port to connect from */
      // This option is only used for targets that send responses to a specific port number
      // The Kamailio SIP server is an example

      if (local_port)
        FATAL("Multiple -l options not supported");
      local_port = atoi(optarg);
      if (local_port < 1024 || local_port > 65535)
        FATAL("Invalid source port number");
      break;

    default:

      usage(argv[0]);
    }

  if (optind == argc || !in_dir || !out_dir)
    usage(argv[0]);

  // AFLNet - Check for required arguments
  if (!use_net)
    FATAL("Please specify network information of the server under test (e.g., tcp://127.0.0.1/8554)");

  if (!protocol_selected)
    FATAL("Please specify the protocol to be tested using the -P option");

  if (netns_name)
  {
    if (check_ep_capability(CAP_SYS_ADMIN, argv[0]) != 0)
      FATAL("Could not run the server under test in a \"%s\" network namespace "
            "without CAP_SYS_ADMIN capability.\n You can set it by invoking "
            "afl-fuzz with sudo or by \"$ setcap cap_sys_admin+ep /path/to/afl-fuzz\".",
            netns_name);
  }

  setup_signal_handlers();
  check_asan_opts();

  if (sync_id)
    fix_up_sync();

  if (!strcmp(in_dir, out_dir))
    FATAL("Input and output directories can't be the same");

  if (dumb_mode)
  {

    if (crash_mode)
      FATAL("-C and -n are mutually exclusive");
    if (qemu_mode)
      FATAL("-Q and -n are mutually exclusive");
  }

  if (getenv("AFL_NO_FORKSRV"))
    no_forkserver = 1;
  if (getenv("AFL_NO_CPU_RED"))
    no_cpu_meter_red = 1;
  if (getenv("AFL_NO_ARITH"))
    no_arith = 1;
  if (getenv("AFL_SHUFFLE_QUEUE"))
    shuffle_queue = 1;
  if (getenv("AFL_FAST_CAL"))
    fast_cal = 1;

  if (getenv("AFL_HANG_TMOUT"))
  {
    hang_tmout = atoi(getenv("AFL_HANG_TMOUT"));
    if (!hang_tmout)
      FATAL("Invalid value of AFL_HANG_TMOUT");
  }

  if (dumb_mode == 2 && no_forkserver)
    FATAL("AFL_DUMB_FORKSRV and AFL_NO_FORKSRV are mutually exclusive");

  if (getenv("AFL_PRELOAD"))
  {
    setenv("LD_PRELOAD", getenv("AFL_PRELOAD"), 1);
    setenv("DYLD_INSERT_LIBRARIES", getenv("AFL_PRELOAD"), 1);
  }

  if (getenv("AFL_LD_PRELOAD"))
    FATAL("Use AFL_PRELOAD instead of AFL_LD_PRELOAD");

  save_cmdline(argc, argv);

  /* ── MQTT Persistent Server Mode ────────────────────────────────────
   * DISABLED by default — experiments showed +116% exec_speed but
   * stability crashed to 9.9% (broker state accumulation), yielding
   * zero net coverage gain.  Opt-in via MQTT_PERSIST=1 for research.
   * Text protocols are completely unaffected. */
  if (protocol_name && strcasecmp(protocol_name, "MQTT") == 0) {
    if (getenv("MQTT_PERSIST") && atoi(getenv("MQTT_PERSIST")) == 1) {
      mqtt_persistent_mode = 1;
      if (getenv("MQTT_PERSIST_LIMIT"))
        mqtt_persistent_limit = atoi(getenv("MQTT_PERSIST_LIMIT"));
      if (mqtt_persistent_limit < 2) mqtt_persistent_limit = 2;
      if (mqtt_persistent_limit > 500) mqtt_persistent_limit = 500;
      OKF("MQTT persistent server mode ENABLED (re-fork every %u execs)",
          mqtt_persistent_limit);
    } else {
      OKF("MQTT persistent mode DISABLED (set MQTT_PERSIST=1 to enable)");
    }
    /* MQTT fast I/O: skip usleep(10) in net_send/net_recv */
    mqtt_fast_io = 1;
  }

  fix_up_banner(argv[optind]);

  check_if_tty();

  get_core_count();

#ifdef HAVE_AFFINITY
  bind_to_free_cpu();
#endif /* HAVE_AFFINITY */

  check_crash_handling();
  check_cpu_governor();

  setup_post();
  setup_shm();
  init_count_class16();

  setup_ipsm();

  setup_dirs_fds();

  if (protocol_selected)
  {
    protocol_patterns = kl_init(rang);
    message_types_set = kh_init(strSet);

    /* ── A12: MQTT fast-net auto-tuning ──────────────────────────────
     * MQTT messages are tiny (2-200 bytes) and mosquitto's fork-server
     * child starts in <1 ms.  Override conservative defaults unless the
     * user explicitly set them via -w / -p / -t flags.
     * These values are safe for all MQTT targets (Mosquitto, EMQ X,
     * VerneMQ) tested so far.  Non-MQTT protocols keep the originals. */
    if (protocol_name && strcasecmp(protocol_name, "MQTT") == 0) {
      /* A12-fix: Restored minimal poll_wait (was 0 from A12, caused H5).
       * poll_wait=0 made net_recv miss ALL late-arriving MQTT responses
       * (forwarded PUBLISHes arrive 1-5 ms after the triggering PUBLISH).
       * server_wait increased to 3 ms to give the broker time to process
       * async QoS handshakes and retained-message delivery. */
      if (!server_wait)   server_wait_usecs    = 3000;   /* 10 ms → 3 ms */
      if (!poll_wait)     poll_wait_msecs      = 1;      /*  1 ms → 1 ms (minimum) */
      if (!socket_timeout) socket_timeout_usecs = 500;   /*  1 ms → 0.5 ms */
      OKF("MQTT fast-net: server_wait=%u µs, poll_wait=%u ms, "
          "socket_timeout=%u µs",
          server_wait_usecs, poll_wait_msecs, socket_timeout_usecs);
    }

    setup_llm_grammars();
    enrich_testcases();
  }
  read_testcases();
  load_auto();

  pivot_inputs();

  if (extras_dir)
    load_extras(extras_dir);

  if (!timeout_given)
    find_timeout();

  detect_file_args(argv + optind + 1);

  if (!out_file)
    setup_stdio_file();

  check_binary(argv[optind]);

  start_time = get_cur_time();

  if (qemu_mode)
    use_argv = get_qemu_argv(argv[0], argv + optind, argc - optind);
  else
    use_argv = argv + optind;

  fprintf(stderr, "[DEBUG] ========== BEFORE perform_dry_run ==========\n");
  fflush(stderr);

  /* Fix-14b: corpus_read_or_sync=1 during dry_run.
   *
   * Originally needed so Fix-14a's run_target() returned FAULT_NONE
   * for child_force_killed during dry_run.  Fix-14c now returns
   * FAULT_NONE unconditionally for child_force_killed, so the
   * run_target motivation is obsolete.
   *
   * However, corpus_read_or_sync is still read by add_to_queue()
   * (L2268/2287) for max_seed_region_count limiting during initial
   * corpus loading — keep the wrapper for that purpose. */
  corpus_read_or_sync = 1;

  perform_dry_run(use_argv);

  corpus_read_or_sync = 0;

  fprintf(stderr, "[DEBUG] ========== AFTER perform_dry_run ==========\n");
  fflush(stderr);

  /* ChatAFL-Opt: Grammar hypothesis system — DEFERRED initialization.
   *
   * Fix-10b: Do NOT initialize hypothesis system eagerly at startup.
   * R9 data showed that eager init costs:
   *   - 380s startup delay (RFC fetch + LLM hypothesis generation)
   *   - +30MB RSS overhead from hypothesis_ctx allocation
   *   - hypothesis_avg_fitness stuck at 0.500 (never validated)
   *
   * Instead, just record that hypothesis mode is requested.  The actual
   * init_grammar_hypothesis_system() call is deferred to the first time
   * the plateau handler fires, when the system actually needs it. */
  fprintf(stderr, "[DEBUG] Checking CHATAFL_HYPOTHESIS env var...\n");
  fflush(stderr);
  char *hyp_env = getenv("CHATAFL_HYPOTHESIS");
  if (hyp_env)
  {
    fprintf(stderr, "[DEBUG] CHATAFL_HYPOTHESIS=%s, hypothesis mode DEFERRED (lazy init on first plateau)\n", hyp_env);
    fflush(stderr);
    hypothesis_mode = 1;
    OKF("Grammar Hypothesis Mode enabled (deferred init until first plateau)");
    /* init_grammar_hypothesis_system() will be called on first plateau trigger */
  }
  else
  {
    fprintf(stderr, "[DEBUG] CHATAFL_HYPOTHESIS not set, hypothesis mode disabled\n");
    fflush(stderr);
  }

  /* ============================================
   * Ablation Control: Read env vars
   * ============================================ */
  if (getenv("CHATAFL_NO_REFINEMENT")) {
    ablation_no_refinement = 1;
    OKF("ABLATION: Tier-2 hypothesis refinement DISABLED");
    /* Fix-Ablation-2: Warn if CHATAFL_HYPOTHESIS is not set.
     * Without hypothesis_mode=1, periodic_hypothesis_refinement() returns
     * immediately at its entry guard — NO_REFINEMENT has zero effect and
     * Full vs w/o-Refinement runs are behaviorally identical, making the
     * ablation data meaningless. */
    if (!getenv("CHATAFL_HYPOTHESIS")) {
      WARNF("ABLATION: CHATAFL_NO_REFINEMENT set but CHATAFL_HYPOTHESIS not set "
            "— ablation has NO EFFECT (hypothesis_mode=0). "
            "Set CHATAFL_HYPOTHESIS=1 to make this ablation valid.");
      fprintf(stderr,
              "[ABLATION WARNING] NO_REFINEMENT is a no-op without CHATAFL_HYPOTHESIS=1.\n");
      fflush(stderr);
    }
  }
  if (getenv("CHATAFL_NO_FRONTIER")) {
    ablation_no_frontier = 1;
    OKF("ABLATION: Frontier bonus + error penalty DISABLED");
  }
  if (getenv("CHATAFL_NO_ADAPTIVE")) {
    ablation_no_adaptive = 1;
    /* Fix-Ablation-1: Support CHATAFL_ABLATION_THRESHOLD to set a custom
     * fixed threshold.  Without this, NO_ADAPTIVE always fixes at 100
     * (Opt's UNINTERESTING_THRESHOLD), which is 5× more frequent than
     * ChatAFL baseline's 512.  To align with baseline trigger frequency,
     * use: export CHATAFL_NO_ADAPTIVE=1 CHATAFL_ABLATION_THRESHOLD=512 */
    char *fixed_thresh_env = getenv("CHATAFL_ABLATION_THRESHOLD");
    if (fixed_thresh_env) {
      u32 custom_thresh = (u32)atoi(fixed_thresh_env);
      if (custom_thresh > 0) {
        /* Will be applied after adaptive_plateau_threshold is initialized below */
        setenv("_CHATAFL_RESOLVED_THRESHOLD", fixed_thresh_env, 1);
        OKF("ABLATION: Adaptive plateau threshold DISABLED (fixed=%u from CHATAFL_ABLATION_THRESHOLD)",
            custom_thresh);
      } else {
        OKF("ABLATION: Adaptive plateau threshold DISABLED (fixed=%u, default)",
            UNINTERESTING_THRESHOLD);
      }
    } else {
      OKF("ABLATION: Adaptive plateau threshold DISABLED (fixed=%u, default — "
          "note: ChatAFL baseline uses 512; set CHATAFL_ABLATION_THRESHOLD=512 to align)",
          UNINTERESTING_THRESHOLD);
    }
  }
  if (getenv("CHATAFL_NO_STATE_PROMPT")) {
    ablation_no_state_prompt = 1;
    OKF("ABLATION: State-aware rich prompt + actions[] DISABLED (simple prompt mode)");
  }

  /* ============================================
   * Ablation Configuration Summary Banner
   * Plain fprintf so it survives ANSI/UI clutter
   * and is always visible in `docker logs`.
   * ============================================ */
  {
    int any_ablation = ablation_no_refinement || ablation_no_frontier
                     || ablation_no_adaptive  || ablation_no_state_prompt;
    fprintf(stderr,
      "\n"
      "========== ABLATION CONFIG ==========\n"
      "  NO_REFINEMENT   : %s\n"
      "  NO_FRONTIER     : %s\n"
      "  NO_ADAPTIVE     : %s\n"
      "  NO_STATE_PROMPT : %s\n"
      "  MODE            : %s\n"
      "  HYPOTHESIS      : %s\n"
      "  CHATAFL_OPT     : %s\n"
      "=====================================\n\n",
      ablation_no_refinement   ? "ON (disabled)" : "off",
      ablation_no_frontier     ? "ON (disabled)" : "off",
      ablation_no_adaptive     ? "ON (disabled)" : "off",
      ablation_no_state_prompt ? "ON (disabled)" : "off",
      any_ablation ? "ABLATION RUN" : "FULL (no ablation)",
      getenv("CHATAFL_HYPOTHESIS") ? "enabled" : "disabled",
      getenv("AFL_ENABLE_CHATAFL_OPT") ? "enabled" : "disabled");
    /* Warn in banner if NO_REFINEMENT is active but HYPOTHESIS is not set */
    if (ablation_no_refinement && !getenv("CHATAFL_HYPOTHESIS")) {
      fprintf(stderr,
        "  *** ABLATION WARNING: NO_REFINEMENT is a NO-OP (hypothesis_mode=0) ***\n"
        "  *** Set CHATAFL_HYPOTHESIS=1 for this ablation to be valid.         ***\n");
    }
    if (ablation_no_adaptive) {
      fprintf(stderr,
        "  NO_ADAPTIVE fixed threshold : %u%s\n",
        adaptive_plateau_threshold,
        adaptive_plateau_threshold == 512 ? " (matches ChatAFL baseline)" :
        adaptive_plateau_threshold == 200 ? " (Opt default, 2.5x more frequent than baseline-512)" : "");
    }
    fflush(stderr);
  }

  memset(llm_prompt_hash_ring, 0, sizeof(llm_prompt_hash_ring));

  /* ============================================
   * MQTT remaining_length fixer (protocol-specific)
   * Default: ON for MQTT, OFF for everything else.
   * Override: CHATAFL_MQTT_FIX_LENGTH=0 to disable.
   * ============================================ */
  if (protocol_name && strcasecmp(protocol_name, "MQTT") == 0) {
    const char *fix_env = getenv("CHATAFL_MQTT_FIX_LENGTH");
    if (fix_env && fix_env[0] == '0') {
      mqtt_fix_length_enabled = 0;
      OKF("MQTT remaining_length fixer DISABLED (CHATAFL_MQTT_FIX_LENGTH=0)");
    } else {
      mqtt_fix_length_enabled = 1;
      OKF("MQTT remaining_length fixer ENABLED (set CHATAFL_MQTT_FIX_LENGTH=0 to disable)");
    }

    /* ============================================
     * P1: MQTT-specific — suppress Hypothesis (S4).
     *
     * Binary protocols like MQTT have <10% hypothesis parse success.
     * The LLM-generated textual grammars cannot describe variable-
     * length binary fields, so hypothesis validation is wasted work.
     *
     * Default: OFF for MQTT.
     * Override: CHATAFL_MQTT_FORCE_HYPOTHESIS=1 to re-enable.
     * ============================================ */
    if (!getenv("CHATAFL_MQTT_FORCE_HYPOTHESIS")) {
      hypothesis_mode = 0;
      OKF("MQTT mode: Hypothesis (S4) auto-DISABLED "
          "(set CHATAFL_MQTT_FORCE_HYPOTHESIS=1 to override)");
    }

    /* P2a: Enable field-aware MQTT mutation in havoc.
     * Default: ON for MQTT.
     * Override: CHATAFL_MQTT_NO_FIELD_MUTATE=1 to disable. */
    if (!getenv("CHATAFL_MQTT_NO_FIELD_MUTATE")) {
      mqtt_field_mutate_enabled = 1;
      OKF("MQTT mode: Field-aware mutation ENABLED "
          "(set CHATAFL_MQTT_NO_FIELD_MUTATE=1 to disable)");
    }

    /* P2b: Enable cross-session state fuzzing.
     * Default: ON for MQTT.
     * Override: CHATAFL_MQTT_NO_CROSS_SESSION=1 to disable. */
    if (!getenv("CHATAFL_MQTT_NO_CROSS_SESSION")) {
      mqtt_cross_session_enabled = 1;
      OKF("MQTT mode: Cross-session state fuzzing ENABLED "
          "(set CHATAFL_MQTT_NO_CROSS_SESSION=1 to disable)");
    }

    /* P3: Initialize Q-Learning + UCB1 bandit schedulers.
     * Default: ON for MQTT when field mutation is also enabled.
     * Override: CHATAFL_MQTT_NO_SCHEDULER=1 to disable. */
    if (mqtt_field_mutate_enabled && !getenv("CHATAFL_MQTT_NO_SCHEDULER")) {
      mqtt_ql_init(&mqtt_ql);
      mqtt_bandit_init(&mqtt_bandit);
      mqtt_scheduler_enabled = 1;
      OKF("MQTT mode: Q-Learning + UCB1 scheduler ENABLED "
          "(set CHATAFL_MQTT_NO_SCHEDULER=1 to disable)");
    }

    /* P4: MQTT differential feedback loop.
     * Uses CHATAFL_MQTT_BROKERS probe output as auxiliary reward signal
     * for state scoring and packet/arm scheduler updates.
     * Default: ON for MQTT.
     *   CHATAFL_MQTT_NO_DIFF_FEEDBACK=1   -> disable
     *   CHATAFL_MQTT_DIFF_PROBE_PERIOD=N  -> probe every N execs (default 8)
     *
     * O1: Default period changed from 32 to 8 — frequent but not
     * every-exec.  Period=1 caused 3× throughput drop (2.1 vs 6.5
     * execs/sec) because each exec replayed against all brokers.
     * Period=8 gives ~12% multi-broker overhead while retaining
     * high-quality diff signal (λ=1.0, cap=2.0 amplify each probe).
     * The main multi-broker block is now gated by the same period
     * counter; between probes, the generic multi-fd single-broker
     * path handles execution at full throughput. */
    if (!getenv("CHATAFL_MQTT_NO_DIFF_FEEDBACK")) {
      mqtt_diff_feedback_enabled = 1;
      mqtt_diff_probe_period = 4;  /* V3-2: every 4th exec (was 8→stale signal, 0.95^8=0.66 decay) */
      {
        const char *pp = getenv("CHATAFL_MQTT_DIFF_PROBE_PERIOD");
        if (pp && *pp) {
          u32 v = (u32)atoi(pp);
          if (v > 0 && v <= 10000)
            mqtt_diff_probe_period = v;
        }
      }
      OKF("MQTT mode: Differential feedback ENABLED "
          "(period=%u, set CHATAFL_MQTT_NO_DIFF_FEEDBACK=1 to disable)",
          mqtt_diff_probe_period);
    }
  }

  /* ============================================
   * Initialize Adaptive Plateau Variables
   * ============================================ */
  last_edges_count = agnedges(ipsm);  // Use IPSM edges (FIXED: was count_bits)
  last_edges_check_time = get_cur_time();
  edges_growth_rate = 0.0;
  adaptive_plateau_threshold = UNINTERESTING_THRESHOLD;  // Start with default 200

  /* Fix-Ablation-1: Apply custom fixed threshold from CHATAFL_ABLATION_THRESHOLD
   * (only meaningful when CHATAFL_NO_ADAPTIVE=1).  Applied here so it overrides
   * the UNINTERESTING_THRESHOLD default set two lines above. */
  if (ablation_no_adaptive) {
    char *resolved = getenv("_CHATAFL_RESOLVED_THRESHOLD");
    if (resolved) {
      u32 custom_thresh = (u32)atoi(resolved);
      if (custom_thresh > 0) {
        adaptive_plateau_threshold = custom_thresh;
      }
      unsetenv("_CHATAFL_RESOLVED_THRESHOLD");
    }
  }

  fprintf(stderr, "[adaptive-plateau] Initialized: initial_edges=%u (IPSM), threshold=%u%s\n",
          last_edges_count, adaptive_plateau_threshold,
          ablation_no_adaptive ? " (ABLATION: fixed)" : "");

  /* ============================================
   * P1: MQTT-specific — raise adaptive plateau floor.
   *
   * For MQTT, the default floor (150-300) triggers LLM calls every
   * ~20-40 sec.  Since MQTT hypotheses have <10% parse success, most
   * LLM calls are wasted.  Raise floor to 500 so LLM triggers only
   * every ~60-80s, giving the fuzzer more uninterrupted mutation time.
   *
   * This runs AFTER the ablation override so it doesn't clobber
   * ablation experiments (ablation_no_adaptive keeps a fixed threshold).
   *
   * Override: CHATAFL_MQTT_LLM_THRESHOLD=N
   * ============================================ */
  if (protocol_name && strcasecmp(protocol_name, "MQTT") == 0 && !ablation_no_adaptive) {
    char *mqtt_thr = getenv("CHATAFL_MQTT_LLM_THRESHOLD");
    if (mqtt_thr) {
      u32 custom = (u32)atoi(mqtt_thr);
      if (custom > 0) adaptive_plateau_threshold = custom;
      OKF("MQTT mode: Plateau threshold=%u (from CHATAFL_MQTT_LLM_THRESHOLD)",
          adaptive_plateau_threshold);
    } else {
      adaptive_plateau_threshold = 500;
      OKF("MQTT mode: Plateau threshold raised to 500 "
          "(set CHATAFL_MQTT_LLM_THRESHOLD=N to override)");
    }
  }

  cull_queue();

  show_init_stats();

  seek_to = find_start_position();

  write_stats_file(0, 0, 0);
  save_auto();

  if (stop_soon)
    goto stop_fuzzing;

  /* Woop woop woop */

  if (!not_on_tty)
  {
    sleep(4);
    start_time += 4000;
    if (stop_soon)
      goto stop_fuzzing;
  }

  if (state_aware_mode)
  {

    if (state_ids_count == 0)
    {
      PFATAL("No server states have been detected. Server responses are likely empty!");
    }

    /* Fix 5b: Node stagnation detection.
     * If no new IPSM nodes have been discovered recently, periodically
     * force random state selection to break out of exploitation ruts. */
    u32 prev_node_count_loop = agnnodes(ipsm);
    u32 node_stagnation_rounds = 0;

    while (1)
    {
      u8 skipped_fuzz;

      struct queue_entry *selected_seed = NULL;
      while (!selected_seed || selected_seed->region_count == 0)
      {
        /* Track node stagnation */
        u32 cur_nodes = agnnodes(ipsm);
        if (cur_nodes > prev_node_count_loop) {
          prev_node_count_loop = cur_nodes;
          node_stagnation_rounds = 0;
        } else {
          node_stagnation_rounds++;
        }

        /* If nodes haven't grown for 80+ rounds, occasionally use
         * RANDOM_SELECTION to explore underrepresented states.
         * 30% chance ensures we don't abandon FAVOR entirely. */
        u8 effective_algo = state_selection_algo;
        if (node_stagnation_rounds > 80 && UR(100) < 30) {
          effective_algo = RANDOM_SELECTION;
        }

        target_state_id = choose_target_state(effective_algo);

        /* Update favorites based on the selected state */
        cull_queue();

        /* Update number of times a state has been selected for targeted fuzzing */
        khint_t k = kh_get(hms, khms_states, target_state_id);
        if (k != kh_end(khms_states))
        {
          kh_val(khms_states, k)->selected_times++;
        }

        selected_seed = choose_seed(target_state_id, seed_selection_algo);
      }

      /* Seek to the selected seed */
      if (selected_seed)
      {
        if (!queue_cur)
        {
          current_entry = 0;
          cur_skipped_paths = 0;
          queue_cur = queue;
          queue_cycle++;
        }
        while (queue_cur != selected_seed)
        {
          queue_cur = queue_cur->next;
          current_entry++;
          if (!queue_cur)
          {
            current_entry = 0;
            cur_skipped_paths = 0;
            queue_cur = queue;
            queue_cycle++;
          }
        }
      }

      skipped_fuzz = fuzz_one(use_argv);

      if (!stop_soon && sync_id && !skipped_fuzz)
      {

        if (!(sync_interval_cnt++ % SYNC_INTERVAL))
          sync_fuzzers(use_argv);
      }

      if (!stop_soon && exit_1)
        stop_soon = 2;

      if (stop_soon)
        break;
    }
  }
  else
  {
    while (1)
    {

      u8 skipped_fuzz;

      cull_queue();

      if (!queue_cur)
      {

        queue_cycle++;
        current_entry = 0;
        cur_skipped_paths = 0;
        queue_cur = queue;

        while (seek_to)
        {
          current_entry++;
          seek_to--;
          queue_cur = queue_cur->next;
        }

        show_stats();

        if (not_on_tty)
        {
          ACTF("Entering queue cycle %llu.", queue_cycle);
          fflush(stdout);
        }

        /* If we had a full queue cycle with no new finds, try
           recombination strategies next. */

        if (queued_paths == prev_queued)
        {

          if (use_splicing)
            cycles_wo_finds++;
          else
            use_splicing = 1;
        }
        else
          cycles_wo_finds = 0;

        prev_queued = queued_paths;

        if (sync_id && queue_cycle == 1 && getenv("AFL_IMPORT_FIRST"))
          sync_fuzzers(use_argv);
      }

      skipped_fuzz = fuzz_one(use_argv);

      if (!stop_soon && sync_id && !skipped_fuzz)
      {

        if (!(sync_interval_cnt++ % SYNC_INTERVAL))
          sync_fuzzers(use_argv);
      }

      if (!stop_soon && exit_1)
        stop_soon = 2;

      if (stop_soon)
        break;

      queue_cur = queue_cur->next;
      current_entry++;
    }
  }

  if (queue_cur)
    show_stats();

  /* If we stopped programmatically, we kill the forkserver and the current runner.
     If we stopped manually, this is done by the signal handler. */
  if (stop_soon == 2)
  {
    if (child_pid > 0)
      kill(child_pid, SIGKILL);
    if (forksrv_pid > 0)
      kill(forksrv_pid, SIGKILL);
  }
  /* Now that we've killed the forkserver, we wait for it to be able to get rusage stats. */
  if (waitpid(forksrv_pid, NULL, 0) <= 0)
  {
    WARNF("error waitpid\n");
  }

  write_bitmap();
  write_stats_file(0, 0, 0);
  save_auto();

stop_fuzzing:

  SAYF(CURSOR_SHOW cLRD "\n\n+++ Testing aborted %s +++\n" cRST,
       stop_soon == 2 ? "programmatically" : "by user");

  /* Running for more than 30 minutes but still doing first cycle? */

  if (queue_cycle == 1 && get_cur_time() - start_time > 30 * 60 * 1000)
  {

    SAYF("\n" cYEL "[!] " cRST
         "Stopped during the first cycle, results may be incomplete.\n"
         "    (For info on resuming, see %s/README.)\n",
         doc_path);
  }

  fclose(plot_file);
  destroy_queue();
  destroy_extras();
  ck_free(target_path);
  ck_free(sync_id);

  destroy_ipsm();

  alloc_report();

  OKF("We're done here. Have a nice day!\n");

  exit(0);
}

#endif /* !AFL_LIB */
