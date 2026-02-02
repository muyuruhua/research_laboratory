#!/bin/bash
# apply-dynamic-plugin-integration.sh - Apply minimal plugin hooks to afl-fuzz.c
#
# This script automates the integration described in DYNAMIC_PLUGIN_INTEGRATION.md
# It makes surgical modifications to afl-fuzz.c for 100% OCP compliance

set -e

AFL_FUZZ_FILE="afl-fuzz.c"
BACKUP_FILE="afl-fuzz.c.before-dynamic-plugin"

echo "[*] Creating backup: $BACKUP_FILE"
cp "$AFL_FUZZ_FILE" "$BACKUP_FILE"

echo "[+] Step 1: Adding plugin system headers after line 96..."
# Find the line number after last #include
INCLUDE_LINE=$(grep -n "^#include" "$AFL_FUZZ_FILE" | tail -1 | cut -d: -f1)
sed -i "" "${INCLUDE_LINE}a\\
\\
/* Plugin system headers */\\
#include \"afl-plugin-loader.h\"\\
#include \"afl-plugin-hooks.h\"
" "$AFL_FUZZ_FILE"

echo "[+] Step 2: Adding plugin_path global variable..."
# Add after first static variable declaration (around line 550)
VAR_LINE=$(grep -n "^static u8\* " "$AFL_FUZZ_FILE" | head -1 | cut -d: -f1)
sed -i "" "${VAR_LINE}a\\
static u8* plugin_path = NULL;        /* Path to .so plugin */
" "$AFL_FUZZ_FILE"

echo "[+] Step 3: Adding -L option to getopt string..."
sed -i "" 's/getopt(argc, argv, "+i:o:f:m:t:T:dnCB:S:M:x:QN:D:W:w:e:P:KEq:s:RFc:l:")/getopt(argc, argv, "+i:o:f:m:t:T:dnCB:S:M:x:QN:D:W:w:e:P:KEq:s:RFc:l:L:")/' "$AFL_FUZZ_FILE"

echo "[+] Step 4: Adding -L case handler..."
# Find the last case before default in the switch statement
LAST_CASE=$(grep -n "^    case 'l':" "$AFL_FUZZ_FILE" | tail -1 | cut -d: -f1)
# Find the corresponding break statement
BREAK_LINE=$(tail -n +$LAST_CASE "$AFL_FUZZ_FILE" | grep -n "break;" | head -1 | cut -d: -f1)
BREAK_LINE=$((LAST_CASE + BREAK_LINE))

sed -i "" "${BREAK_LINE}a\\
\\
    case 'L': /* Load plugin */\\
\\
      if (plugin_path) FATAL(\"Multiple -L options not supported\");\\
      plugin_path = optarg;\\
      break;
" "$AFL_FUZZ_FILE"

echo "[+] Step 5: Adding plugin loading code..."
# Find setup_dirs() call
SETUP_DIRS_LINE=$(grep -n "setup_dirs_dests();" "$AFL_FUZZ_FILE" | cut -d: -f1)
sed -i "" "${SETUP_DIRS_LINE}a\\
\\
  /* Load dynamic plugin if specified */\\
  if (plugin_path) {\\
    ACTF(\"Loading plugin: %s\", plugin_path);\\
    if (afl_load_plugin(plugin_path) != 0) {\\
      FATAL(\"Failed to load plugin: %s\", plugin_path);\\
    }\\
  }
" "$AFL_FUZZ_FILE"

echo "[+] Step 6: Adding plugin INIT hook..."
# Find line after perform_dry_run() or write_stats_file(0)
INIT_LINE=$(grep -n "write_stats_file(0);" "$AFL_FUZZ_FILE" | tail -1 | cut -d: -f1)
sed -i "" "${INIT_LINE}a\\
\\
  /* Invoke plugin INIT hook */\\
  if (afl_plugins_enabled()) {\\
    afl_hook_data_t init_data = {0};\\
    init_data.init.input_dir = in_dir;\\
    init_data.init.output_dir = out_dir;\\
    init_data.init.target_path = argv[optind];\\
    init_data.init.exec_timeout = exec_tmout;\\
    init_data.init.mem_limit = mem_limit;\\
    AFL_HOOK_CALL_INIT(&init_data);\\
  }
" "$AFL_FUZZ_FILE"

echo "[+] Step 7: Adding plugin CLEANUP hook..."
# Find the last return statement before end of main
CLEANUP_LINE=$(grep -n "return 0;" "$AFL_FUZZ_FILE" | tail -1 | cut -d: -f1)
sed -i "" "$((CLEANUP_LINE - 1))a\\
\\
  /* Invoke plugin CLEANUP hook and unload plugins */\\
  if (afl_plugins_enabled()) {\\
    AFL_HOOK_CALL_CLEANUP();\\
    afl_unload_all_plugins();\\
  }
" "$AFL_FUZZ_FILE"

echo "[+] Step 8: Updating usage message..."
# Find the -E option line in usage and add -L after it
sed -i "" '/"-E ext/a\
"  -L plugin.so    - load dynamic plugin for enhanced fuzzing\\n"
' "$AFL_FUZZ_FILE"

echo ""
echo "[✓] Successfully integrated dynamic plugin support into afl-fuzz.c"
echo "[✓] Backup saved to: $BACKUP_FILE"
echo "[*] Next steps:"
echo "    1. Review changes: diff $BACKUP_FILE $AFL_FUZZ_FILE"
echo "    2. Build: make -f Makefile.dynamic all"
echo "    3. Test: ./afl-fuzz --load-plugin ./chatafl-enhanced.so -h"
