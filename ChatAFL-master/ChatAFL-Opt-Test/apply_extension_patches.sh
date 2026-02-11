#!/bin/bash

# ============================================================================
# Apply Extension Framework Patches to afl-fuzz.c
# ============================================================================
# 
# This script applies minimal patches to enable extension support in AFL
# WITHOUT violating the Open/Closed Principle.
# 
# Usage: ./apply_extension_patches.sh
# 
# ============================================================================

set -e

AFL_FUZZ_C="afl-fuzz.c"
BACKUP_FILE="afl-fuzz.c.backup"

# Check if file exists
if [ ! -f "$AFL_FUZZ_C" ]; then
    echo "[!] Error: $AFL_FUZZ_C not found"
    exit 1
fi

# Create backup
echo "[*] Creating backup: $BACKUP_FILE"
cp "$AFL_FUZZ_C" "$BACKUP_FILE"

echo "[*] Applying extension framework patches to afl-fuzz.c..."

# ============================================================================
# Patch 1: Add include at the top
# ============================================================================
echo "[*] Patch 1: Adding fuzzer_extension.h include"

# Find the line with #include "chat-llm.h" and add after it
sed -i '/#include "chat-llm.h"/a #include "fuzzer_extension.h"\n#include "chatafl_opt_extension.h"' "$AFL_FUZZ_C"

# ============================================================================
# Patch 2: Declare global extension manager
# ============================================================================
echo "[*] Patch 2: Declaring global extension manager"

# Add after the line with "EXP_ST u8 *in_dir"
sed -i '/^EXP_ST u8 \*in_dir,/a \
\n/* Extension manager for pluggable functionality */\nstatic extension_manager_t *ext_mgr = NULL;' "$AFL_FUZZ_C"

# ============================================================================
# Patch 3: Initialize extension manager in main()
# ============================================================================
echo "[*] Patch 3: Initializing extension manager in main()"

# Find check_asan_opts() and add extension initialization after it
sed -i '/check_asan_opts();/a \
\n  /* Initialize extension framework */\n  ext_mgr = init_extension_manager();\n  if (ext_mgr && protocol_name) {\n    ext_mgr->global_ctx->protocol_name = protocol_name;\n    ext_mgr->global_ctx->sut_host = netinfo_ptr != NULL ? netinfo_ptr->server_name : "127.0.0.1";\n    ext_mgr->global_ctx->sut_port = netinfo_ptr != NULL ? netinfo_ptr->port : 0;\n\n    /* Register ChatAFL-Opt extension if enabled */\n    if (getenv("AFL_ENABLE_CHATAFL_OPT")) {\n      ACTF("Registering ChatAFL-Opt extension");\n      register_extension(ext_mgr, get_chatafl_opt_extension());\n    }\n\n    /* Trigger startup hook */\n    trigger_hook(ext_mgr, HOOK_BEFORE_FUZZING_START);\n  }' "$AFL_FUZZ_C"

# ============================================================================
# Patch 4: Add cleanup before exit
# ============================================================================
echo "[*] Patch 4: Adding extension cleanup before exit"

# Find the final OKF and add cleanup before it
sed -i '/OKF("We'"'"'re done here. Have a nice day!/i \
\n  /* Cleanup extensions */\n  if (ext_mgr) {\n    trigger_hook(ext_mgr, HOOK_BEFORE_FUZZING_END);\n    cleanup_extensions(ext_mgr);\n  }\n' "$AFL_FUZZ_C"

echo "[+] Patches applied successfully!"
echo ""
echo "Summary of changes:"
echo "  - Added fuzzer_extension.h include"
echo "  - Declared global extension_manager_t *ext_mgr"
echo "  - Initialize extension manager in main()"
echo "  - Cleanup extensions before exit"
echo ""
echo "To enable ChatAFL-Opt extension:"
echo "  export AFL_ENABLE_CHATAFL_OPT=1"
echo ""
echo "To restore original file:"
echo "  mv $BACKUP_FILE $AFL_FUZZ_C"
echo ""
echo "[*] Next steps:"
echo "  1. Run: make clean && make"
echo "  2. Test: export AFL_ENABLE_CHATAFL_OPT=1 && ./afl-fuzz ..."
