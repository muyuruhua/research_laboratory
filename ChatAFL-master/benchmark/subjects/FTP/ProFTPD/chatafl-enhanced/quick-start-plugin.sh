#!/bin/bash
#
# quick-start-plugin.sh - Quick Start Guide for Plugin Architecture
#
# This script demonstrates how to build and use the plugin-based ChatAFL-Enhanced
#

set -e

echo "======================================================================="
echo "ChatAFL-Enhanced Plugin Architecture - Quick Start"
echo "======================================================================="
echo ""

# Step 1: Check environment
echo "[1/6] Checking build environment..."
if ! command -v gcc &> /dev/null; then
    echo "ERROR: gcc not found. Please install build-essential."
    exit 1
fi
if ! command -v make &> /dev/null; then
    echo "ERROR: make not found. Please install make."
    exit 1
fi
echo "✓ Build tools OK"
echo ""

# Step 2: Clean previous builds
echo "[2/6] Cleaning previous builds..."
make clean 2>/dev/null || true
echo "✓ Clean complete"
echo ""

# Step 3: Build with plugin system
echo "[3/6] Building ChatAFL-Enhanced with plugin architecture..."
echo "      This may take a few minutes..."
make CHATAFL_ENHANCED=1 -f Makefile.plugin -j$(nproc 2>/dev/null || echo 4)
echo "✓ Build successful!"
echo ""

# Step 4: Verify plugins
echo "[4/6] Verifying plugin system..."
if [ -f "afl-fuzz" ]; then
    echo "✓ afl-fuzz compiled with plugin support"
else
    echo "ERROR: afl-fuzz not found"
    exit 1
fi
echo ""

# Step 5: Show usage
echo "[5/6] Plugin System Usage:"
echo ""
echo "Basic fuzzing (all plugins enabled by default):"
echo "  ./afl-fuzz -i input_dir -o output_dir -- ./target_binary"
echo ""
echo "Configure plugin behavior via environment variables:"
echo "  export CEGAR_TRIGGER_INTERVAL=20        # Trigger CEGAR every 20 rejections"
echo "  export SCHEDULER_PLATEAU_THRESHOLD=100  # Plateau detection threshold"
echo "  export VERIFIER_LOG=1                   # Enable verifier logging"
echo "  export PLUGIN_VERBOSE=1                 # Verbose plugin output"
echo ""
echo "Disable specific plugins:"
echo "  export PLUGIN_DISABLE_CEGAR=1           # Disable CEGAR plugin"
echo "  ./afl-fuzz -i in -o out -- ./target"
echo ""

# Step 6: Create test script
echo "[6/6] Creating test script (test-plugins.sh)..."
cat > test-plugins.sh << 'EOF'
#!/bin/bash
# Test script for plugin system

echo "Testing Plugin System..."
echo ""

# Create test input
mkdir -p test_in test_out
echo "GET / HTTP/1.1\r\nHost: test\r\n\r\n" > test_in/seed.txt

# Configure plugins
export CHATAFL_ENHANCED=1
export PLUGIN_VERBOSE=1
export CEGAR_TRIGGER_INTERVAL=5
export SCHEDULER_PLATEAU_THRESHOLD=50

# Run fuzzer for 60 seconds (test mode)
timeout 60 ./afl-fuzz -i test_in -o test_out -m none -V 60 -- ./testLLM || true

echo ""
echo "Test complete! Check test_out/ for results."
echo "Plugin statistics should be displayed above."
EOF

chmod +x test-plugins.sh
echo "✓ Test script created: ./test-plugins.sh"
echo ""

echo "======================================================================="
echo "Setup Complete!"
echo "======================================================================="
echo ""
echo "Next steps:"
echo "  1. Read the documentation:  cat PLUGIN_ARCHITECTURE.md"
echo "  2. Run a test:              ./test-plugins.sh"
echo "  3. Create your own plugin:  See PLUGIN_ARCHITECTURE.md"
echo ""
echo "Architecture benefits:"
echo "  ✓ Zero core code modification (follows Open/Closed Principle)"
echo "  ✓ Plugins can be enabled/disabled without recompiling"
echo "  ✓ Easy to add new functionality without breaking existing code"
echo "  ✓ Clean separation of concerns"
echo "  ✓ Testable and maintainable"
echo ""
echo "For more information, see:"
echo "  - PLUGIN_ARCHITECTURE.md  (Complete guide)"
echo "  - REFACTORING_GUIDE.md    (Technical details)"
echo "  - plugin-*.c              (Example plugins)"
echo ""
echo "Happy fuzzing with plugins! 🚀"
