#!/bin/bash
# Script to build and run the load testing tool GUI

echo "================================================="
echo "   🚀 SIMULATE LOAD RUST - Desktop GUI Launcher"
echo "================================================="

# Compile binary if not compiled
if [ ! -f "./target/release/simulate_load_rust" ]; then
    echo "  [1/2] Compiling Rust binary in release mode..."
    cargo build --release
else
    echo "  [1/2] Rust binary already compiled."
fi

# Run GUI
echo "  [2/2] Launching Electron GUI wrapper..."
cd ../simulate_load_gui && npm start
