#!/bin/bash

# RAVEN-X Enterprise - Ultra Quick Setup
# For those who want to GO FAST!

echo "
╔══════════════════════════════════════════════════════════════════════════════╗
║   🔥🔥🔥 RAVEN-X ENTERPRISE QUICKSTART 🔥🔥🔥                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
"

# Check Python
echo "[*] Checking Python..."
if ! command -v python &> /dev/null; then
    echo "❌ Python not found! Install Python 3.8+"
    exit 1
fi

echo "✅ Python found: $(python --version)"

# Install dependencies
echo ""
echo "[*] Installing dependencies..."
pip install -q -r requirements.txt

# Setup
echo ""
echo "[*] Running setup..."
python run.py --mode setup

echo ""
echo "
╔══════════════════════════════════════════════════════════════════════════════╗
║   ✅ SETUP COMPLETE!                                                          ║
║                                                                              ║
║   Run: python run.py --mode all                                             ║
║                                                                              ║
║   🚀 LET'S DOMINATE THE EXPO! 🚀                                            ║
╚══════════════════════════════════════════════════════════════════════════════╝
"