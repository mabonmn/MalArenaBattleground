#!/bin/bash
set -e

echo "========================================"
echo "EMBER2024 Setup for Virtual Environment"
echo "========================================"

# Check if we're in a virtual environment
if [[ "$VIRTUAL_ENV" != "" ]]; then
    echo "✓ Virtual environment detected: $VIRTUAL_ENV"
else
    echo "⚠️  Warning: Not in a virtual environment"
    echo "   Consider running: python3 -m venv venv && source venv/bin/activate"
fi

# Install Python dependencies that don't require system libraries
echo "Installing core dependencies..."
pip install --upgrade pip setuptools wheel

# Install dependencies one by one with error handling
dependencies=(
    "numpy"
    "lightgbm"
    "flask>=1.1.2"
    "gevent>=1.4.0"
    "envparse"
    "tqdm"
    "pefile"
    "scikit-learn"
    "requests"
)

for dep in "${dependencies[@]}"; do
    echo "Installing $dep..."
    pip install "$dep"
done

# Try to install thrember with fallback
echo "Attempting to install EMBER2024 (thrember)..."
if pip install git+https://github.com/FutureComputing4AI/EMBER2024.git; then
    echo "✓ thrember installed successfully"
    
    # Test if it works
    if python3 -c "import thrember; print('thrember import successful')" 2>/dev/null; then
        echo "✓ thrember working correctly"
    else
        echo "⚠️  thrember installed but has runtime issues"
        echo "   This is likely due to missing system libraries"
        echo "   The training pipeline will handle this gracefully"
    fi
else
    echo "✗ thrember installation failed"
    echo "   This is expected without system dependencies"
    echo "   You can still run the pipeline - it will install thrember during setup"
fi

# Verify core installations
echo ""
echo "Verifying core installations..."
python3 -c "
import numpy as np
import lightgbm as lgb
import flask
import gevent
print('✓ All core dependencies working')
print(f'✓ numpy: {np.__version__}')
print(f'✓ lightgbm: {lgb.__version__}')
print(f'✓ flask: {flask.__version__}')
"

echo ""
echo "========================================"
echo "Virtual Environment Setup Complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo "1. Try running: python3 train/ember_smoke_test.py"
echo "2. If thrember fails, run: ./train/run_ember_pipeline.sh"
echo "   (The pipeline will handle thrember installation during setup)"
echo ""
echo "Alternative approach if thrember issues persist:"
echo "1. Skip EMBER2024 training for now"
echo "2. Use the existing MalConv model: DF_MODEL_TYPE=malconv"
echo "3. Build Docker: cd defender && docker build -t mydefender ."
echo "========================================"
