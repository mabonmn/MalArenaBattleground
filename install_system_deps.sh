#!/bin/bash
set -e

echo "========================================"
echo "EMBER2024 System Dependencies Setup"
echo "========================================"

# Update system packages

#echo "Updating system packages..."
#sudo apt-get update

# Install required system dependencies
#echo "Installing system dependencies..."
#sudo apt-get install -y \
 #   build-essential \
  #  git \
   # libssl-dev \
   # libffi-dev \
  #  python3-dev \
   # pkg-config \
    #libgomp1
###

# Install Python dependencies
echo "Installing Python dependencies..."
pip install --upgrade pip setuptools wheel

# Install LightGBM
echo "Installing LightGBM..."
pip install lightgbm

# Install EMBER2024 with retry logic
echo "Installing EMBER2024..."
for i in {1..3}; do
    echo "Attempt $i/3 to install thrember..."
    if pip install git+https://github.com/FutureComputing4AI/EMBER2024.git; then
        echo "✓ thrember installed successfully"
        break
    else
        echo "✗ Attempt $i failed"
        if [ $i -eq 3 ]; then
            echo "Failed to install thrember after 3 attempts"
            echo "You may need to install manually or use a different approach"
            exit 1
        fi
        sleep 2
    fi
done

# Verify installation
echo "Verifying installation..."
python3 -c "
import thrember
print('✓ thrember imported successfully')
extractor = thrember.features.PEFeatureExtractor()
print(f'✓ Feature extractor created with {extractor.dim} features')
"

echo "========================================"
echo "System setup complete!"
echo "========================================"
