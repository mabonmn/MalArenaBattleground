#!/bin/bash
set -e

echo "========================================"
echo "EMBER2024 LightGBM Training Pipeline"
echo "========================================"
echo "This script will:"
echo "1. Setup EMBER2024 dataset"
echo "2. Train LightGBM model"
echo "3. Validate model requirements"
echo "========================================"

# Configuration
DATA_DIR="data/ember2024"
OUTPUT_DIR="defender/defender/models/ember_lightgbm"
TARGET_FPR=0.01
TARGET_TPR=0.95

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "ERROR: python3 is required but not found"
    exit 1
fi

# Check if we're in the right directory
if [ ! -f "train/setup_ember2024.py" ]; then
    echo "ERROR: Please run this script from the project root directory"
    echo "Current directory: $(pwd)"
    exit 1
fi

echo ""
echo "Step 1: Setting up EMBER2024..."
echo "========================================"
python3 train/setup_ember2024.py

if [ $? -ne 0 ]; then
    echo "ERROR: EMBER2024 setup failed"
    exit 1
fi

echo ""
echo "Step 2: Training LightGBM model..."
echo "========================================"
python3 train/train_lightgbm_ember.py \
    --data-dir "$DATA_DIR" \
    --output-dir "$OUTPUT_DIR" \
    --target-fpr "$TARGET_FPR" \
    --target-tpr "$TARGET_TPR"

if [ $? -ne 0 ]; then
    echo "ERROR: Model training failed"
    exit 1
fi

echo ""
echo "Step 3: Validating model output..."
echo "========================================"

# Check if model files were created
MODEL_FILE="$OUTPUT_DIR/lightgbm_ember_model.txt"
METADATA_FILE="$OUTPUT_DIR/model_metadata.json"
THRESHOLD_FILE="$OUTPUT_DIR/optimal_threshold.txt"

if [ ! -f "$MODEL_FILE" ]; then
    echo "ERROR: Model file not found: $MODEL_FILE"
    exit 1
fi

if [ ! -f "$METADATA_FILE" ]; then
    echo "ERROR: Metadata file not found: $METADATA_FILE"
    exit 1
fi

if [ ! -f "$THRESHOLD_FILE" ]; then
    echo "ERROR: Threshold file not found: $THRESHOLD_FILE"
    exit 1
fi

echo "✓ Model file: $MODEL_FILE"
echo "✓ Metadata file: $METADATA_FILE"
echo "✓ Threshold file: $THRESHOLD_FILE"

# Display model information
echo ""
echo "Model Information:"
echo "========================================"
echo "Threshold: $(cat $THRESHOLD_FILE)"

if command -v jq &> /dev/null; then
    echo "Model metrics:"
    jq '.metrics | {fpr, tpr, accuracy, meets_requirements}' "$METADATA_FILE"
else
    echo "Install 'jq' to see detailed metrics"
fi

# Display next steps
echo ""
echo "========================================"
echo "Training Pipeline Complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo ""
echo "1. Build Docker image:"
echo "   cd defender"
echo "   docker build -t mydefender ."
echo ""
echo "2. Run defender:"
echo "   docker run --rm -p 8080:8080 --memory=1g --cpus=1 mydefender"
echo ""
echo "3. Test the model:"
echo "   python3 -m defender.test -m /path/to/malware -b /path/to/benign"
echo ""
echo "4. Batch scan files:"
echo "   python3 tools/batch_scan.py --url http://localhost:8080 --dir /path/to/files"
echo ""
echo "Environment variables for tuning:"
echo "   DF_MODEL_TYPE=ember_lightgbm (default)"
echo "   DF_EMBER_THRESHOLD=<threshold> (uses trained optimal threshold by default)"
echo "   DF_EMBER_MAX_BYTES=2097152 (2MB limit)"
echo ""

# Check disk space used
if command -v du &> /dev/null; then
    echo "Disk space used:"
    echo "Data: $(du -sh $DATA_DIR 2>/dev/null || echo 'N/A')"
    echo "Model: $(du -sh $OUTPUT_DIR 2>/dev/null || echo 'N/A')"
fi

echo "========================================"
