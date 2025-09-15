# EMBER2024 LightGBM Malware Classifier

This implementation provides a complete LightGBM-based malware classifier using the EMBER2024 dataset, designed to meet the defender challenge requirements:

- **False Positive Rate (FPR)**: ≤ 1%
- **True Positive Rate (TPR)**: ≥ 95%
- **Memory**: ≤ 1 GB RAM
- **Response Time**: ≤ 5 seconds per sample

## Features

- ✅ EMBER2024 dataset with modern PE features
- ✅ LightGBM model optimized for speed and accuracy
- ✅ Docker-based deployment
- ✅ Automated training pipeline
- ✅ Comprehensive testing tools
- ✅ Environment-based configuration
- ✅ Performance monitoring

## Quick Start

### 1. build environment

```
python3 -m venv venv
source venv/bin/activate
./install_venv_deps.sh
pip3 install -I git+https://github.com/wbond/oscrypto.git 
```
oscrypto install is to fix bug 

### 1. Train the Model

```bash
# Run the complete training pipeline
./train/run_ember_pipeline.sh
```

This will:
- Install EMBER2024 (thrember)
- Download the dataset (~50GB)
- Train and optimize the LightGBM model
- Save model files to `defender/defender/models/ember_lightgbm/`

### 2. Build Docker Image

```bash
cd defender
docker build -t mydefender .
```

### 3. Run the Defender

```bash
# Run with memory and CPU limits (as per challenge requirements)
docker run --rm -p 8080:8080 --memory=1g --cpus=1 mydefender
```

### 4. Test the API

```bash
# Test with a single file
curl -X POST --data-binary @sample.exe http://localhost:8080/ \
     -H "Content-Type: application/octet-stream"

# Batch scan directory
python3 tools/batch_scan.py --dir /path/to/test/files --output results.csv
```

## File Structure

```
train/
├── setup_ember2024.py          # Dataset setup and installation
├── train_lightgbm_ember.py     # Model training script
└── run_ember_pipeline.sh       # Complete training pipeline

defender/
├── defender/
│   ├── __main__.py             # Updated main application
│   └── models/
│       ├── ember_lightgbm_model.py    # LightGBM model class
│       └── ember_lightgbm/             # Trained model files (created during training)
│           ├── lightgbm_ember_model.txt
│           ├── model_metadata.json
│           ├── optimal_threshold.txt
│           └── feature_importance.json
├── requirements.txt            # Updated Python dependencies
├── docker-requirements.txt     # Updated Docker dependencies
└── Dockerfile                  # Updated Docker configuration

tools/
└── batch_scan.py              # Enhanced batch scanning tool

data/
└── ember2024/                  # EMBER2024 dataset (created during setup)
```

## Configuration

The system supports flexible configuration via environment variables:

### Model Selection
```bash
# Use EMBER LightGBM (default)
DF_MODEL_TYPE=ember_lightgbm

# Use MalConv (fallback)
DF_MODEL_TYPE=malconv
```

### EMBER Model Configuration
```bash
# Model file path (relative to models directory)
DF_EMBER_MODEL_PATH=ember_lightgbm/lightgbm_ember_model.txt

# Prediction threshold (uses trained optimal threshold if not set)
DF_EMBER_THRESHOLD=0.8

# Maximum file size to process (2MB default)
DF_EMBER_MAX_BYTES=2097152
```

## Training Details

### Dataset
- **EMBER2024**: Modern PE features for Windows malware
- **Training set**: ~2.6M files (Win32, Win64, .NET)
- **Test set**: ~600K files
- **Challenge set**: ~6K evasive malware samples

### Model Optimization
- **Algorithm**: LightGBM with optimized hyperparameters
- **Features**: EMBER v3 feature vector (enhanced PE analysis)
- **Threshold tuning**: Automated to meet FPR ≤ 1% requirement
- **Speed optimization**: Reduced tree depth and leaves for fast inference

### Performance Targets
- **FPR**: ≤ 1% (False Positive Rate)
- **TPR**: ≥ 95% (True Positive Rate) 
- **Response time**: < 5 seconds per sample
- **Memory usage**: < 1GB during operation

## Docker Usage

### Basic Usage
```bash
# Build image
docker build -t mydefender .

# Run with default settings
docker run --rm -p 8080:8080 mydefender
```

### Advanced Configuration
```bash
# Run with custom threshold
docker run --rm -p 8080:8080 \
  --env DF_EMBER_THRESHOLD=0.9 \
  mydefender

# Run with MalConv fallback
docker run --rm -p 8080:8080 \
  --env DF_MODEL_TYPE=malconv \
  mydefender

# Run with memory and CPU limits
docker run --rm -p 8080:8080 \
  --memory=1g --cpus=1 \
  mydefender
```

## Testing and Validation

### Batch Scanning
```bash
# Scan directory recursively
python3 tools/batch_scan.py --dir /path/to/malware --output results.csv

# Scan specific file types
python3 tools/batch_scan.py --dir /path/to/files --extensions .exe .dll .scr

# Limit number of files
python3 tools/batch_scan.py --dir /path/to/files --max-files 1000
```

### Performance Testing
```bash
# Test response times
python3 tools/batch_scan.py --dir /path/to/large/files --timeout 6

# Monitor for requirement compliance
python3 tools/batch_scan.py --dir /path/to/test/set --output compliance_test.csv
```

## API Specification

The defender exposes a simple HTTP API:

### Endpoint: `POST /`
- **Content-Type**: `application/octet-stream`
- **Body**: Raw PE file bytes
- **Response**: `{"result": 0}` (benign) or `{"result": 1}` (malicious)

### Example
```bash
curl -X POST --data-binary @malware.exe http://localhost:8080/ \
     -H "Content-Type: application/octet-stream"
```

## Troubleshooting

### Dataset Download Issues
```bash
# Retry dataset download
python3 train/setup_ember2024.py

# Download specific components
python3 -c "
import thrember
thrember.download_dataset('data/ember2024', file_type='Win32', split='train')
"
```

### Model Training Issues
```bash
# Check dependencies
python3 -c "import lightgbm, thrember; print('Dependencies OK')"

# Train with verbose output
python3 train/train_lightgbm_ember.py --data-dir data/ember2024 --output-dir defender/defender/models/ember_lightgbm
```

### Docker Issues
```bash
# Check model file exists
ls -la defender/defender/models/ember_lightgbm/

# Build with verbose output
docker build -t mydefender . --progress=plain

# Run with environment debugging
docker run --rm -p 8080:8080 -e DF_MODEL_TYPE=ember_lightgbm mydefender
```

## Performance Metrics

The trained model provides comprehensive metrics:

- **Test set performance**: FPR, TPR, accuracy
- **Challenge set performance**: Performance on evasive samples
- **Inference speed**: Average time per prediction
- **Memory usage**: RAM consumption during operation
- **Feature importance**: Most important features for classification

These metrics are saved in `model_metadata.json` and can be monitored during operation.

## Development

### Adding New Features
1. Modify `ember_lightgbm_model.py` for model changes
2. Update `train_lightgbm_ember.py` for training changes
3. Rebuild Docker image and test

### Custom Thresholds
1. Train model with desired FPR target: `--target-fpr 0.005`
2. Set threshold via environment: `DF_EMBER_THRESHOLD=<value>`

### Integration Testing
1. Use `tools/batch_scan.py` for comprehensive testing
2. Monitor performance metrics via model API
3. Validate against challenge requirements

---

This implementation provides a robust, scalable malware detection system that meets all defender challenge requirements while maintaining high performance and accuracy.
