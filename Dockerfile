# Dockerfile for MLSEC Competition Malware Detection
# Based on competition requirements: Memory ≤ 1GB, Response time ≤ 5s

FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY malware_detector_api.py .
COPY malware_detector_sample.pkl .
COPY ember_features.py .

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Run the API
CMD ["python", "malware_detector_api.py"]