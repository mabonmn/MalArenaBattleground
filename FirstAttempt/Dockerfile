# Dockerfile for MLSEC Competition Malware Detection
# Competition requirements: Memory ≤ 1.5GB, Response time ≤ 5s, Port 8080

FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies needed for EMBER
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    git \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install EMBER library
RUN pip install git+https://github.com/elastic/ember.git

# Copy application files
COPY malware_detector_api.py .
COPY models/ ./models/

# Set environment variables for competition
ENV MODEL_PATH=/app/models/malware_lightgbm_200sample_model.txt
ENV THRESHOLD=0.5
ENV PORT=8080
ENV HOST=0.0.0.0
ENV FLASK_ENV=production
ENV PYTHONPATH=/app

# Expose the required port (competition requirement)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the API
CMD ["python", "malware_detector_api.py"]