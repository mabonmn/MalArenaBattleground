##########################################
# STAGE 1 — BUILD ENVIRONMENT + INSTALL DEPS
##########################################

FROM python:3.11-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        git \
        python3-dev \
        libomp-dev \
        cmake \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Create Python virtual env
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy general Python dependencies
COPY docker-requirements.txt .

# Upgrade pip and install requirements
RUN pip install --upgrade pip setuptools wheel
RUN pip install --no-cache-dir -r docker-requirements.txt

# Install EMBER2024 from source automatically
RUN git clone https://github.com/FutureComputing4AI/EMBER2024.git /tmp/EMBER2024 \
    && cd /tmp/EMBER2024 \
    && pip install . \
    && rm -rf /tmp/EMBER2024

##########################################
# STAGE 2 — SMALL RUNTIME IMAGE
##########################################

FROM python:3.11-slim

# Needed for LightGBM + EMBER runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        libgomp1 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy Python virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Copy defender code
COPY defender /opt/defender/defender

##########################################
# SETUP ENVIRONMENT
##########################################

# Fix Matplotlib cache issue (no writable home for 'defender' user yet)
RUN mkdir -p /opt/mplconfig && chmod -R 777 /opt/mplconfig
ENV MPLCONFIGDIR=/opt/mplconfig

# Create defender user with home directory
RUN useradd -m -d /home/defender defender
USER defender

# Working directory
WORKDIR /opt/defender/

# Environment variables
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONPATH="/opt/defender"

# Ensemble configuration
ENV DF_ENSEMBLE_THRESHOLD=.65
ENV DF_ENSEMBLE_REQUIRE_2OF3=false

# MalConv model configuration
ENV DF_MALCONV_WEIGHTS=models/malconv_model.pt
ENV DF_MALCONV_THRESH=0.85
ENV DF_MALCONV_MAX_BYTES=1048576
ENV DF_MALCONV_VOTE_WEIGHT=1.5

# LightGBM model configuration
ENV DF_LIGHTGBM_MODEL_PATH=models/LGBM_model.txt
ENV DF_LIGHTGBM_THRESH=.825
ENV DF_LIGHTGBM_MAX_BYTES=1048576
ENV DF_LIGHTGBM_VOTE_WEIGHT=.5
ENV DF_LIGHTGBM_USE_ENHANCED=false

# StringCNN model configuration
ENV DF_STRINGCNN_WEIGHTS=models/cnn_strings_best.pt
ENV DF_STRINGCNN_THRESH=0.5
ENV DF_STRINGCNN_MAX_BYTES=1048576
ENV DF_STRINGCNN_VOTE_WEIGHT=0.5

# Expose API port
EXPOSE 8080

##########################################
# RUN DEFENDER
##########################################

CMD ["/opt/venv/bin/python", "-m", "defender"]
