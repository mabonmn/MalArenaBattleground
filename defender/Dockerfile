##########################################
# STAGE 1 — BUILD ENVIRONMENT + INSTALL DEPS
##########################################
FROM python:3.11-slim AS builder

# Install build dependencies required for EMBER2024 / LightGBM / lief etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        git \
        python3-dev \
        libomp-dev \
        cmake \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Create virtualenv
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade pip and install wheel first
RUN pip install --upgrade pip setuptools wheel

# Copy your original requirements (keep everything you already need)
COPY docker-requirements.txt .

# IMPORTANT: Override signify version and install thrember from git (latest fixes)
RUN pip install --no-cache-dir -r docker-requirements.txt \
    && pip install --no-cache-dir "signify==0.7.0" --force-reinstall \
    && pip install --no-cache-dir "git+https://github.com/airbus-cert/thrember.git@main" --force-reinstall

# Clone and install EMBER2024 (unchanged)
RUN git clone https://github.com/FutureComputing4AI/EMBER2024.git /tmp/EMBER2024 \
    && cd /tmp/EMBER2024 \
    && pip install --no-cache-dir . \
    && rm -rf /tmp/EMBER2024

##########################################
# STAGE 2 — RUNTIME IMAGE
##########################################
FROM python:3.11-slim

# Runtime libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
        libgomp1 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy virtualenv from builder
COPY --from=builder /opt/venv /opt/venv

# Copy your defender code
COPY defender /opt/defender/defender

# Matplotlib cache dir (non-root friendly)
RUN mkdir -p /opt/mplconfig && chmod -R 777 /opt/mplconfig
ENV MPLCONFIGDIR=/opt/mplconfig

# Create non-root user
RUN useradd -m -d /home/defender defender
USER defender
WORKDIR /opt/defender/

ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONPATH="/opt/defender"

EXPOSE 8080

# Your existing ENV vars for thresholds, model paths, etc. go here
# ENV THREMBER_THRESHOLD=0.8
# ENV EMBER_MODEL_PATH=/opt/defender/models/ember.pkl
# etc.

CMD ["/opt/venv/bin/python", "-m", "defender"]
