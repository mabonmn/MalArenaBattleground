##########################################
# STAGE 1 — BUILD ENVIRONMENT + INSTALL DEPS
##########################################

FROM python:3.11-slim AS builder

# Install build dependencies required for EMBER2024
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        git \
        python3-dev \
        libomp-dev \
        cmake \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Create Python virtualenv
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy and install standard Python dependencies
COPY docker-requirements.txt .
RUN pip install --upgrade pip setuptools wheel \
 && pip install --no-cache-dir -r docker-requirements.txt

# Clone EMBER2024 and install it
RUN git clone https://github.com/FutureComputing4AI/EMBER2024.git /tmp/EMBER2024 \
    && cd /tmp/EMBER2024 \
    && pip install --no-cache-dir . \
    && rm -rf /tmp/EMBER2024

##########################################
# STAGE 2 — RUNTIME IMAGE
##########################################

FROM python:3.11-slim

# Needed for LightGBM / EMBER runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        libgomp1 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy venv from builder
COPY --from=builder /opt/venv /opt/venv

# Copy application code
COPY defender /opt/defender/defender

# Fix matplotlib cache issues (no home for user yet)
RUN mkdir -p /opt/mplconfig && chmod -R 777 /opt/mplconfig
ENV MPLCONFIGDIR=/opt/mplconfig

# Create non-root user
RUN useradd -m -d /home/defender defender
USER defender

WORKDIR /opt/defender/
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONPATH="/opt/defender"

# Expose port (as before)
EXPOSE 8080

# Environment vars previously used (thresholds, model paths, etc.)
# ... (keep your previous ENV lines here) ...

# Run using the venv Python explicitly
CMD ["/opt/venv/bin/python", "-m", "defender"]
