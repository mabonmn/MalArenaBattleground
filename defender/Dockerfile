##########################################
# STAGE 1 — BUILD ENVIRONMENT + INSTALL DEPS
##########################################
FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential git python3-dev libomp-dev cmake ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Create venv
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade pip
RUN pip install --upgrade pip setuptools wheel

# Install EMBER2024
RUN git clone https://github.com/FutureComputing4AI/EMBER2024.git /tmp/EMBER2024 \
    && cd /tmp/EMBER2024 \
    && pip install --no-cache-dir . \
    && rm -rf /tmp/EMBER2024

# Install requirements
COPY docker-requirements.txt .
RUN pip install --no-cache-dir -r docker-requirements.txt

# Pin signify 0.7.0
RUN pip install --no-cache-dir --force-reinstall "signify==0.7.0"

# ↓↓↓ FIX BROKEN IMPORT (THE ROBUST WAY) ↓↓↓
# Instead of using sed to guess the line in thrember, we expose SignedPEFile
# in signify's __init__.py. This makes signify backward compatible.
# We use standard shell 'echo' so we don't need to apt-install sed.
RUN echo "from .signed_pe import SignedPEFile" >> /opt/venv/lib/python3.11/site-packages/signify/authenticode/__init__.py


##########################################
# STAGE 2 — RUNTIME IMAGE
##########################################
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv

COPY defender /opt/defender/defender

RUN mkdir -p /opt/mplconfig && chmod -R 777 /opt/mplconfig
ENV MPLCONFIGDIR=/opt/mplconfig

RUN useradd -m -d /home/defender defender
USER defender
WORKDIR /opt/defender/

ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONPATH="/opt/defender"

EXPOSE 8080

CMD ["/opt/venv/bin/python", "-m", "defender"]
