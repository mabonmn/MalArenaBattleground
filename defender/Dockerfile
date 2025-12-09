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

# Upgrade pip once
RUN pip install --upgrade pip setuptools wheel
# Install EMBER2024
RUN git clone https://github.com/FutureComputing4AI/EMBER2024.git /tmp/EMBER2024 \
    && cd /tmp/EMBER2024 \
    && pip install --no-cache-dir . \
    && rm -rf /tmp/EMBER2024

# Install everything from your original requirements first
COPY docker-requirements.txt .
RUN pip install --no-cache-dir -r docker-requirements.txt

# Pin signify 0.7.0 (keeps it stable)
RUN pip install --no-cache-dir --force-reinstall "signify==0.7.0"

# ↓↓↓ PATCH THREMBER'S BROKEN IMPORT ↓↓↓
# Install sed for editing (slim doesn't have it)
RUN apt-get update && apt-get install -y --no-install-recommends sed \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && sed -i 's/from signify.authenticode import SignedPEFile/from signify.authenticode.signed_pe import SignedPEFile/' /opt/venv/lib/python3.11/site-packages/thrember/features.py \
    && rm -rf /var/lib/apt/lists/*


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

