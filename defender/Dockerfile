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

# Install everything from your original requirements first
COPY docker-requirements.txt .
RUN pip install --no-cache-dir -r docker-requirements.txt

# ↓↓↓ THIS IS THE ONLY THING YOU NEED ↓↓↓
# Force-install the last working signify version (0.7.0) — thrember 0.1.0 is perfectly happy with it
RUN pip install --no-cache-dir --force-reinstall "signify==0.7.0"

# Install EMBER2024
RUN git clone https://github.com/FutureComputing4AI/EMBER2024.git /tmp/EMBER2024 \
    && cd /tmp/EMBER2024 \
    && pip install --no-cache-dir . \
    && rm -rf /tmp/EMBER2024

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
