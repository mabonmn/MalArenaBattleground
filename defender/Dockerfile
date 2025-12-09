##########################################
# STAGE 1 — BUILD ENVIRONMENT + INSTALL DEPS
##########################################

FROM python:3.11-slim AS builder

# Install dependencies required to build EMBER2024 (thrember)
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        git \
        python3-dev \
        libomp-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Create Python virtual env
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements
COPY docker-requirements.txt .

# Install python packages (including EMBER2024 from GitHub)
RUN pip install --no-cache-dir -r docker-requirements.txt


##########################################
# STAGE 2 — SMALL RUNTIME IMAGE
##########################################

FROM python:3.11-slim

# Needed for LightGBM + EMBER runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        libgomp1 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy the prebuilt venv from stage 1
COPY --from=builder /opt/venv /opt/venv

# Copy defender code
COPY defender /opt/defender/defender

##########################################
# SETUP ENVIRONMENT
##########################################

# Fix Matplotlib (no home for defender user)
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

# Model configuration
ENV DF_ENSEMBLE_THRESHOLD=.65
ENV DF_ENSEMBLE_REQUIRE_2OF3=false

ENV DF_MALCONV_WEIGHTS=models/malconv_model.pt
ENV DF_MALCONV_THRESH=0.85
ENV DF_MALCONV_MAX_BYTES=1048576
ENV DF_MALCONV_VOTE_WEIGHT=1.5

ENV DF_LIGHTGBM_MODEL_PATH=models/LGBM_model.txt
ENV DF_LIGHTGBM_THRESH=.825
ENV DF_LIGHTGBM_MAX_BYTES=1048576
ENV DF_LIGHTGBM_VOTE_WEIGHT=.5
ENV DF_LIGHTGBM_USE_ENHANCED=false

ENV DF_LIGHTGBM800K_MODEL_PATH=models/LGBM_model800.txt

ENV DF_STRINGCNN_WEIGHTS=models/cnn_strings_best.pt
ENV DF_STRINGCNN_THRESH=0.5
ENV DF_STRINGCNN_MAX_BYTES=1048576
ENV DF_STRINGCNN_VOTE_WEIGHT=0.5

# Expose the API port
EXPOSE 8080

##########################################
# RUN DEFENDER
##########################################

CMD ["/opt/venv/bin/python", "-m", "defender"]

