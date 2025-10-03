FROM python:3.11-slim

#############################
# INSTALL PYTHON DEPENDENCIES
#############################

# install git for pip install git+https://
RUN apt-get -o Acquire::Max-FutureTime=100000 update \
 && apt-get install -y --no-install-recommends build-essential git

# create a virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# copy and install python requirements + ember from github
COPY docker-requirements.txt .
RUN pip install --no-cache-dir -r docker-requirements.txt

#############################
# REBASE & DEPLOY CODE
#############################

# rebase to make a smaller image
FROM python:3.11-slim

# required libgomp1 for ember
RUN apt-get -o Acquire::Max-FutureTime=100000 update \
    && apt-get -y --no-install-recommends install \
        libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# copy python virtual env (all dependencies) from previous image
COPY --from=0 /opt/venv /opt/venv

# copy defender code to /opt/defender/defender
COPY defender /opt/defender/defender

#############################
# SETUP ENVIRONMENT
#############################

# open port 8080
EXPOSE 8080

# add a defender user and switch user
RUN groupadd -r defender && useradd --no-log-init -r -g defender defender
USER defender

# change working directory
WORKDIR /opt/defender/

# update environmental variables
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONPATH="/opt/defender"

# Ensemble configuration - Lower threshold for higher TPR with abstaining models
ENV DF_ENSEMBLE_THRESHOLD=.65
ENV DF_ENSEMBLE_REQUIRE_2OF3=false

# MalConv model configuration - Lower threshold for higher TPR (primary detector now)
ENV DF_MALCONV_WEIGHTS=models/malconv_model.pt
ENV DF_MALCONV_THRESH=0.85
ENV DF_MALCONV_MAX_BYTES=1048576
ENV DF_MALCONV_VOTE_WEIGHT=1.5

# LightGBM model configuration - Much lower threshold for higher TPR
ENV DF_LIGHTGBM_MODEL_PATH=models/LGBM_model.txt
ENV DF_LIGHTGBM_THRESH=.825
ENV DF_LIGHTGBM_MAX_BYTES=1048576
ENV DF_LIGHTGBM_VOTE_WEIGHT=.5
ENV DF_LIGHTGBM_USE_ENHANCED=false

# LightGBM 800000 samples, bigger model trained on 800,000 samples TURNED OFF RN
ENV DF_LIGHTGBM800K_MODEL_PATH=models/LGBM_model800.txt
#ENV DF_LIGHTGBM800K_THRESH=.5336
#ENV DF_LIGHTGBM800K_MAX_BYTES=1048576
#ENV DF_LIGHTGBM800K_VOTE_WEIGHT=1
#ENV DF_LIGHTGBM800K_USE_ENHANCED=true

# StringCNN model configuration - Lower threshold TURNED OFF
ENV DF_STRINGCNN_WEIGHTS=models/cnn_strings_best.pt
ENV DF_STRINGCNN_THRESH=0.5
ENV DF_STRINGCNN_MAX_BYTES=1048576
ENV DF_STRINGCNN_VOTE_WEIGHT=0.5

#############################
# RUN CODE
#############################
CMD ["python","-m","defender"]

## TO BUILD IMAGE:
# docker build -t mydefender .
## TO RUN IMAGE (ENVIRONMENTAL VARIABLES DECLARED ABOVE)
# docker run -itp 8080:8080 --memory=1g --cpus=1 mydefender
## TO RUN IMAGE (OVERRIDE ENSEMBLE SETTINGS)
# docker run -itp 8080:8080 --memory=1g --cpus=1 --env DF_ENSEMBLE_THRESHOLD=0.6 --env DF_LIGHTGBM_VOTE_WEIGHT=2.0 mydefender
## TO RUN IMAGE (OVERRIDE MODEL THRESHOLDS)
# docker run -itp 8080:8080 --memory=1g --cpus=1 --env DF_MALCONV_THRESH=0.90 --env DF_LIGHTGBM_THRESH=0.60 mydefender
