# Copilot Instructions for MalArenaBattleground

## Project Context & MLSEC Defender Challenge
This project is a class assignment for the MLSEC Defender Challenge. The goal is to build a Dockerized malware classifier that meets strict competition requirements:

- **Deliverable:** Docker image (≤ 1 GB uncompressed) exposing a REST API on port 8080.
- **API:** Accepts POST `/` with `Content-Type: application/octet-stream` and a PE file in the body. Returns `{ "result": 0 }` (benign) or `{ "result": 1 }` (malicious) as JSON.
- **Performance:**
  - False Positive Rate (FPR) < 1%
  - True Positive Rate (TPR) ≥ 95%
  - ≤ 1 GB RAM, ≤ 5 seconds per sample, ≤ 2 MiB file size

## Architecture & Key Components
- `defender/`: Main Python package and Docker context
  - `defender/models/`: Model code (e.g., `malconv_model.py`) and weights (`malconv_model.pt`, `LGBM_model.txt`)
  - `feature_extractor.py`: Feature extraction for PE files
  - `apps.py`, `__main__.py`: API server entry points (see `create_app` usage)
  - `tools/batch_scan.py`: Batch scanning utility
- `train/`: Model training scripts (e.g., `train_malconv.py`, `train_lgbm.py`)
- `temp/`: Model checkpoints, metrics, thresholds

## Developer Workflows
- **Build Docker image:**
  - `docker build -t mydefender .`
- **Run container:**
  - `docker run --rm -p 8080:8080 mydefender`
- **Test API:**
  - Single file: `curl -s -X POST -H "Content-Type: application/octet-stream" --data-binary @/path/to/file.exe http://127.0.0.1:8080/`
  - Batch: `python defender/tools/batch_scan.py --dir /path/to/files --workers 8 --out-csv /path/to/results.csv`
- **Train model:**
  - `python train/train_malconv.py` (outputs to `temp/`)
  - `python train/train_lgbm.py` (outputs to `temp/`)
- **Export for submission:**
  - `docker image save -o mydefender.tar mydefender && gzip mydefender.tar`

## Project-Specific Conventions
- All model weights, thresholds, and metrics are stored in `temp/`.
- REST API always returns a JSON object with a `result` field.
- Batch tools and shell scripts follow the pattern in `tools/batch_scan.py` and `README.md`.
- Minimal dependencies: see `defender/requirements.txt` and `docker-requirements.txt`.
- Model logic should be in `defender/models/` and expose a `predict` method returning 0 (benign) or 1 (malicious).
- Update Dockerfile and requirements if adding dependencies.
- **Feature extraction** is centralized in `defender/feature_extractor.py`.
- **Error handling:** Errors are logged to `defender/errors.txt`.
- **Testing:** Minimal; see `train/smoke_test.py`.

## Integration & Testing
- The Docker container must not exceed 1 GB uncompressed and must run with ≤ 1 GB RAM.
- All API and batch tools use the same REST endpoint.
- Use provided test scripts and sample archives (see MLSEC site) for offline validation.
- For submission, gzip the Docker image and upload to the MLSEC portal.
- **External Models:** Model files must be present in `defender/models/` for inference.

## Tournament Script (In Progress)
- Work is underway to build a tournament script that runs multiple models, each voting with a different weight to classify malware. This ensemble approach will combine predictions from several models for improved accuracy. See `defender/models/` and future scripts for implementation details.

## Examples & References
- See `README.md` and `defender/README.md` for up-to-date usage and batch scan examples.
- Example batch scan:
  ```sh
  python defender/tools/batch_scan.py --dir /path/to/files --workers 8 --out-csv /path/to/results.csv
  ```
- Example shell script for batch scan: see `README.md`.
- **Scan a file:**
  ```sh
  curl -s -X POST -H "Content-Type: application/octet-stream" --data-binary @/path/to/file.exe http://127.0.0.1:8080/
  ```

## Tips for AI Agents
- When adding new model logic, update both `defender/models/` and the API interface as needed.
- For new batch tools, follow the pattern in `tools/batch_scan.py`.
- Keep Docker and requirements files in sync with any new dependencies.
- Reference `README.md` for workflow and submission details.

---
For new patterns or changes, update this file to keep AI agents productive.
