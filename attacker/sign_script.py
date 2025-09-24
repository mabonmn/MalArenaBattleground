"""
Linux PE Signing Script - Compatible with orchestrator API

This script signs PE files using osslsigncode on Linux, matching the API 
used by pe_string_injector.py, code_cave_inserter.py, and wrappe_packer.py
"""

import os
import sys
import argparse
import subprocess
import logging
import shutil
from pathlib import Path
import datetime
import csv

def setup_activity_logging(script_name="linux_pe_signer"):
    """Set up comprehensive activity logging to match other scripts."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"{script_name}_activity_{timestamp}.log"

    # Create logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Log everything

    # Clear any existing handlers
    logger.handlers.clear()

    # File handler for all activity
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    file_handler.setFormatter(file_formatter)

    # Console handler (INFO and above)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    # Log session start
    logger.info("=== LINUX PE SIGNER SESSION STARTED ===")
    logger.info(f"Activity log file: {log_file}")
    logger.info(f"Timestamp: {datetime.datetime.now()}")
    logger.info(f"Working directory: {os.getcwd()}")
    logger.info(f"Command line: {' '.join(sys.argv)}")

    return log_file

def check_dependencies():
    """Check if required dependencies are available."""
    logger = logging.getLogger()
    logger.info("Checking dependencies")

    # Check osslsigncode
    osslsigncode_path = shutil.which("osslsigncode")
    if osslsigncode_path:
        logger.info(f"✓ osslsigncode found at: {osslsigncode_path}")
    else:
        logger.error("✗ osslsigncode not found")
        logger.error("Install with: apt install osslsigncode")
        print("ERROR: osslsigncode not found.")
        print("Install with: apt install osslsigncode")
        return False, None

    # Check openssl
    openssl_path = shutil.which("openssl")
    if openssl_path:
        logger.info(f"✓ openssl found at: {openssl_path}")
    else:
        logger.error("✗ openssl not found")
        logger.error("Install with: apt install openssl")
        print("ERROR: openssl not found.")
        print("Install with: apt install openssl")
        return False, None

    return True, {"osslsigncode": osslsigncode_path, "openssl": openssl_path}

def run_command(cmd, timeout=300, check_return=True):
    """Run a command and return the result."""
    logger = logging.getLogger()

    try:
        logger.debug(f"Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )

        logger.debug(f"Return code: {result.returncode}")
        if result.stdout:
            logger.debug(f"STDOUT: {result.stdout}")
        if result.stderr:
            logger.debug(f"STDERR: {result.stderr}")

        if check_return and result.returncode != 0:
            logger.error(f"Command failed with return code {result.returncode}")

        return result
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout} seconds")
        return None
    except Exception as e:
        logger.error(f"Command failed: {e}")
        return None

def create_certificate_if_missing(cert_file, key_file, subject="Test Code Signing", tools=None):
    """Create certificate files if they don't exist."""
    logger = logging.getLogger()

    cert_path = Path(cert_file)
    key_path = Path(key_file)

    if cert_path.exists() and key_path.exists():
        logger.info("Certificate files already exist")
        return True

    logger.info("Creating self-signed certificate")

    if not tools or not tools.get("openssl"):
        logger.error("OpenSSL not available")
        return False

    openssl_path = tools["openssl"]

    # Generate private key
    key_cmd = [
        openssl_path, "genpkey",
        "-algorithm", "RSA",
        "-out", str(key_path),
        "-pkcs8",
        "-keylen", "2048"
    ]

    result = run_command(key_cmd)
    if not result or result.returncode != 0:
        logger.error("Failed to generate private key")
        return False

    # Generate certificate
    cert_cmd = [
        openssl_path, "req",
        "-new", "-x509",
        "-key", str(key_path),
        "-out", str(cert_path),
        "-days", "3650",
        "-subj", f"/CN={subject}/O=Test Organization/C=US"
    ]

    result = run_command(cert_cmd)
    if not result or result.returncode != 0:
        logger.error("Failed to generate certificate")
        return False

    logger.info(f"✓ Certificate created: {cert_file}")
    logger.info(f"✓ Private key created: {key_file}")
    return True

def sign_pe_files_in_directory(input_dir, cert_file, key_file, tools=None):
    """Sign all PE files in a directory - main API function."""
    logger = logging.getLogger()
    logger.info(f"Signing PE files in directory: {input_dir}")

    if not tools or not tools.get("osslsigncode"):
        logger.error("osslsigncode not available")
        return False

    osslsigncode_path = tools["osslsigncode"]

    # Find PE files
    input_path = Path(input_dir)
    pe_files = []

    for pattern in ["*.exe", "*.dll"]:
        pe_files.extend(input_path.glob(pattern))

    if not pe_files:
        logger.warning(f"No PE files found in {input_dir}")
        return True

    logger.info(f"Found {len(pe_files)} PE files to sign")

    # Prepare CSV output
    csv_file = Path(input_dir) / "signed_results.csv"
    results = []

    signed_count = 0
    failed_count = 0

    for pe_file in pe_files:
        logger.info(f"Processing: {pe_file.name}")

        # Create backup
        backup_file = str(pe_file) + ".backup"
        try:
            shutil.copy2(pe_file, backup_file)
            logger.debug(f"Created backup: {backup_file}")
        except Exception as e:
            logger.warning(f"Could not create backup: {e}")

        # Sign the file
        success = False
        error_msg = ""

        try:
            # Build signing command
            cmd = [
                osslsigncode_path, "sign",
                "-certs", str(cert_file),
                "-key", str(key_file),
                "-h", "sha256",
                "-in", str(pe_file),
                "-out", str(pe_file)
            ]

            # Try with timestamping first
            cmd_with_ts = cmd + ["-t", "http://timestamp.digicert.com"]
            result = run_command(cmd_with_ts, check_return=False)

            if result and result.returncode == 0:
                success = True
                logger.info(f"✓ Signed {pe_file.name} with timestamp")
            else:
                # Try without timestamping
                logger.debug("Timestamping failed, trying without timestamp")
                result = run_command(cmd, check_return=False)

                if result and result.returncode == 0:
                    success = True
                    logger.info(f"✓ Signed {pe_file.name} without timestamp")
                else:
                    error_msg = result.stderr if result else "Command failed"
                    logger.error(f"✗ Failed to sign {pe_file.name}: {error_msg}")

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Exception signing {pe_file.name}: {e}")

        # Record result
        if success:
            signed_count += 1
            results.append([str(pe_file), "ok", ""])
        else:
            failed_count += 1
            results.append([str(pe_file), "error", error_msg[:100]])  # Truncate long errors

            # Restore backup if signing failed
            try:
                shutil.copy2(backup_file, pe_file)
                logger.debug(f"Restored backup for {pe_file.name}")
            except Exception as e:
                logger.warning(f"Could not restore backup: {e}")

        # Clean up backup
        try:
            if Path(backup_file).exists():
                os.unlink(backup_file)
        except Exception as e:
            logger.debug(f"Could not remove backup: {e}")

    # Write CSV results
    try:
        with open(csv_file, 'w', newline='', encoding='utf-8') as csvf:
            writer = csv.writer(csvf)
            writer.writerow(["path", "status", "error"])
            writer.writerows(results)
        logger.info(f"Results written to: {csv_file}")
    except Exception as e:
        logger.error(f"Failed to write CSV: {e}")

    logger.info(f"Signing completed: {signed_count} signed, {failed_count} failed")
    print(f"Signed {signed_count}/{len(pe_files)} PE files")

    return failed_count == 0

def main():
    """Main function matching the API of other scripts."""
    parser = argparse.ArgumentParser(description='Linux PE Signer with Activity Logging')

    # Primary argument - directory to sign
    parser.add_argument('input_dir', help='Directory containing PE files to sign')

    # Certificate options
    parser.add_argument('--cert', default='mykey.pem', help='Certificate file path')
    parser.add_argument('--key', default='mycert.pem', help='Private key file path') 
    parser.add_argument('--subject', default='Test Code Signing Certificate', help='Certificate subject')

    # Compatibility with orchestrator
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')

    args = parser.parse_args()

    # Set up activity logging
    log_file = setup_activity_logging()
    logger = logging.getLogger()

    print("Linux PE Signer with Activity Logging")
    print(f"Log file: {log_file}")

    try:
        logger.info("=== DEPENDENCY CHECK ===")
        has_deps, tools = check_dependencies()
        if not has_deps:
            return 1

        logger.info("=== CERTIFICATE PREPARATION ===")
        # Ensure certificate files exist
        if not create_certificate_if_missing(args.cert, args.key, args.subject, tools):
            logger.error("Failed to create certificate")
            return 2

        logger.info("=== PE SIGNING PROCESS ===")
        # Sign PE files
        success = sign_pe_files_in_directory(args.input_dir, args.cert, args.key, tools)

        if success:
            logger.info("=== SIGNING SUCCESSFUL ===")
            print("✓ All PE files signed successfully")
            return 0
        else:
            logger.warning("=== SIGNING COMPLETED WITH ERRORS ===")
            print("⚠ Some files failed to sign (check log)")
            return 3

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"ERROR: {e}")
        return 1

    finally:
        logger.info(f"Session log saved to: {log_file}")
        print(f"Activity log: {log_file}")

if __name__ == "__main__":
    sys.exit(main())
