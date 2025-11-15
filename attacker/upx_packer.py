"""
UPX Packer with Activity Logging
Logs all operations and activity to file for complete audit trail.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path
import argparse
import logging
import datetime
import traceback

def setup_activity_logging(script_name="upx_packer"):
    """Set up comprehensive activity logging."""
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
    logger.info(f"=== UPX PACKER SESSION STARTED ===")
    logger.info(f"Activity log file: {log_file}")
    logger.info(f"Timestamp: {datetime.datetime.now()}")
    logger.info(f"Working directory: {os.getcwd()}")
    logger.info(f"Command line: {' '.join(sys.argv)}")

    return log_file

def check_upx_available(custom_path=None):
    """Check if UPX is available in the system PATH or at a specified path."""
    logger = logging.getLogger()
    logger.info("Starting UPX availability check")

    # Log current directory for debugging
    current_dir = os.getcwd()
    logger.debug(f"Current directory: {current_dir}")

    # First try UPX in current directory (most common case)
    local_upx = Path('./upx')
    logger.debug(f"Checking for local UPX at: {local_upx}")

    if local_upx.exists():
        logger.info(f"Found UPX file at: {local_upx}")

        # Ensure executable permission
        try:
            mode = local_upx.stat().st_mode
            local_upx.chmod(mode | 0o111)  # Add execute bit for user, group, others
            logger.debug(f"Set executable permissions on {local_upx}")
        except Exception as e:
            logger.warning(f"Failed to set execute permission on {local_upx}: {e}")

        try:
            logger.debug(f"Testing UPX execution: {local_upx} --version")
            result = subprocess.run([str(local_upx), '--version'],
                                  capture_output=True, text=True, timeout=10)
            logger.debug(f"UPX version check result: return_code={result.returncode}")

            if result.returncode == 0:
                logger.info(f"✓ UPX validated at: {local_upx}")
                return str(local_upx)
            else:
                logger.warning(f"UPX found but failed version check: {result.stderr}")
        except subprocess.TimeoutExpired:
            logger.error(f"UPX version check timed out for {local_upx}")
        except Exception as e:
            logger.error(f"Failed to run UPX at {local_upx}: {e}")

    # Try custom path if provided
    if custom_path:
        logger.info(f"Checking custom UPX path: {custom_path}")
        try:
            result = subprocess.run([custom_path, '--version'],
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logger.info(f"✓ UPX found at custom path: {custom_path}")
                return custom_path
            else:
                logger.warning(f"Custom UPX path failed version check: {result.stderr}")
        except Exception as e:
            logger.warning(f"UPX not found at specified path {custom_path}: {e}")

    # Check environment variable
    upx_env_path = os.environ.get("UPX_PATH")
    if upx_env_path:
        logger.info(f"Checking UPX_PATH environment variable: {upx_env_path}")
        try:
            result = subprocess.run([upx_env_path, '--version'],
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logger.info(f"✓ UPX found via environment: {upx_env_path}")
                return upx_env_path
            else:
                logger.warning(f"UPX_PATH failed version check: {result.stderr}")
        except Exception as e:
            logger.warning(f"UPX_PATH check failed: {e}")

    # Try common executable names in current directory
    upx_names = ['upx', 'upx.exe', 'upx-linux', 'upx-mac']
    logger.debug(f"Checking UPX variants: {upx_names}")

    for name in upx_names:
        try:
            path = os.path.join(current_dir, name)
            logger.debug(f"Checking: {path}")

            if os.path.isfile(path):
                logger.debug(f"Found file: {path}")
                # Try to make executable
                try:
                    os.chmod(path, os.stat(path).st_mode | 0o111)
                    logger.debug(f"Set permissions on {path}")
                except Exception as e:
                    logger.debug(f"Could not set permissions on {path}: {e}")

                result = subprocess.run([path, '--version'],
                                      capture_output=True, text=True, timeout=10)
                logger.debug(f"{name} version check: return_code={result.returncode}")

                if result.returncode == 0:
                    logger.info(f"✓ UPX found as {name}")
                    return path
        except Exception as e:
            logger.debug(f"Error checking {name}: {e}")

    # Try system PATH
    logger.debug("Checking system PATH for UPX")
    try:
        result = subprocess.run(['upx', '--version'],
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            logger.info("✓ UPX found in system PATH")
            return 'upx'
    except Exception as e:
        logger.debug(f"System PATH UPX check failed: {e}")

    logger.error("✗ UPX is not installed or not found in PATH")
    logger.info("Please install UPX from: https://upx.github.io/")
    return None

def compress_file_with_upx(input_file, output_file, upx_path, compression_level=8):
    """
    Attempt to compress a file using UPX.
    """
    logger = logging.getLogger()
    logger.info(f"Starting compression of {input_file.name}")
    logger.debug(f"Input: {input_file} ({input_file.stat().st_size} bytes)")
    logger.debug(f"Output: {output_file}")
    logger.debug(f"UPX path: {upx_path}")
    logger.debug(f"Compression level: {compression_level}")

    try:
        # Create a temporary copy for UPX to work with
        temp_file = output_file.with_suffix('.tmp')
        logger.debug(f"Creating temporary file: {temp_file}")

        shutil.copy2(input_file, temp_file)
        logger.debug(f"Copied to temporary file ({temp_file.stat().st_size} bytes)")

        # UPX command with compression level
        if compression_level == 'best':
            cmd = [upx_path, '--best', '--lzma', str(temp_file)]
        else:
            cmd = [upx_path, f'-{compression_level}', str(temp_file)]

        logger.info(f"Running UPX: {' '.join(cmd)}")

        # Run UPX compression
        start_time = datetime.datetime.now()
        result = subprocess.run(cmd,
                              capture_output=True,
                              text=True,
                              timeout=300)  # 5 minute timeout
        end_time = datetime.datetime.now()

        logger.debug(f"UPX execution time: {end_time - start_time}")
        logger.debug(f"UPX return code: {result.returncode}")
        logger.debug(f"UPX stdout: {result.stdout}")
        if result.stderr:
            logger.debug(f"UPX stderr: {result.stderr}")

        if result.returncode == 0:
            # Move the compressed file to final location
            logger.debug(f"Moving compressed file: {temp_file} -> {output_file}")
            shutil.move(temp_file, output_file)

            # Check if compression was successful
            if "Packed 1 file" in result.stdout:
                # Log compression results
                original_size = input_file.stat().st_size
                compressed_size = output_file.stat().st_size
                ratio = (1 - compressed_size/original_size) * 100 if original_size > 0 else 0

                logger.info(f"✓ Compression successful: {original_size} -> {compressed_size} bytes ({ratio:.1f}% saved)")

                # Extract details from UPX output
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if '->' in line and '%' in line:
                        logger.info(f"UPX result: {line.strip()}")
                        break

                print(f"Compressed {input_file.name}: {original_size} -> {compressed_size} bytes ({ratio:.1f}% saved)")
                return True
            else:
                logger.warning(f"File processed but compression unclear")
                logger.warning(f"UPX stdout: {result.stdout}")
                return False
        else:
            logger.error(f"UPX compression failed with return code {result.returncode}")
            logger.error(f"UPX stderr: {result.stderr}")
            raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)

    except subprocess.CalledProcessError as e:
        logger.error(f"UPX compression failed for {input_file.name}")
        logger.error(f"Command: {' '.join(e.cmd)}")
        logger.error(f"Return code: {e.returncode}")
        logger.error(f"Stderr: {e.stderr}")

        # Clean up temp file if it exists
        if temp_file.exists():
            temp_file.unlink()
            logger.debug(f"Cleaned up temp file: {temp_file}")

        # Fall back to copying the original file
        logger.info("Falling back to file copy without compression")
        shutil.copy2(input_file, output_file)
        logger.info(f"✓ Copied {input_file.name} without compression")
        print(f"Copied {input_file.name} without compression (UPX failed)")
        return False

    except subprocess.TimeoutExpired as e:
        logger.error(f"UPX compression timed out for {input_file.name}")
        logger.error(f"Command: {' '.join(e.cmd)}")

        # Kill the process and clean up
        if temp_file.exists():
            temp_file.unlink()
            logger.debug(f"Cleaned up temp file after timeout: {temp_file}")

        # Fall back to copying the original file
        logger.info("Falling back to file copy after timeout")
        shutil.copy2(input_file, output_file)
        logger.info(f"✓ Copied {input_file.name} without compression (timeout)")
        print(f"Copied {input_file.name} without compression (timeout)")
        return False

    except Exception as e:
        logger.error(f"Unexpected error compressing {input_file.name}: {str(e)}")
        logger.error(f"Exception type: {type(e).__name__}")
        logger.error(f"Exception traceback: {traceback.format_exc()}")

        # Fall back to copying the original file
        if not output_file.exists():
            try:
                logger.info("Attempting emergency file copy")
                shutil.copy2(input_file, output_file)
                logger.info(f"✓ Emergency copy successful")
                print(f"Copied {input_file.name} without compression (error fallback)")
            except Exception as copy_error:
                logger.error(f"Failed to copy file as fallback: {copy_error}")
                return False

        return False

def main():
    """Main function to compress a file with UPX."""
    parser = argparse.ArgumentParser(description='UPX Packer with Activity Logging')
    parser.add_argument('input_file', help='Input file to compress')
    parser.add_argument('output_file', help='Output path for the compressed file')
    parser.add_argument('-c', '--compression', default=8,
                       help='Compression level (1-9 or "best", default: 8)')
    parser.add_argument('--overwrite', action='store_true',
                       help='Overwrite existing output file')
    parser.add_argument('--upx-path', help='Path to UPX executable')

    args = parser.parse_args()

    # Set up activity logging
    log_file = setup_activity_logging()
    logger = logging.getLogger()

    print("UPX Packer with Activity Logging")
    print(f"Log file: {log_file}")

    logger.info("=== ARGUMENT VALIDATION ===")
    logger.info(f"Input file: {args.input_file}")
    logger.info(f"Output file: {args.output_file}")
    logger.info(f"Compression: {args.compression}")
    logger.info(f"Overwrite: {args.overwrite}")
    logger.info(f"UPX path: {args.upx_path or 'auto-detect'}")

    # Check if input file exists
    input_path = Path(args.input_file)
    logger.info(f"Validating input file: {input_path}")

    if not input_path.exists() or not input_path.is_file():
        logger.error(f"Input file does not exist or is not a file: {args.input_file}")
        print(f"ERROR: Input file not found: {args.input_file}")
        sys.exit(1)

    logger.info(f"✓ Input file validated ({input_path.stat().st_size} bytes)")

    # Check if output file already exists
    output_path = Path(args.output_file)
    logger.info(f"Checking output path: {output_path}")

    if output_path.exists() and not args.overwrite:
        logger.error(f"Output file already exists: {args.output_file}")
        print(f"ERROR: Output file exists: {args.output_file} (use --overwrite)")
        sys.exit(1)

    # Create output directory if it doesn't exist
    output_path.parent.mkdir(parents=True, exist_ok=True)
    logger.debug(f"Output directory prepared: {output_path.parent}")

    logger.info("=== UPX DETECTION ===")

    # Check if UPX is available
    upx_path = check_upx_available(args.upx_path)
    if not upx_path:
        logger.warning("UPX not found, will copy file without compression")
        print("UPX not found, copying file without compression")

        # Just copy the file
        try:
            logger.info(f"Copying file: {input_path} -> {output_path}")
            shutil.copy2(input_path, output_path)
            logger.info(f"✓ File copied successfully")
            print(f"Copied {input_path.name} (UPX not available)")
        except Exception as e:
            logger.error(f"Failed to copy file: {e}")
            print(f"ERROR: Failed to copy file: {e}")
            sys.exit(1)

        logger.info("=== SESSION COMPLETED (NO COMPRESSION) ===")
        print(f"Log file: {log_file}")
        sys.exit(0)

    logger.info("=== COMPRESSION SETTINGS ===")

    # Validate compression level
    compression_level = args.compression
    if compression_level != 'best':
        try:
            compression_level = int(compression_level)
            if not 1 <= compression_level <= 9:
                raise ValueError()
            logger.info(f"Using compression level: {compression_level}")
        except ValueError:
            logger.error("Invalid compression level - must be 1-9 or 'best'")
            print("ERROR: Compression level must be 1-9 or 'best'")
            sys.exit(1)
    else:
        logger.info("Using best compression level")

    logger.info("=== COMPRESSION PROCESS ===")

    # Process file
    logger.info(f"Processing file: {input_path.name}")
    print(f"Compressing: {input_path.name}")

    compression_start = datetime.datetime.now()
    success = compress_file_with_upx(input_path, output_path, upx_path, compression_level)
    compression_end = datetime.datetime.now()

    logger.info(f"Total processing time: {compression_end - compression_start}")

    # Final verification
    if output_path.exists():
        final_size = output_path.stat().st_size
        logger.info(f"Output file created: {output_path} ({final_size} bytes)")

        if success:
            logger.info("=== COMPRESSION SUCCESSFUL ===")
            print(f"SUCCESS: Compressed file saved to {output_path}")
        else:
            logger.info("=== COMPRESSION FAILED (FILE COPIED) ===")
            print(f"PARTIAL SUCCESS: File copied (compression failed)")
    else:
        logger.error("CRITICAL ERROR: Output file was not created")
        print("ERROR: Output file was not created")
        sys.exit(1)

    logger.info(f"Session log saved to: {log_file}")
    print(f"Activity log: {log_file}")
    sys.exit(0)

if __name__ == "__main__":
    main()
