#!/usr/bin/env python3

"""
Wrappe Packer with Activity Logging

Uses Wrappe for creating self-contained single-binary applications.
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
import platform

def setup_activity_logging(script_name="wrappe_packer"):
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
    logger.info("=== WRAPPE PACKER SESSION STARTED ===")
    logger.info(f"Activity log file: {log_file}")
    logger.info(f"Timestamp: {datetime.datetime.now()}")
    logger.info(f"Working directory: {os.getcwd()}")
    logger.info(f"Command line: {' '.join(sys.argv)}")
    logger.info(f"Platform: {platform.system()} {platform.machine()}")
    
    return log_file

def check_wrappe_available(custom_path=None):
    """Check if Wrappe is available in the system PATH or at a specified path."""
    logger = logging.getLogger()
    logger.info("Starting Wrappe availability check")
    
    # Log current directory for debugging
    current_dir = os.getcwd()
    logger.debug(f"Current directory: {current_dir}")
    
    # First try Wrappe in current directory (most common case)
    local_wrappe = Path('./wrappe')
    logger.debug(f"Checking for local Wrappe at: {local_wrappe}")
    
    if local_wrappe.exists():
        logger.info(f"Found Wrappe file at: {local_wrappe}")
        
        # Ensure executable permission
        try:
            mode = local_wrappe.stat().st_mode
            local_wrappe.chmod(mode | 0o111)  # Add execute bit
            logger.debug(f"Set executable permissions on {local_wrappe}")
        except Exception as e:
            logger.warning(f"Failed to set execute permission on {local_wrappe}: {e}")
        
        try:
            logger.debug(f"Testing Wrappe execution: {local_wrappe} --version")
            result = subprocess.run([str(local_wrappe), '--version'], 
                                  capture_output=True, text=True, timeout=10)
            logger.debug(f"Wrappe version check result: return_code={result.returncode}")
            
            if result.returncode == 0:
                logger.info(f"✓ Wrappe validated at: {local_wrappe}")
                return str(local_wrappe)
            else:
                logger.warning(f"Wrappe found but failed version check: {result.stderr}")
        except subprocess.TimeoutExpired:
            logger.error(f"Wrappe version check timed out for {local_wrappe}")
        except Exception as e:
            logger.error(f"Failed to run Wrappe at {local_wrappe}: {e}")
    
    # Try custom path if provided
    if custom_path:
        logger.info(f"Checking custom Wrappe path: {custom_path}")
        try:
            result = subprocess.run([custom_path, '--version'],
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logger.info(f"✓ Wrappe found at custom path: {custom_path}")
                return custom_path
            else:
                logger.warning(f"Custom Wrappe path failed version check: {result.stderr}")
        except Exception as e:
            logger.warning(f"Wrappe not found at specified path {custom_path}: {e}")
    
    # Check environment variable
    wrappe_env_path = os.environ.get("WRAPPE_PATH")
    if wrappe_env_path:
        logger.info(f"Checking WRAPPE_PATH environment variable: {wrappe_env_path}")
        try:
            result = subprocess.run([wrappe_env_path, '--version'],
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logger.info(f"✓ Wrappe found via environment: {wrappe_env_path}")
                return wrappe_env_path
            else:
                logger.warning(f"WRAPPE_PATH failed version check: {result.stderr}")
        except Exception as e:
            logger.warning(f"WRAPPE_PATH check failed: {e}")
    
    # Try common executable names in current directory
    wrappe_names = ['wrappe', 'wrappe.exe']
    logger.debug(f"Checking Wrappe variants: {wrappe_names}")
    
    for name in wrappe_names:
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
                    logger.info(f"✓ Wrappe found as {name}")
                    return path
        except Exception as e:
            logger.debug(f"Error checking {name}: {e}")
    
    # Try system PATH
    logger.debug("Checking system PATH for Wrappe")
    try:
        result = subprocess.run(['wrappe', '--version'],
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            logger.info("✓ Wrappe found in system PATH")
            return 'wrappe'
    except Exception as e:
        logger.debug(f"System PATH Wrappe check failed: {e}")
    
    logger.error("✗ Wrappe is not installed or not found in PATH")
    logger.info("Please install Wrappe from: https://github.com/Systemcluster/wrappe")
    return None

def prepare_input_for_wrappe(input_file):
    """
    Prepare input for Wrappe packing.
    Creates a temporary directory structure since Wrappe works with directories.
    """
    logger = logging.getLogger()
    input_path = Path(input_file)
    
    if not input_path.exists():
        raise FileNotFoundError(f"Input file does not exist: {input_file}")
    
    if input_path.is_file():
        logger.info(f"Input is a single file, creating directory structure")
        
        # Create temporary directory
        temp_dir = Path.cwd() / f"wrappe_temp_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        temp_dir.mkdir(exist_ok=True)
        
        # Copy the file to temp directory
        dest_file = temp_dir / input_path.name
        shutil.copy2(input_path, dest_file)
        
        logger.info(f"Created temporary directory: {temp_dir}")
        logger.info(f"Copied file: {input_path} -> {dest_file}")
        
        return temp_dir, input_path.name, True  # True indicates temp dir was created
    
    elif input_path.is_dir():
        logger.info(f"Input is already a directory, using as-is")
        
        # Find the main executable in the directory
        # Look for common executable patterns
        exe_patterns = ['*.exe', '*.app', '*']
        main_exe = None
        
        for pattern in exe_patterns:
            for exe_file in input_path.glob(pattern):
                if exe_file.is_file() and os.access(exe_file, os.X_OK):
                    main_exe = exe_file.name
                    logger.info(f"Found executable: {main_exe}")
                    break
            if main_exe:
                break
        
        if not main_exe:
            # If no executable found, use the first .exe file or ask user
            exe_files = list(input_path.glob('*.exe'))
            if exe_files:
                main_exe = exe_files[0].name
                logger.info(f"Using first .exe file: {main_exe}")
            else:
                logger.error("No executable found in directory")
                raise FileNotFoundError("No executable found in directory")
        
        return input_path, main_exe, False  # False indicates no temp dir was created
    
    else:
        raise FileNotFoundError(f"Input path is neither file nor directory: {input_file}")

def pack_with_wrappe(input_dir, command_path, output_file, wrappe_path, compression_level=8):
    """
    Pack a directory using Wrappe.
    
    Args:
        input_dir: Path to input directory
        command_path: Path to executable to launch (relative to input_dir)
        output_file: Output executable path
        wrappe_path: Path to wrappe executable
        compression_level: Zstd compression level (0-22)
    """
    logger = logging.getLogger()
    logger.info(f"Starting Wrappe packing of {input_dir}")
    logger.debug(f"Input: {input_dir}")
    logger.debug(f"Command: {command_path}")
    logger.debug(f"Output: {output_file}")
    logger.debug(f"Wrappe path: {wrappe_path}")
    logger.debug(f"Compression level: {compression_level}")
    
    try:
        # Build wrappe command
        cmd = [wrappe_path, '--compression', str(compression_level), 
               str(input_dir), str(command_path), str(output_file)]
        
        logger.info(f"Running Wrappe: {' '.join(cmd)}")
        
        # Run Wrappe packing
        start_time = datetime.datetime.now()
        result = subprocess.run(cmd,
                              capture_output=True,
                              text=True,
                              timeout=600)  # 10 minute timeout
        end_time = datetime.datetime.now()
        
        logger.debug(f"Wrappe execution time: {end_time - start_time}")
        logger.debug(f"Wrappe return code: {result.returncode}")
        logger.debug(f"Wrappe stdout: {result.stdout}")
        
        if result.stderr:
            logger.debug(f"Wrappe stderr: {result.stderr}")
        
        if result.returncode == 0:
            # Check if output file was created
            if Path(output_file).exists():
                # Calculate compression ratio
                original_size = 0
                if Path(input_dir).is_dir():
                    for dirpath, dirnames, filenames in os.walk(input_dir):
                        for filename in filenames:
                            filepath = os.path.join(dirpath, filename)
                            try:
                                original_size += os.path.getsize(filepath)
                            except (OSError, FileNotFoundError):
                                pass
                else:
                    original_size = Path(input_dir).stat().st_size
                
                packed_size = Path(output_file).stat().st_size
                ratio = (1 - packed_size/original_size) * 100 if original_size > 0 else 0
                
                logger.info(f"✓ Packing successful: {original_size} -> {packed_size} bytes ({ratio:.1f}% saved)")
                
                # Log wrappe output details
                if result.stdout:
                    for line in result.stdout.strip().split('\n'):
                        if line.strip():
                            logger.info(f"Wrappe: {line.strip()}")
                
                print(f"Packed {Path(input_dir).name}: {original_size} -> {packed_size} bytes ({ratio:.1f}% saved)")
                return True
            else:
                logger.error("Wrappe reported success but output file not found")
                return False
        else:
            logger.error(f"Wrappe packing failed with return code {result.returncode}")
            logger.error(f"Wrappe stderr: {result.stderr}")
            raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)
    
    except subprocess.CalledProcessError as e:
        logger.error(f"Wrappe packing failed for {input_dir}")
        logger.error(f"Command: {' '.join(e.cmd)}")
        logger.error(f"Return code: {e.returncode}")
        logger.error(f"Stderr: {e.stderr}")
        
        # Try to provide helpful error messages
        if "No such file or directory" in str(e.stderr):
            logger.error("Make sure the input directory and command executable exist")
        elif "Permission denied" in str(e.stderr):
            logger.error("Check file permissions on input files and output directory")
        
        return False
    
    except subprocess.TimeoutExpired as e:
        logger.error(f"Wrappe packing timed out for {input_dir}")
        logger.error(f"Command: {' '.join(e.cmd)}")
        return False
    
    except Exception as e:
        logger.error(f"Unexpected error packing {input_dir}: {str(e)}")
        logger.error(f"Exception type: {type(e).__name__}")
        logger.error(f"Exception traceback: {traceback.format_exc()}")
        return False

def main():
    """Main function to pack files/directories with Wrappe."""
    parser = argparse.ArgumentParser(description='Wrappe Packer with Activity Logging')
    parser.add_argument('input_file', help='Input file or directory to pack')
    parser.add_argument('output_file', help='Output path for the packed executable')
    parser.add_argument('-c', '--compression', type=int, default=8, choices=range(0, 23),
                       help='Zstd compression level (0-22, default: 8)')
    parser.add_argument('--overwrite', action='store_true',
                       help='Overwrite existing output file')
    parser.add_argument('--wrappe-path', help='Path to Wrappe executable')
    parser.add_argument('--keep-temp', action='store_true',
                       help='Keep temporary directories (for debugging)')
    
    args = parser.parse_args()
    
    # Set up activity logging
    log_file = setup_activity_logging()
    logger = logging.getLogger()
    
    print("Wrappe Packer with Activity Logging")
    print(f"Log file: {log_file}")
    
    logger.info("=== ARGUMENT VALIDATION ===")
    logger.info(f"Input file: {args.input_file}")
    logger.info(f"Output file: {args.output_file}")
    logger.info(f"Compression: {args.compression}")
    logger.info(f"Overwrite: {args.overwrite}")
    logger.info(f"Wrappe path: {args.wrappe_path or 'auto-detect'}")
    
    temp_dir_created = False
    temp_dir = None
    
    try:
        # Prepare input
        logger.info("=== INPUT PREPARATION ===")
        input_dir, command_rel, temp_dir_created = prepare_input_for_wrappe(args.input_file)
        
        if temp_dir_created:
            temp_dir = input_dir  # Mark for cleanup
        
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
        
        logger.info("=== WRAPPE DETECTION ===")
        
        # Check if Wrappe is available
        wrappe_path = check_wrappe_available(args.wrappe_path)
        if not wrappe_path:
            logger.warning("Wrappe not found, will copy file without packing")
            print("Wrappe not found, copying file without packing")
            
            # Just copy the original file
            try:
                input_path = Path(args.input_file)
                logger.info(f"Copying file: {input_path} -> {output_path}")
                shutil.copy2(input_path, output_path)
                logger.info("✓ File copied successfully")
                print(f"Copied {input_path.name} (Wrappe not available)")
            except Exception as e:
                logger.error(f"Failed to copy file: {e}")
                print(f"ERROR: Failed to copy file: {e}")
                sys.exit(1)
            
            logger.info("=== SESSION COMPLETED (NO PACKING) ===")
            print(f"Log file: {log_file}")
            sys.exit(0)
        
        logger.info("=== PACKING PROCESS ===")
        
        # Process directory/file
        logger.info(f"Processing: {input_dir}")
        print(f"Packing: {Path(args.input_file).name}")
        
        packing_start = datetime.datetime.now()
        success = pack_with_wrappe(input_dir, command_rel, output_path, wrappe_path, args.compression)
        packing_end = datetime.datetime.now()
        
        logger.info(f"Total processing time: {packing_end - packing_start}")
        
        # Final verification
        if output_path.exists():
            final_size = output_path.stat().st_size
            logger.info(f"Output file created: {output_path} ({final_size} bytes)")
            
            if success:
                logger.info("=== PACKING SUCCESSFUL ===")
                print(f"SUCCESS: Packed executable saved to {output_path}")
            else:
                logger.warning("=== PACKING COMPLETED WITH WARNINGS ===")
                print(f"COMPLETED: Packed executable saved to {output_path}")
        else:
            logger.error("CRITICAL ERROR: Output file was not created")
            print("ERROR: Output file was not created")
            sys.exit(1)
    
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        print(f"ERROR: {e}")
        sys.exit(1)
    
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        logger.error(f"Exception traceback: {traceback.format_exc()}")
        print(f"ERROR: {e}")
        sys.exit(1)
    
    finally:
        # Cleanup temporary directory if created and not in debug mode
        if temp_dir_created and temp_dir and temp_dir.exists() and not args.keep_temp:
            try:
                shutil.rmtree(temp_dir)
                logger.info(f"Cleaned up temporary directory: {temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to cleanup temporary directory {temp_dir}: {e}")
    
    logger.info(f"Session log saved to: {log_file}")
    print(f"Activity log: {log_file}")
    sys.exit(0)

if __name__ == "__main__":
    main()