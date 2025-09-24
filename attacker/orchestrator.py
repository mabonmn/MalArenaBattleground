"""
Fixed Orchestrator for PE Modification Pipeline
Calls the correct script names and handles all failure modes properly.
"""

import os
import sys
import argparse
import shutil
import subprocess
import logging
import traceback
from pathlib import Path
import datetime

def setup_logging():
    """Set up logging configuration."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"fixed_orchestrator_{timestamp}.log"

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return log_file

def verify_script_exists(script_name):
    """Verify that a required script exists in the current directory."""
    script_path = Path(script_name)
    if script_path.exists() and script_path.is_file():
        return True, str(script_path.resolve())

    # Check if bulletproof versions exist
    bulletproof_name = f"bulletproof_{script_name}"
    bulletproof_path = Path(bulletproof_name)
    if bulletproof_path.exists() and bulletproof_path.is_file():
        return True, str(bulletproof_path.resolve())

    return False, f"Script not found: {script_name}"

def verify_pe_integrity(pe_file):
    """Quick PE integrity check without crashing."""
    try:
        # Basic file validation first
        if not Path(pe_file).exists():
            return False, "File does not exist"

        if Path(pe_file).stat().st_size < 64:
            return False, "File too small"

        # Try to load with pefile if available
        try:
            import pefile
            pe = pefile.PE(pe_file)

            if not pe.sections:
                return False, "No sections"

            if hasattr(pe, 'FILE_HEADER') and hasattr(pe.FILE_HEADER, 'NumberOfSections'):
                if pe.FILE_HEADER.NumberOfSections != len(pe.sections):
                    return False, "Section count mismatch"

            return True, "Valid"

        except ImportError:
            # pefile not available, do basic check
            with open(pe_file, 'rb') as f:
                header = f.read(2)
                if header != b'MZ':
                    return False, "Invalid MZ header"
            return True, "Basic validation passed"

    except Exception as e:
        return False, f"Error: {str(e)}"

def run_string_injection_safe(input_dir, output_dir, source_dir):
    """Run string injection with proper script calling."""
    try:
        logging.info("=== STRING INJECTION PHASE ===")

        # Find the correct string injector script
        script_candidates = [
            "bulletproof_pe_string_injector.py",
            "pe_string_injector.py",
            "pe_string_injector.py"
        ]

        script_found = False
        script_path = None

        for candidate in script_candidates:
            exists, path = verify_script_exists(candidate)
            if exists:
                script_found = True
                script_path = path
                logging.info(f"Using string injector: {candidate}")
                break

        if not script_found:
            logging.error("No string injector script found")
            # Fallback: just copy files
            for file_path in Path(input_dir).glob("*"):
                if file_path.is_file():
                    shutil.copy2(file_path, output_dir / file_path.name)
            return True

        # Get files to process
        input_files = []
        for file_path in Path(input_dir).glob("*"):
            if file_path.is_file() and file_path.suffix.lower() in ['.exe', '.dll', '']:
                input_files.append(file_path)

        if not input_files:
            logging.warning("No executable files found")
            return False

        # Get source files
        source_files = []
        for file_path in Path(source_dir).glob("*"):
            if file_path.is_file() and file_path.suffix.lower() in ['.exe', '.dll', '']:
                source_files.append(file_path)

        if not source_files:
            logging.warning("No source files found - copying without injection")
            for input_file in input_files:
                shutil.copy2(input_file, output_dir / input_file.name)
            return True

        logging.info(f"Processing {len(input_files)} files with {len(source_files)} sources")

        success_count = 0
        failure_count = 0

        for input_file in input_files:
            output_file = output_dir / input_file.name

            # Verify input file
            is_valid, msg = verify_pe_integrity(input_file)
            if not is_valid:
                logging.warning(f"Skipping {input_file.name}: {msg}")
                shutil.copy2(input_file, output_file)
                failure_count += 1
                continue

            # Try injection with first available source
            injected = False
            for source_file in source_files[:3]:  # Limit to 3 attempts
                try:
                    # Build command properly
                    cmd = [
                        sys.executable, script_path,
                        str(source_file), str(input_file),
                        '--output', str(output_file),
                        '--max-strings', '15'
                    ]

                    logging.debug(f"Running: {' '.join(cmd)}")

                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=120,
                        cwd=Path.cwd()  # Explicit working directory
                    )

                    if result.returncode == 0:
                        # Verify output
                        if output_file.exists():
                            is_valid, msg = verify_pe_integrity(output_file)
                            if is_valid:
                                logging.info(f"✓ Injected strings into {input_file.name}")
                                injected = True
                                break
                            else:
                                logging.warning(f"Injection corrupted {input_file.name}: {msg}")
                                if output_file.exists():
                                    output_file.unlink()
                    else:
                        logging.debug(f"Injection failed for {input_file.name}: {result.stderr}")

                except subprocess.TimeoutExpired:
                    logging.warning(f"Injection timeout for {input_file.name}")
                    break
                except Exception as e:
                    logging.debug(f"Injection error: {e}")
                    continue

            if injected:
                success_count += 1
            else:
                # Copy original as fallback
                shutil.copy2(input_file, output_file)
                logging.info(f"Copied {input_file.name} without injection (fallback)")
                failure_count += 1

        total = success_count + failure_count
        logging.info(f"String injection completed: {success_count}/{total} successful")
        return True

    except Exception as e:
        logging.error(f"String injection phase error: {e}")
        traceback.print_exc()
        return False

def run_code_cave_insertion_safe(input_dir, output_dir, source_dir):
    """Run code cave insertion with proper script calling."""
    try:
        logging.info("=== CODE CAVE INSERTION PHASE ===")

        # Find the correct code cave script
        script_candidates = [
            "code_cave_inserter.py",
        ]

        script_found = False
        script_path = None

        for candidate in script_candidates:
            exists, path = verify_script_exists(candidate)
            if exists:
                script_found = True
                script_path = path
                logging.info(f"Using code cave inserter: {candidate}")
                break

        if not script_found:
            logging.error("No code cave inserter script found")
            # Fallback: just copy files
            for file_path in Path(input_dir).glob("*"):
                if file_path.is_file():
                    shutil.copy2(file_path, output_dir / file_path.name)
            return True

        # Get files to process
        input_files = []
        for file_path in Path(input_dir).glob("*"):
            if file_path.is_file() and file_path.suffix.lower() in ['.exe', '.dll', '']:
                input_files.append(file_path)

        if not input_files:
            logging.warning("No executable files found")
            return False

        # Get source files
        source_files = []
        for file_path in Path(source_dir).glob("*"):
            if file_path.is_file() and file_path.suffix.lower() in ['.exe', '.dll', '']:
                source_files.append(file_path)

        if not source_files:
            logging.warning("No source files found - copying without insertion")
            for input_file in input_files:
                shutil.copy2(input_file, output_dir / input_file.name)
            return True

        logging.info(f"Processing {len(input_files)} files with {len(source_files)} sources")

        success_count = 0
        failure_count = 0

        for input_file in input_files:
            output_file = output_dir / input_file.name

            # Verify input file
            is_valid, msg = verify_pe_integrity(input_file)
            if not is_valid:
                logging.warning(f"Skipping {input_file.name}: {msg}")
                shutil.copy2(input_file, output_file)
                failure_count += 1
                continue

            # Try insertion with first available source
            inserted = False
            for source_file in source_files[:2]:  # Limit to 2 attempts
                try:
                    # Build command properly - note argument order for code cave inserter
                    cmd = [
                        sys.executable, script_path,
                        str(input_file), str(source_file),  # target first, source second
                        '--output', str(output_file),
                    ]

                    logging.debug(f"Running: {' '.join(cmd)}")

                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=180,  # Longer timeout for code cave insertion
                        cwd=Path.cwd()
                    )

                    if result.returncode == 0:
                        # Verify output
                        if output_file.exists():
                            is_valid, msg = verify_pe_integrity(output_file)
                            if is_valid:
                                logging.info(f"✓ Inserted code caves into {input_file.name}")
                                inserted = True
                                break
                            else:
                                logging.warning(f"Insertion corrupted {input_file.name}: {msg}")
                                if output_file.exists():
                                    output_file.unlink()
                    else:
                        logging.debug(f"Insertion failed for {input_file.name}: {result.stderr}")

                except subprocess.TimeoutExpired:
                    logging.warning(f"Insertion timeout for {input_file.name}")
                    break
                except Exception as e:
                    logging.debug(f"Insertion error: {e}")
                    continue

            if inserted:
                success_count += 1
            else:
                # Copy original as fallback
                shutil.copy2(input_file, output_file)
                logging.info(f"Copied {input_file.name} without insertion (fallback)")
                failure_count += 1

        total = success_count + failure_count
        logging.info(f"Code cave insertion completed: {success_count}/{total} successful")
        return True

    except Exception as e:
        logging.error(f"Code cave insertion phase error: {e}")
        traceback.print_exc()
        return False


def run_wrappe_packing_safe(input_dir, output_dir, wrappe_path=None):
    """Run Wrappe packing by using the dedicated wrappe_packer.py script."""
    try:
        logging.info("=== WRAPPE PACKING PHASE ===")

        # Check for wrappe_packer script
        packer_candidates = [
            "wrappe_packer.py"
        ]

        packer_script = None
        for candidate in packer_candidates:
            if Path(candidate).exists() and Path(candidate).is_file():
                packer_script = str(Path(candidate).resolve())
                logging.info(f"Using packer script: {packer_script}")
                break

        if not packer_script:
            logging.error("Wrappe packer script not found - copying without compression")
            for file_path in Path(input_dir).glob("*"):
                if file_path.is_file():
                    shutil.copy2(file_path, output_dir / file_path.name)
            return True

        # Get files to process
        input_files = []
        for file_path in Path(input_dir).glob("*"):
            if file_path.is_file() and file_path.suffix.lower() in ['.exe', '.dll', '']:
                input_files.append(file_path)

        if not input_files:
            logging.warning("No executable files found")
            return False

        logging.info(f"Processing {len(input_files)} files for Wrappe packing")

        success_count = 0
        failure_count = 0

        for input_file in input_files:
            output_file = output_dir / input_file.name

            # Verify input file
            is_valid, msg = verify_pe_integrity(input_file)
            if not is_valid:
                logging.warning(f"Skipping {input_file.name}: {msg}")
                shutil.copy2(input_file, output_file)
                failure_count += 1
                continue

            try:
                # Build command for the packer script
                cmd = [
                    sys.executable,
                    packer_script,
                    str(input_file),
                    str(output_file),
                    "--compression", "8",
                    "--overwrite"
                ]

                # Add Wrappe path if specified
                if wrappe_path:
                    cmd.extend(["--wrappe-path", wrappe_path])

                logging.debug(f"Running: {' '.join(cmd)}")

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300
                )

                if result.returncode == 0 and output_file.exists():
                    # Verify output file
                    is_valid, _ = verify_pe_integrity(output_file)
                    if is_valid:
                        logging.info(f"✓ Packed {input_file.name}")
                        success_count += 1
                        continue

                # If we're here, something went wrong
                logging.warning(f"Packing failed for {input_file.name}")

                # Use the original if output doesn't exist or is invalid
                if not output_file.exists() or not is_valid:
                    shutil.copy2(input_file, output_file)
                    logging.info(f"Copied original file as fallback")
                failure_count += 1

            except subprocess.TimeoutExpired:
                logging.warning(f"Packing timeout for {input_file.name}")
                shutil.copy2(input_file, output_file)
                failure_count += 1

            except Exception as e:
                logging.warning(f"Packing error for {input_file.name}: {e}")
                shutil.copy2(input_file, output_file)
                failure_count += 1

        total = success_count + failure_count
        logging.info(f"Wrappe packing completed: {success_count}/{total} successful")
        return True

    except Exception as e:
        logging.error(f"Wrappe packing phase error: {e}")
        traceback.print_exc()
        return False

def run_upx_packing_safe(input_dir, output_dir, upx_path=None):
    """Run UPX packing by using the dedicated upx_packer.py script."""
    try:
        logging.info("=== UPX PACKING PHASE ===")

        # Check for upx_packer script
        packer_candidates = [
            "upx_packer.py"
        ]

        packer_script = None
        for candidate in packer_candidates:
            if Path(candidate).exists() and Path(candidate).is_file():
                packer_script = str(Path(candidate).resolve())
                logging.info(f"Using packer script: {packer_script}")
                break

        if not packer_script:
            logging.error("UPX packer script not found - copying without compression")
            for file_path in Path(input_dir).glob("*"):
                if file_path.is_file():
                    shutil.copy2(file_path, output_dir / file_path.name)
            return True

        # Get files to process
        input_files = []
        for file_path in Path(input_dir).glob("*"):
            if file_path.is_file() and file_path.suffix.lower() in ['.exe', '.dll', '']:
                input_files.append(file_path)

        if not input_files:
            logging.warning("No executable files found")
            return False

        logging.info(f"Processing {len(input_files)} files for UPX compression")

        success_count = 0
        failure_count = 0

        for input_file in input_files:
            output_file = output_dir / input_file.name

            # Verify input file
            is_valid, msg = verify_pe_integrity(input_file)
            if not is_valid:
                logging.warning(f"Skipping {input_file.name}: {msg}")
                shutil.copy2(input_file, output_file)
                failure_count += 1
                continue

            try:
                # Build command for the packer script
                cmd = [
                    sys.executable,
                    packer_script,
                    str(input_file),
                    str(output_file),
                    "--compression", "best",
                    "--overwrite"
                ]

                # Add UPX path if specified
                if upx_path:
                    cmd.extend(["--upx-path", upx_path])

                logging.debug(f"Running: {' '.join(cmd)}")

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300
                )

                if result.returncode == 0 and output_file.exists():
                    # Verify output file
                    is_valid, _ = verify_pe_integrity(output_file)
                    if is_valid:
                        logging.info(f"✓ Compressed {input_file.name}")
                        success_count += 1
                        continue

                # If we're here, something went wrong
                logging.warning(f"Packing failed for {input_file.name}")
                if "CantPackException" in result.stdout or "CantPackException" in result.stderr:
                    logging.warning(f"UPX reported: {result.stderr if result.stderr else result.stdout}")

                # Use the original if output doesn't exist or is invalid
                if not output_file.exists() or not is_valid:
                    shutil.copy2(input_file, output_file)
                    logging.info(f"Copied original file as fallback")
                failure_count += 1

            except subprocess.TimeoutExpired:
                logging.warning(f"Packing timeout for {input_file.name}")
                shutil.copy2(input_file, output_file)
                failure_count += 1

            except Exception as e:
                logging.warning(f"Packing error for {input_file.name}: {e}")
                shutil.copy2(input_file, output_file)
                failure_count += 1

        total = success_count + failure_count
        logging.info(f"UPX compression completed: {success_count}/{total} successful")
        return True

    except Exception as e:
        logging.error(f"UPX packing phase error: {e}")
        traceback.print_exc()
        return False

def main():
    """Fixed orchestrator main function."""
    parser = argparse.ArgumentParser(
        description='Fixed PE Modification Orchestrator'
    )

    parser.add_argument('target_dir', help='Directory with target PE files')
    parser.add_argument('source_dir', help='Directory with source PE files')
    parser.add_argument('--output-dir', default='output', help='Base output directory')
    parser.add_argument('--skip-strings', action='store_true', help='Skip string injection')
    parser.add_argument('--skip-caves', action='store_true', help='Skip code cave insertion')
    parser.add_argument('--skip-packing', action='store_true', help='Skip UPX packing')
    parser.add_argument('--upx-path', help='Path to UPX executable')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')

    args = parser.parse_args()

    # Set up logging
    log_file = setup_logging()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logging.info("=== FIXED PE MODIFICATION ORCHESTRATOR ===")
    logging.info("Properly calling scripts with correct names and arguments")

    try:
        # Prepare directories
        output_base = Path(args.output_dir).resolve()
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        working_dir = output_base / f"working_{timestamp}"
        strings_dir = output_base / f"strings_{timestamp}"
        caves_dir = output_base / f"caves_{timestamp}"
        final_dir = output_base / f"final_{timestamp}"

        for directory in [output_base, working_dir, strings_dir, caves_dir, final_dir]:
            directory.mkdir(parents=True, exist_ok=True)

        logging.info("Directory structure prepared")

        # Phase 0: Copy and verify target files
        logging.info("=== PHASE 0: PREPARING TARGET FILES ===")
        target_files = []

        for file_path in Path(args.target_dir).glob("*"):
            if file_path.is_file() and file_path.suffix.lower() in ['.exe', '.dll', '']:
                dest_file = working_dir / file_path.name
                shutil.copy2(file_path, dest_file)

                is_valid, msg = verify_pe_integrity(dest_file)
                if is_valid:
                    target_files.append(dest_file)
                    logging.info(f"✓ Prepared: {file_path.name}")
                else:
                    logging.warning(f"✗ Skipped invalid PE: {file_path.name} - {msg}")

        logging.info(f"Prepared {len(target_files)} valid PE files")

        if not target_files:
            logging.error("No valid PE files to process")
            return 1

        # Phase 1: String Injection
        if not args.skip_strings:
            success = run_string_injection_safe(working_dir, strings_dir, args.source_dir)
            if success:
                input_for_caves = strings_dir
            else:
                logging.warning("String injection failed - proceeding without")
                for file_path in working_dir.glob("*"):
                    if file_path.is_file():
                        shutil.copy2(file_path, strings_dir / file_path.name)
                input_for_caves = strings_dir
        else:
            logging.info("String injection skipped")
            for file_path in working_dir.glob("*"):
                if file_path.is_file():
                    shutil.copy2(file_path, strings_dir / file_path.name)
            input_for_caves = strings_dir

        # Phase 2: Code Cave Insertion
        if not args.skip_caves:
            success = run_code_cave_insertion_safe(input_for_caves, caves_dir, args.source_dir)
            if success:
                input_for_upx = caves_dir
            else:
                logging.warning("Code cave insertion failed - proceeding without")
                for file_path in input_for_caves.glob("*"):
                    if file_path.is_file():
                        shutil.copy2(file_path, caves_dir / file_path.name)
                input_for_upx = caves_dir
        else:
            logging.info("Code cave insertion skipped")
            for file_path in input_for_caves.glob("*"):
                if file_path.is_file():
                    shutil.copy2(file_path, caves_dir / file_path.name)
            input_for_upx = caves_dir

        # Phase 3: UPX Packing
        if not args.skip_packing:
            success = run_wrappe_packing_safe(input_for_upx, final_dir, args.upx_path)
        else:
            logging.info("UPX packing skipped")
            for file_path in input_for_upx.glob("*"):
                if file_path.is_file():
                    shutil.copy2(file_path, final_dir / file_path.name)

        # Final summary
        final_files = list(final_dir.glob("*"))
        logging.info("=== ORCHESTRATION COMPLETED ===")
        logging.info(f"Final output directory: {final_dir}")
        logging.info(f"Total output files: {len(final_files)}")
        logging.info(f"Log file: {log_file}")

        return 0

    except Exception as e:
        logging.error(f"Fatal orchestrator error: {e}")
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
