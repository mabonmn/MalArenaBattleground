"""
Orchestrator Version 3 - Mutates only at the end

This version uses metame to mutate PE files only once at the very end, before signing.
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
    log_file = f"orchestrator_v3_{timestamp}.log"
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
    return False, f"Script not found: {script_name}"


def run_mutation(input_dir, output_dir, mutation_level=5):
    """Run mutation on all files in input directory."""
    try:
        logging.info("=== MUTATION STEP ===")

        # Check if mutate script exists
        exists, mutate_script = verify_script_exists("mutate_script.py")
        if not exists:
            logging.error("mutate_script.py not found - copying without mutation")
            for file_path in Path(input_dir).glob("*"):
                if file_path.is_file():
                    shutil.copy2(file_path, Path(output_dir) / file_path.name)
            return True

        # Run mutation script
        cmd = [
            sys.executable, mutate_script,
            str(input_dir), str(output_dir),
            "--mutation-level", str(mutation_level),
            "--preserve-names",
            "--verbose"  # Add verbose flag to get more output
        ]

        logging.debug(f"Running: {' '.join(cmd)}")

        # FIXED: Don't capture stdout, allow it to flow through to console
        result = subprocess.run(
            cmd,
            text=True,
            timeout=300,
            stdout=None,  # Let stdout go to console (shows logging)
            stderr=subprocess.PIPE  # Only capture stderr for error handling
        )

        if result.returncode == 0:
            logging.info("✓ Mutation completed successfully")
            return True
        else:
            logging.warning(f"Mutation failed with return code {result.returncode}")
            if result.stderr:
                logging.warning(f"Mutation stderr: {result.stderr}")
            # Copy files without mutation as fallback
            for file_path in Path(input_dir).glob("*"):
                if file_path.is_file():
                    shutil.copy2(file_path, Path(output_dir) / file_path.name)
            return True

    except subprocess.TimeoutExpired:
        logging.error("Mutation timed out after 300 seconds")
        # Copy files without mutation as fallback
        for file_path in Path(input_dir).glob("*"):
            if file_path.is_file():
                shutil.copy2(file_path, Path(output_dir) / file_path.name)
        return True

    except Exception as e:
        logging.error(f"Mutation error: {e}")
        # Copy files without mutation as fallback
        for file_path in Path(input_dir).glob("*"):
            if file_path.is_file():
                shutil.copy2(file_path, Path(output_dir) / file_path.name)
        return True
def run_string_injection(input_dir, output_dir, source_dir):
    """Run string injection step."""
    try:
        logging.info("=== STRING INJECTION PHASE ===")

        # Find string injector script
        script_candidates = [
            "bulletproof_pe_string_injector.py",
            "pe_string_injector.py"
        ]

        script_path = None
        for candidate in script_candidates:
            exists, path = verify_script_exists(candidate)
            if exists:
                script_path = path
                logging.info(f"Using string injector: {candidate}")
                break

        if not script_path:
            logging.error("No string injector script found - copying without injection")
            for file_path in Path(input_dir).glob("*"):
                if file_path.is_file():
                    shutil.copy2(file_path, Path(output_dir) / file_path.name)
            return True

        # Get input and source files
        input_files = [f for f in Path(input_dir).glob("*")
                      if f.is_file() and f.suffix.lower() in ['.exe', '.dll', '']]
        source_files = [f for f in Path(source_dir).glob("*")
                       if f.is_file() and f.suffix.lower() in ['.exe', '.dll', '']]

        if not source_files:
            logging.warning("No source files found - copying without injection")
            for input_file in input_files:
                shutil.copy2(input_file, Path(output_dir) / input_file.name)
            return True

        Path(output_dir).mkdir(parents=True, exist_ok=True)
        success_count = 0

        for input_file in input_files:
            output_file = Path(output_dir) / input_file.name
            injected = False

            for source_file in source_files[:3]:  # Try up to 3 sources
                try:
                    cmd = [
                        sys.executable, script_path,
                        str(source_file), str(input_file),
                        '--output', str(output_file),
                        '--max-strings', '15'
                    ]

                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

                    if result.returncode == 0 and output_file.exists():
                        logging.info(f"✓ Injected strings into {input_file.name}")
                        injected = True
                        success_count += 1
                        break

                except Exception as e:
                    logging.debug(f"Injection error: {e}")
                    continue

            if not injected:
                shutil.copy2(input_file, output_file)
                logging.info(f"Copied {input_file.name} without injection (fallback)")

        logging.info(f"String injection completed: {success_count}/{len(input_files)} successful")
        return True

    except Exception as e:
        logging.error(f"String injection error: {e}")
        return False

def run_code_cave_insertion(input_dir, output_dir, source_dir):
    """Run code cave insertion step."""
    try:
        logging.info("=== CODE CAVE INSERTION PHASE ===")

        # Find code cave script
        exists, script_path = verify_script_exists("code_cave_inserter.py")
        if not exists:
            logging.error("code_cave_inserter.py not found - copying without insertion")
            for file_path in Path(input_dir).glob("*"):
                if file_path.is_file():
                    shutil.copy2(file_path, Path(output_dir) / file_path.name)
            return True

        # Get input and source files
        input_files = [f for f in Path(input_dir).glob("*")
                      if f.is_file() and f.suffix.lower() in ['.exe', '.dll', '']]
        source_files = [f for f in Path(source_dir).glob("*")
                       if f.is_file() and f.suffix.lower() in ['.exe', '.dll', '']]

        if not source_files:
            logging.warning("No source files found - copying without insertion")
            for input_file in input_files:
                shutil.copy2(input_file, Path(output_dir) / input_file.name)
            return True

        Path(output_dir).mkdir(parents=True, exist_ok=True)
        success_count = 0

        for input_file in input_files:
            output_file = Path(output_dir) / input_file.name
            inserted = False

            for source_file in source_files[:2]:  # Try up to 2 sources
                try:
                    cmd = [
                        sys.executable, script_path,
                        str(input_file), str(source_file),
                        '--output', str(output_file)
                    ]

                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

                    if result.returncode == 0 and output_file.exists():
                        logging.info(f"✓ Inserted code caves into {input_file.name}")
                        inserted = True
                        success_count += 1
                        break

                except Exception as e:
                    logging.debug(f"Insertion error: {e}")
                    continue

            if not inserted:
                shutil.copy2(input_file, output_file)
                logging.info(f"Copied {input_file.name} without insertion (fallback)")

        logging.info(f"Code cave insertion completed: {success_count}/{len(input_files)} successful")
        return True

    except Exception as e:
        logging.error(f"Code cave insertion error: {e}")
        return False

def run_packing(input_dir, output_dir, packer_type="upx"):
    """Run packing step."""
    try:
        logging.info(f"=== {packer_type.upper()} PACKING PHASE ===")

        # Find packer script
        packer_script = f"{packer_type}_packer.py"
        exists, script_path = verify_script_exists(packer_script)
        if not exists:
            logging.error(f"{packer_script} not found - copying without packing")
            for file_path in Path(input_dir).glob("*"):
                if file_path.is_file():
                    shutil.copy2(file_path, Path(output_dir) / file_path.name)
            return True

        # Get input files
        input_files = [f for f in Path(input_dir).glob("*")
                      if f.is_file() and f.suffix.lower() in ['.exe', '.dll', '']]

        Path(output_dir).mkdir(parents=True, exist_ok=True)
        success_count = 0

        for input_file in input_files:
            output_file = Path(output_dir) / input_file.name

            try:
                cmd = [
                    sys.executable, script_path,
                    str(input_file), str(output_file),
                    "--compression", "best" if packer_type == "upx" else "8",
                    "--overwrite"
                ]

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

                if result.returncode == 0 and output_file.exists():
                    logging.info(f"✓ Packed {input_file.name}")
                    success_count += 1
                else:
                    shutil.copy2(input_file, output_file)
                    logging.info(f"Copied {input_file.name} without packing (fallback)")

            except Exception as e:
                logging.debug(f"Packing error: {e}")
                shutil.copy2(input_file, output_file)

        logging.info(f"Packing completed: {success_count}/{len(input_files)} successful")
        return True

    except Exception as e:
        logging.error(f"Packing error: {e}")
        return False

def run_signing(input_dir):
    """Run signing step."""
    try:
        logging.info("=== SIGNING PHASE ===")

        # Find signing script
        exists, script_path = verify_script_exists("sign_script.py")
        if not exists:
            logging.error("sign_script.py not found - skipping signing")
            return True

        # Run signing script
        cmd = [
            sys.executable, script_path,
            str(input_dir),
            "--verbose"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode == 0:
            logging.info("✓ Signing completed successfully")
        else:
            logging.warning(f"Signing failed: {result.stderr}")

        return True

    except Exception as e:
        logging.error(f"Signing error: {e}")
        return True  # Non-critical, continue anyway


def run_picture_maker(input_dir, output_dir, source_dir):
    """Run picture maker script to embed files in bitmap images."""
    try:
        logging.info("=== PICTURE MAKER PHASE ===")

        # Find picture maker script
        exists, script_path = verify_script_exists("picture_maker.py")
        if not exists:
            logging.error("picture_maker.py not found - copying without steganography")
            for file_path in Path(input_dir).glob("*"):
                if file_path.is_file():
                    shutil.copy2(file_path, Path(output_dir) / file_path.name)
            return True

        # Get input files (PE files)
        input_files = [f for f in Path(input_dir).glob("*")
                      if f.is_file() and f.suffix.lower() in ['.exe', '.dll', '']]

        if not input_files:
            logging.warning("No PE files found for picture maker")
            return True

        Path(output_dir).mkdir(parents=True, exist_ok=True)
        success_count = 0

        for input_file in input_files:
            try:
                # Create bitmap with embedded file
                bitmap_name = f"{input_file.stem}.bmp"
                bitmap_path = Path(output_dir) / bitmap_name

                cmd = [
                    sys.executable, script_path,
                    str(input_file), str(source_dir),
                    '--output', str(bitmap_path),
                    '--key', '42'
                ]

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

                if result.returncode == 0 and bitmap_path.exists():
                    logging.info(f"✓ Created steganographic bitmap for {input_file.name}")
                    success_count += 1

                    # Also copy the original file
                    shutil.copy2(input_file, Path(output_dir) / input_file.name)
                else:
                    # Fallback: just copy the original file
                    shutil.copy2(input_file, Path(output_dir) / input_file.name)
                    logging.info(f"Copied {input_file.name} without steganography (fallback)")

            except Exception as e:
                logging.debug(f"Picture maker error for {input_file.name}: {e}")
                # Fallback: copy original file
                shutil.copy2(input_file, Path(output_dir) / input_file.name)

        logging.info(f"Picture maker completed: {success_count}/{len(input_files)} successful")
        return True

    except Exception as e:
        logging.error(f"Picture maker error: {e}")
        return False


def main():
    """Main orchestrator function - Version 3: Mutate only at the end."""
    parser = argparse.ArgumentParser(
        description='PE Modification Orchestrator v3 - Mutates only at the end before signing'
    )
    parser.add_argument('target_dir', help='Directory with target PE files')
    parser.add_argument('source_dir', help='Directory with source PE files')
    parser.add_argument('--output-dir', default='output_v3', help='Base output directory')
    parser.add_argument('--mutation-level', type=int, default=5, help='Mutation level (1-10)')
    parser.add_argument('--skip-strings', action='store_true', help='Skip string injection')
    parser.add_argument('--skip-caves', action='store_true', help='Skip code cave insertion')
    parser.add_argument('--skip-packing', action='store_true', help='Skip packing')
    parser.add_argument('--skip-pictures', action='store_true', help='Skip picture maker steganography')
    parser.add_argument('--skip-signing', action='store_true', help='Skip signing')
    parser.add_argument('--skip-mutation', action='store_true', help='Skip final mutation')
    parser.add_argument('--packer', choices=['upx', 'wrappe'], default='upx', help='Packer to use')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')

    args = parser.parse_args()

    # Set up logging
    log_file = setup_logging()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logging.info("=== PE MODIFICATION ORCHESTRATOR V3 ===")
    logging.info("Strategy: Mutate only at the end before signing")

    try:
        # Prepare directories
        output_base = Path(args.output_dir).resolve()
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create working directories
        working_dir = output_base / f"working_{timestamp}"
        after_strings_dir = output_base / f"after_strings_{timestamp}"
        after_caves_dir = output_base / f"after_caves_{timestamp}"
        after_pictures_dir = output_base / f"after_pictures_{timestamp}"
        after_packing_dir = output_base / f"after_packing_{timestamp}"
        mutated_final_dir = output_base / f"mutated_final_{timestamp}"
        final_dir = output_base / f"final_{timestamp}"

        for directory in [output_base, working_dir, after_strings_dir, after_caves_dir,
                         after_packing_dir, mutated_final_dir, final_dir]:
            directory.mkdir(parents=True, exist_ok=True)

        # Phase 0: Copy target files
        logging.info("=== PHASE 0: PREPARING TARGET FILES ===")
        for file_path in Path(args.target_dir).glob("*"):
            if file_path.is_file():
                shutil.copy2(file_path, working_dir / file_path.name)
                logging.info(f"✓ Prepared: {file_path.name}")

        current_dir = working_dir

        # Phase 1: String Injection (no mutation)
        # if not args.skip_strings:
        #     run_string_injection(current_dir, after_strings_dir, args.source_dir)
        #     current_dir = after_strings_dir
        # else:
        #     logging.info("String injection skipped")
        #     for file_path in current_dir.glob("*"):
        #         if file_path.is_file():
        #             shutil.copy2(file_path, after_strings_dir / file_path.name)
        #     current_dir = after_strings_dir
        #
        # # Phase 2: Code Cave Insertion (no mutation)
        # if not args.skip_caves:
        #     run_code_cave_insertion(current_dir, after_caves_dir, args.source_dir)
        #     current_dir = after_caves_dir
        # else:
        #     logging.info("Code cave insertion skipped")
        #     for file_path in current_dir.glob("*"):
        #         if file_path.is_file():
        #             shutil.copy2(file_path, after_caves_dir / file_path.name)
        #     current_dir = after_caves_dir

                # Phase 3: Picture Maker (steganography)
        if not args.skip_pictures:
            run_picture_maker(current_dir, after_pictures_dir, args.source_dir)
            current_dir = after_pictures_dir
        else:
            logging.info("Picture maker skipped")
            for file_path in current_dir.glob("*"):
                if file_path.is_file():
                    shutil.copy2(file_path, after_pictures_dir / file_path.name)
            current_dir = after_pictures_dir

        # Phase 4: Packing (no mutation)
        # if not args.skip_packing:
        #     run_packing(current_dir, after_packing_dir, args.packer)
        #     current_dir = after_packing_dir
        # else:
        #     logging.info("Packing skipped")
        #     for file_path in current_dir.glob("*"):
        #         if file_path.is_file():
        #             shutil.copy2(file_path, after_packing_dir / file_path.name)
        #     current_dir = after_packing_dir
        #
        # # Phase 5: Final Mutation (if not skipped)
        # if not args.skip_mutation:
        #     run_mutation(current_dir, mutated_final_dir, args.mutation_level)
        #     current_dir = mutated_final_dir
        # else:
        #     logging.info("Final mutation skipped")
        #     for file_path in current_dir.glob("*"):
        #         if file_path.is_file():
        #             shutil.copy2(file_path, mutated_final_dir / file_path.name)
        #     current_dir = mutated_final_dir

        # Final: Copy to final directory and sign
        for file_path in current_dir.glob("*"):
            if file_path.is_file():
                shutil.copy2(file_path, final_dir / file_path.name)

        # Phase 5: Signing (absolute final step)
        if not args.skip_signing:
            run_signing(final_dir)

        # Summary
        final_files = list(final_dir.glob("*"))
        logging.info("=== ORCHESTRATION V3 COMPLETED ===")
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
