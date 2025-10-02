#!/usr/bin/env python3
"""
Complete Linux PE Modification Orchestrator with Astral-PE Integration
Runs on Linux, processes Windows PE executables
Implements: Build → Astral-PE → Processing → Astral-PE → Packing → Astral-PE → Signing
"""

import os
import sys
import subprocess
import logging
import shutil
import traceback
from pathlib import Path
import datetime

def setup_logging():
    """Set up logging configuration."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"orchestrator_complete_{timestamp}.log"

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
    """Verify that a required script exists."""
    script_path = Path(script_name)
    return script_path.exists() and script_path.is_file(), str(script_path.resolve())

def run_astral_pe_mutation(input_dir, output_dir, phase_name="MUTATION"):
    """Run Astral-PE mutation phase."""
    logger = logging.getLogger(__name__)
    logger.info(f"=== {phase_name} PHASE (ASTRAL-PE) ===")

    try:
        # Use the minimal mutation script
        exists, script_path = verify_script_exists("mutate_script_complete.py")
        if not exists:
            logger.error("mutate_script_complete.py not found")
            # Fallback: copy files
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            for file_path in Path(input_dir).glob("*"):
                if file_path.is_file():
                    shutil.copy2(file_path, Path(output_dir) / file_path.name)
            return True

        # Run mutation script
        cmd = [sys.executable, script_path, str(input_dir), str(output_dir)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode == 0:
            logger.info(f"✓ {phase_name} completed successfully")
            return True
        else:
            logger.warning(f"{phase_name} had issues: {result.stderr}")
            return True  # Continue anyway

    except Exception as e:
        logger.error(f"{phase_name} error: {e}")
        # Fallback: copy files
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        for file_path in Path(input_dir).glob("*"):
            if file_path.is_file():
                shutil.copy2(file_path, Path(output_dir) / file_path.name)
        return True

def run_string_injection(input_dir, output_dir, source_dir):
    """Run string injection step."""
    logger = logging.getLogger(__name__)
    logger.info("=== STRING INJECTION PHASE ===")

    try:
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
                break

        if not script_path:
            logger.warning("No string injector found - copying without injection")
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            for file_path in Path(input_dir).glob("*"):
                if file_path.is_file():
                    shutil.copy2(file_path, Path(output_dir) / file_path.name)
            return True

        # Get files
        input_files = [f for f in Path(input_dir).glob("*") if f.is_file()]
        source_files = [f for f in Path(source_dir).glob("*") if f.is_file()]

        if not source_files:
            logger.warning("No source files - copying without injection")
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            for input_file in input_files:
                shutil.copy2(input_file, Path(output_dir) / input_file.name)
            return True

        Path(output_dir).mkdir(parents=True, exist_ok=True)
        success_count = 0

        for input_file in input_files:
            output_file = Path(output_dir) / input_file.name
            injected = False

            # Try first few source files
            for source_file in source_files[:3]:
                try:
                    cmd = [
                        sys.executable, script_path,
                        str(source_file), str(input_file),
                        '--output', str(output_file),
                        '--max-strings', '15'
                    ]

                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

                    if result.returncode == 0 and output_file.exists():
                        logger.info(f"✓ Injected: {input_file.name}")
                        injected = True
                        success_count += 1
                        break

                except Exception:
                    continue

            if not injected:
                shutil.copy2(input_file, output_file)

        logger.info(f"String injection: {success_count}/{len(input_files)} successful")
        return True

    except Exception as e:
        logger.error(f"String injection error: {e}")
        return False

def run_code_cave_insertion(input_dir, output_dir, source_dir):
    """Run code cave insertion step."""
    logger = logging.getLogger(__name__)
    logger.info("=== CODE CAVE INSERTION PHASE ===")

    try:
        exists, script_path = verify_script_exists("code_cave_inserter.py")
        if not exists:
            logger.warning("code_cave_inserter.py not found - copying without insertion")
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            for file_path in Path(input_dir).glob("*"):
                if file_path.is_file():
                    shutil.copy2(file_path, Path(output_dir) / file_path.name)
            return True

        # Get files
        input_files = [f for f in Path(input_dir).glob("*") if f.is_file()]
        source_files = [f for f in Path(source_dir).glob("*") if f.is_file()]

        if not source_files:
            logger.warning("No source files - copying without insertion")
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            for input_file in input_files:
                shutil.copy2(input_file, Path(output_dir) / input_file.name)
            return True

        Path(output_dir).mkdir(parents=True, exist_ok=True)
        success_count = 0

        for input_file in input_files:
            output_file = Path(output_dir) / input_file.name
            inserted = False

            # Try first couple source files
            for source_file in source_files[:2]:
                try:
                    cmd = [
                        sys.executable, script_path,
                        str(input_file), str(source_file),
                        '--output', str(output_file)
                    ]

                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

                    if result.returncode == 0 and output_file.exists():
                        logger.info(f"✓ Inserted caves: {input_file.name}")
                        inserted = True
                        success_count += 1
                        break

                except Exception:
                    continue

            if not inserted:
                shutil.copy2(input_file, output_file)

        logger.info(f"Code cave insertion: {success_count}/{len(input_files)} successful")
        return True

    except Exception as e:
        logger.error(f"Code cave insertion error: {e}")
        return False

def run_packing(input_dir, output_dir, packer_type="upx"):
    """Run packing step."""
    logger = logging.getLogger(__name__)
    logger.info(f"=== {packer_type.upper()} PACKING PHASE ===")

    try:
        packer_script = f"{packer_type}_packer.py"
        exists, script_path = verify_script_exists(packer_script)

        if not exists:
            logger.warning(f"{packer_script} not found - copying without packing")
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            for file_path in Path(input_dir).glob("*"):
                if file_path.is_file():
                    shutil.copy2(file_path, Path(output_dir) / file_path.name)
            return True

        input_files = [f for f in Path(input_dir).glob("*") if f.is_file()]
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        success_count = 0

        for input_file in input_files:
            output_file = Path(output_dir) / input_file.name

            try:
                cmd = [
                    sys.executable, script_path,
                    str(input_file), str(output_file),
                    "--compression", "best",
                    "--overwrite"
                ]

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

                if result.returncode == 0 and output_file.exists():
                    logger.info(f"✓ Packed: {input_file.name}")
                    success_count += 1
                else:
                    shutil.copy2(input_file, output_file)

            except Exception:
                shutil.copy2(input_file, output_file)

        logger.info(f"Packing: {success_count}/{len(input_files)} successful")
        return True

    except Exception as e:
        logger.error(f"Packing error: {e}")
        return False

def run_signing(input_dir):
    """Run signing step with the fixed signing script."""
    logger = logging.getLogger(__name__)
    logger.info("=== SIGNING PHASE ===")

    try:
        # Try the fixed signing script first, then fallback to original
        signing_scripts = ["sign_script_fixed.py", "sign_script.py"]
        script_path = None

        for script in signing_scripts:
            exists, path = verify_script_exists(script)
            if exists:
                script_path = path
                logger.info(f"Using signing script: {script}")
                break

        if not script_path:
            logger.warning("No signing script found - skipping signing")
            return True

        cmd = [sys.executable, script_path, str(input_dir), "--verbose"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode == 0:
            logger.info("✓ Signing completed")
        else:
            logger.warning("Signing failed")

        return True

    except Exception as e:
        logger.error(f"Signing error: {e}")
        return True

def main():
    """
    Complete Linux PE Modification Orchestrator
    Usage: python orchestrator_complete.py target_dir source_dir [options]
    """

    # Simple argument parsing
    args = sys.argv[1:]
    if len(args) < 2:
        print("Usage: python orchestrator_complete.py target_dir source_dir [options]")
        print("Options:")
        print("  --output-dir DIR     Output directory (default: output_complete)")
        print("  --skip-strings       Skip string injection")
        print("  --skip-caves         Skip code cave insertion")
        print("  --skip-packing       Skip packing")
        print("  --skip-signing       Skip signing")
        print("  --skip-pre-mutation  Skip initial mutation")
        print("  --skip-mid-mutation  Skip pre-pack mutation")
        print("  --skip-post-mutation Skip final mutation")
        print("  --packer TYPE        Packer type (default: upx)")
        return 1

    target_dir = args[0]
    source_dir = args[1]

    # Parse options
    output_base = "output_complete"
    skip_strings = False
    skip_caves = False
    skip_packing = False
    skip_signing = False
    skip_pre_mutation = False
    skip_mid_mutation = False
    skip_post_mutation = False
    packer_type = "upx"

    i = 2
    while i < len(args):
        if args[i] == "--output-dir" and i + 1 < len(args):
            output_base = args[i + 1]
            i += 2
        elif args[i] == "--packer" and i + 1 < len(args):
            packer_type = args[i + 1]
            i += 2
        elif args[i] == "--skip-strings":
            skip_strings = True
            i += 1
        elif args[i] == "--skip-caves":
            skip_caves = True
            i += 1
        elif args[i] == "--skip-packing":
            skip_packing = True
            i += 1
        elif args[i] == "--skip-signing":
            skip_signing = True
            i += 1
        elif args[i] == "--skip-pre-mutation":
            skip_pre_mutation = True
            i += 1
        elif args[i] == "--skip-mid-mutation":
            skip_mid_mutation = True
            i += 1
        elif args[i] == "--skip-post-mutation":
            skip_post_mutation = True
            i += 1
        else:
            i += 1

    # Set up logging
    log_file = setup_logging()

    logging.info("=== COMPLETE LINUX PE MODIFICATION ORCHESTRATOR ===")
    logging.info("Workflow: Build → Astral-PE → Process → Astral-PE → Pack → Astral-PE → Sign")

    try:
        # Prepare directories
        output_base = Path(output_base).resolve()
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        working_dir = output_base / f"working_{timestamp}"
        after_pre_mutation_dir = output_base / f"after_pre_mutation_{timestamp}"
        after_strings_dir = output_base / f"after_strings_{timestamp}"
        after_caves_dir = output_base / f"after_caves_{timestamp}"
        after_mid_mutation_dir = output_base / f"after_mid_mutation_{timestamp}"
        after_packing_dir = output_base / f"after_packing_{timestamp}"
        after_post_mutation_dir = output_base / f"after_post_mutation_{timestamp}"
        final_dir = output_base / f"final_{timestamp}"

        # Create directories
        for directory in [output_base, working_dir, after_pre_mutation_dir, after_strings_dir,
                         after_caves_dir, after_mid_mutation_dir, after_packing_dir,
                         after_post_mutation_dir, final_dir]:
            directory.mkdir(parents=True, exist_ok=True)

        # Phase 0: Copy target files
        logging.info("=== PHASE 0: PREPARING TARGET FILES ===")
        for file_path in Path(target_dir).glob("*"):
            if file_path.is_file():
                shutil.copy2(file_path, working_dir / file_path.name)
                logging.info(f"✓ Prepared: {file_path.name}")

        current_dir = working_dir


        # Phase 4: Pre-packing Astral-PE mutation
        if not skip_mid_mutation:
            run_astral_pe_mutation(current_dir, after_mid_mutation_dir, "PRE-PACKING MUTATION")
            current_dir = after_mid_mutation_dir
        else:
            logging.info("Pre-packing mutation skipped")
            for file_path in current_dir.glob("*"):
                if file_path.is_file():
                    shutil.copy2(file_path, after_mid_mutation_dir / file_path.name)
            current_dir = after_mid_mutation_dir

        # Phase 5: Packing
        if not skip_packing:
            run_packing(current_dir, after_packing_dir, packer_type)
            current_dir = after_packing_dir
        else:
            logging.info("Packing skipped")
            for file_path in current_dir.glob("*"):
                if file_path.is_file():
                    shutil.copy2(file_path, after_packing_dir / file_path.name)
            current_dir = after_packing_dir

        # Phase 6: Final Astral-PE mutation
        if not skip_post_mutation:
            run_astral_pe_mutation(current_dir, after_post_mutation_dir, "POST-PACKING MUTATION")
            current_dir = after_post_mutation_dir
        else:
            logging.info("Post-packing mutation skipped")
            for file_path in current_dir.glob("*"):
                if file_path.is_file():
                    shutil.copy2(file_path, after_post_mutation_dir / file_path.name)
            current_dir = after_post_mutation_dir

        # Phase 7: Copy to final directory
        for file_path in current_dir.glob("*"):
            if file_path.is_file():
                shutil.copy2(file_path, final_dir / file_path.name)

        # Phase 8: Signing
        if not skip_signing:
            run_signing(final_dir)

        # Summary
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
