#!/usr/bin/env python3
"""
Simplified PE Mutation Script using Astral-PE
Removes unnecessary parameters and focuses on Astral-PE integration
"""

from pathlib import Path
import subprocess
import sys
import argparse
import logging
import os

def setup_logging(verbose=False):
    """Set up logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )

def mutate_with_astral_pe(input_file, output_file):
    """
    Mutate PE file using Astral-PE.exe
    """
    logger = logging.getLogger(__name__)

    if not Path(input_file).exists():
        logger.error(f"Input file does not exist: {input_file}")
        return False

    cmd = ["Astral-PE.exe", str(input_file), "-o", str(output_file)]

    try:
        logger.info(f"Running Astral-PE: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if result.returncode == 0:
            logger.info(f"Astral-PE mutation successful: {output_file}")
            if result.stdout:
                logger.debug(f"Astral-PE output: {result.stdout}")
            return True
        else:
            logger.error(f"Astral-PE mutation failed: {result.stderr}")
            return False

    except subprocess.TimeoutExpired:
        logger.error("Astral-PE process timed out")
        return False
    except FileNotFoundError:
        logger.error("Astral-PE.exe not found. Make sure it's in PATH or current directory")
        return False
    except Exception as e:
        logger.error(f"Astral-PE mutation error: {e}")
        return False

def mutate_single_file(input_path, output_path=None):
    """
    Mutate a single PE file using Astral-PE
    """
    logger = logging.getLogger(__name__)

    input_path = Path(input_path)

    if output_path is None:
        # Default output: <input>_ast.exe (following Astral-PE convention)
        output_path = input_path.with_stem(f"{input_path.stem}_ast")
    else:
        output_path = Path(output_path)

    logger.info(f"Mutating: {input_path} -> {output_path}")

    if mutate_with_astral_pe(input_path, output_path):
        logger.info(f"Successfully mutated: {output_path}")
        return True

    logger.error(f"Failed to mutate: {input_path}")
    return False

def mutate_directory(input_dir, output_dir=None, recursive=False):
    """
    Mutate all PE files in a directory using Astral-PE
    """
    logger = logging.getLogger(__name__)
    input_dir = Path(input_dir)

    if not input_dir.is_dir():
        logger.error(f"Input directory does not exist: {input_dir}")
        return False

    if output_dir is None:
        output_dir = input_dir / "mutated"
    else:
        output_dir = Path(output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)

    # Find PE files
    pattern = "**/*.exe" if recursive else "*.exe"
    pe_files = list(input_dir.glob(pattern))
    pe_files.extend(input_dir.glob(pattern.replace(".exe", ".dll")))

    if not pe_files:
        logger.warning(f"No PE files found in: {input_dir}")
        return True

    success_count = 0
    for pe_file in pe_files:
        output_file = output_dir / f"{pe_file.stem}_ast{pe_file.suffix}"
        if mutate_with_astral_pe(pe_file, output_file):
            success_count += 1

    logger.info(f"Successfully mutated {success_count}/{len(pe_files)} files")
    return success_count > 0

def main():
    parser = argparse.ArgumentParser(
        description="Mutate PE files using Astral-PE mutation engine"
    )
    parser.add_argument("input", help="Input PE file or directory")
    parser.add_argument("-o", "--output", help="Output file or directory")
    parser.add_argument("-r", "--recursive", action="store_true", 
                       help="Process directories recursively")
    parser.add_argument("-v", "--verbose", action="store_true", 
                       help="Enable verbose logging")

    args = parser.parse_args()

    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    input_path = Path(args.input)

    if input_path.is_file():
        success = mutate_single_file(input_path, args.output)
    elif input_path.is_dir():
        success = mutate_directory(input_path, args.output, args.recursive)
    else:
        logger.error(f"Input path does not exist: {input_path}")
        return 1

    if success:
        logger.info("Mutation process completed successfully")
        return 0
    else:
        logger.error("Mutation process failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
