#!/usr/bin/env python3
"""
Minimal Linux PE Mutation Script using Astral-PE
Runs on Linux, mutates Windows PE executables
Simplified for orchestrator integration with minimal arguments
"""

import os
import sys
import subprocess
import logging
from pathlib import Path
import shutil

def setup_logging():
    """Set up simple logging."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(levelname)s: %(message)s'
    )

def find_astral_pe():
    """Find Astral-PE binary on Linux."""
    # Try common locations for Linux binary
    candidates = [
        "./Astral-PE",           # Current directory
        "./astral-pe",           # Current directory lowercase
        "Astral-PE",             # PATH
        "astral-pe",             # PATH lowercase
        "/usr/local/bin/Astral-PE",
        "/opt/astral-pe/Astral-PE"
    ]

    for candidate in candidates:
        try:
            # Test if binary exists and is executable
            result = subprocess.run([candidate], capture_output=True, timeout=3)
            # Astral-PE will return non-zero without args, but won't be "command not found"
            return candidate
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            continue

    return None

def mutate_pe_file(input_file, output_file, astral_pe_path):
    """Mutate single PE file using Astral-PE."""
    logger = logging.getLogger(__name__)

    cmd = [astral_pe_path, str(input_file), "-o", str(output_file)]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode == 0 and Path(output_file).exists():
            logger.info(f"Mutated: {Path(input_file).name}")
            return True
        else:
            logger.warning(f"Failed to mutate: {Path(input_file).name}")
            return False

    except subprocess.TimeoutExpired:
        logger.error(f"Timeout mutating: {Path(input_file).name}")
        return False
    except Exception as e:
        logger.error(f"Error mutating {Path(input_file).name}: {e}")
        return False

def mutate_directory(input_dir, output_dir):
    """
    Main mutation function - mutate all PE files in directory.
    Compatible with orchestrator API expectations.
    """
    logger = logging.getLogger(__name__)

    # Validate input
    input_path = Path(input_dir)
    if not input_path.is_dir():
        logger.error(f"Input directory not found: {input_dir}")
        return False

    # Create output directory
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Find Astral-PE binary
    astral_pe = find_astral_pe()
    if not astral_pe:
        logger.error("Astral-PE binary not found")
        logger.info("Download Linux x64 from: https://github.com/DosX-dev/Astral-PE/releases")
        logger.info("Place as 'Astral-PE' in current directory and chmod +x Astral-PE")

        # Fallback: copy files without mutation
        for file_path in input_path.glob("*"):
            if file_path.is_file():
                shutil.copy2(file_path, output_path / file_path.name)
        return True

    logger.info(f"Using Astral-PE: {astral_pe}")

    # Find PE files (Windows executables on Linux)
    pe_files = []
    for file_path in input_path.glob("*"):
        if file_path.is_file():
            # Include files that are likely Windows PE files
            if (file_path.suffix.lower() in ['.exe', '.dll', '.sys'] or
                file_path.suffix == ''):
                pe_files.append(file_path)

    if not pe_files:
        logger.warning("No PE files found")
        return True

    logger.info(f"Processing {len(pe_files)} files")

    # Process each file
    success_count = 0
    for pe_file in pe_files:
        output_file = output_path / pe_file.name

        if mutate_pe_file(pe_file, output_file, astral_pe):
            success_count += 1
        else:
            # Copy original if mutation failed
            shutil.copy2(pe_file, output_file)

    logger.info(f"Completed: {success_count}/{len(pe_files)} mutated successfully")
    return True

def main():
    """Main function with minimal argument handling."""

    # Simple argument parsing
    if len(sys.argv) == 2 and sys.argv[1] == "--check":
        setup_logging()
        astral_pe = find_astral_pe()
        if astral_pe:
            print(f"✓ Astral-PE found: {astral_pe}")
            return 0
        else:
            print("✗ Astral-PE not found")
            print("Download from: https://github.com/DosX-dev/Astral-PE/releases")
            print("Place as 'Astral-PE' in current directory")
            print("Make executable: chmod +x Astral-PE")
            return 1

    if len(sys.argv) != 3:
        print("Usage: python mutate_script.py <input_dir> <output_dir>")
        print("       python mutate_script.py --check")
        return 1

    setup_logging()

    input_dir = sys.argv[1]
    output_dir = sys.argv[2]

    try:
        success = mutate_directory(input_dir, output_dir)
        return 0 if success else 1
    except KeyboardInterrupt:
        logging.info("Interrupted")
        return 1
    except Exception as e:
        logging.error(f"Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
