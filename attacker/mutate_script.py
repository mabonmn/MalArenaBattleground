"""
PE Mutation Script (Linux) - Mutates PE files using metame or binary tricks.

This script handles mutation of PE files on Linux, removing the UPX fallback.
It first tries `metame` if available; otherwise applies binary padding,
objcopy section tricks, and byte shuffling.
"""

from pathlib import Path
import subprocess
import sys
import argparse
import logging
import shutil
import os
import random
import datetime

def setup_logging(verbose=False):
    """Set up logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )

def check_mutation_tools():
    """Check for available mutation tools on the system."""
    logger = logging.getLogger()
    tools = {}
    metame_path = shutil.which("metame")
    if metame_path:
        logger.info(f"Found metame: {metame_path}")
        tools["metame"] = metame_path
    else:
        logger.debug("metame not found")
    # Check objcopy
    objcopy_path = shutil.which("objcopy")
    if objcopy_path:
        logger.debug(f"Found objcopy: {objcopy_path}")
        tools["objcopy"] = objcopy_path
    # No UPX fallback
    return tools

def mutate_with_metame(input_binary, output_binary, mutation_level=5, tools=None):
    """Mutate a binary using metame."""
    logger = logging.getLogger()
    if not tools or "metame" not in tools:
        logger.warning("metame not available")
        return False

    cmd = [
        tools["metame"],
        "-i", str(input_binary),
        "-o", str(output_binary),
        "-d"
    ]
    if mutation_level != 5:
        cmd.extend(["-l", str(mutation_level)])
    logger.debug(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode == 0 and Path(output_binary).exists():
            logger.info(f"✓ Metame mutation successful: {output_binary}")
            return True
        else:
            logger.warning(f"Metame mutation failed: {result.stderr}")
            return False
    except Exception as e:
        logger.warning(f"Metame mutation error: {e}")
        return False

def mutate_with_binary_tricks(input_binary, output_binary):
    """Apply binary-level mutations using Linux tools."""
    logger = logging.getLogger()
    logger.info("Applying binary tricks mutation")
    try:
        shutil.copy2(input_binary, output_binary)
        mutations_applied = 0

        # 1. Apply objcopy section mutation if available
        tools = check_mutation_tools()
        if "objcopy" in tools:
            try:
                temp_file = str(output_binary) + ".temp"
                shutil.copy2(output_binary, temp_file)
                # Create dummy section data
                data_file = "./mutation_data"
                with open(data_file, "wb") as f:
                    f.write(b"MUTATION" + os.urandom(64))
                cmd = [
                    tools["objcopy"],
                    "--add-section", f".mutation={data_file}",
                    temp_file, str(output_binary)
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    logger.debug("Applied objcopy section mutation")
                    mutations_applied += 1
                else:
                    shutil.copy2(temp_file, output_binary)
                os.unlink(temp_file)
                os.unlink(data_file)
            except Exception as e:
                logger.debug(f"objcopy mutation failed: {e}")

        # 2. Binary padding
        try:
            with open(output_binary, "ab") as f:
                padding_size = random.randint(64, 512)
                padding_data = bytearray(padding_size)
                for i in range(0, padding_size, 4):
                    padding_data[i:i+4] = b"\x00\x00\x90\x90"
                f.write(padding_data)
                mutations_applied += 1
                logger.debug(f"Applied binary padding mutation: {padding_size} bytes")
        except Exception as e:
            logger.debug(f"Padding mutation failed: {e}")

        # 3. Byte shuffling
        if mutations_applied < 2:
            try:
                with open(output_binary, "r+b") as f:
                    f.seek(0, 2)
                    file_size = f.tell()
                    if file_size > 1024:
                        start = max(1024, file_size - 512)
                        size = min(256, file_size - start)
                        if size > 64:
                            f.seek(start)
                            data = bytearray(f.read(size))
                            for i in range(0, len(data) - 4, 8):
                                if random.random() < 0.3:
                                    data[i:i+4], data[i+4:i+8] = data[i+4:i+8], data[i:i+4]
                            f.seek(start)
                            f.write(data)
                            mutations_applied += 1
                            logger.debug("Applied basic byte shuffling")
            except Exception as e:
                logger.debug(f"Byte shuffling failed: {e}")

        if mutations_applied > 0:
            logger.info(f"✓ Applied {mutations_applied} binary mutations")
            return True
        else:
            logger.warning("No mutations could be applied")
            return False

    except Exception as e:
        logger.error(f"Binary tricks mutation failed: {e}")
        return False

def mutate_single_file(input_file, output_file, mutation_level=5):
    """Mutate a single PE file."""
    logger = logging.getLogger()
    input_path = Path(input_file)
    output_path = Path(output_file)
    if not input_path.exists():
        logger.error(f"Input file not found: {input_file}")
        return False
    output_path.parent.mkdir(parents=True, exist_ok=True)

    tools = check_mutation_tools()
    if "metame" in tools and mutate_with_metame(input_path, output_path, mutation_level, tools):
        return True
    logger.info("Metame not used or failed, trying binary tricks...")
    if mutate_with_binary_tricks(input_path, output_path):
        return True

    logger.warning("No mutation possible, copying with timestamp update")
    try:
        shutil.copy2(input_path, output_path)
        ts = datetime.datetime.now().timestamp()
        os.utime(output_path, (ts, ts))
        logger.info(f"✓ Copied with timestamp update: {output_file}")
        return True
    except Exception as e:
        logger.error(f"Fallback copy failed: {e}")
        return False

def mutate_directory(input_dir, output_dir, mutation_level=5, preserve_names=True):
    """Mutate all files in a directory."""
    logger = logging.getLogger()
    input_path = Path(input_dir)
    if not input_path.is_dir():
        logger.error(f"Input directory not found: {input_dir}")
        return False
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    mutated, failed = 0, 0
    for f in sorted(input_path.iterdir()):
        if not f.is_file():
            continue
        out_file = output_path / f.name if preserve_names else output_path / f"mutated_{f.name}"
        logger.info(f"Processing: {f.name}")
        if mutate_single_file(str(f), str(out_file), mutation_level):
            mutated += 1
        else:
            failed += 1
            try:
                shutil.copy2(f, out_file)
            except:
                pass

    logger.info(f"Mutation completed: {mutated} mutated, {failed} failed")
    return True

def main():
    parser = argparse.ArgumentParser(description='Mutate PE files using Linux tools')
    parser.add_argument('input', help='Input file or directory')
    parser.add_argument('output', help='Output file or directory')
    parser.add_argument('-l', '--mutation-level', type=int, default=5,
                        help='Mutation level (1-10)')
    parser.add_argument('--preserve-names', action='store_true', default=True,
                        help='Preserve original filenames')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')
    args = parser.parse_args()

    setup_logging(args.verbose)
    logger = logging.getLogger()
    logger.info("=== PE MUTATION SCRIPT (Linux) ===")
    logger.info(f"Input: {args.input}, Output: {args.output}, Level: {args.mutation_level}")

    status = 1
    if Path(args.input).is_file():
        status = 0 if mutate_single_file(args.input, args.output, args.mutation_level) else 2
    elif Path(args.input).is_dir():
        status = 0 if mutate_directory(args.input, args.output, args.mutation_level, args.preserve_names) else 3
    else:
        logger.error(f"Input not found: {args.input}")
        status = 4

    if status == 0:
        logger.info("Mutation completed successfully")
    sys.exit(status)

if __name__ == "__main__":
    main()