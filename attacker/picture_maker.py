"""
Picture Maker - Steganography Tool
Embeds files from a target directory into an RGB bitmap image.
Uses color channel selection based on key value.
"""

import argparse
import math
import os
import random
import logging
import datetime
import traceback
from pathlib import Path
from PIL import Image




def setup_logging(script_name="picture_maker"):
    """Set up logging to file and console."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"{script_name}_activity_{timestamp}.log"

    # Create logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # Clear existing handlers
    logger.handlers.clear()

    # File handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    file_handler.setFormatter(file_formatter)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    logger.info("=== PICTURE MAKER SESSION STARTED ===")
    logger.info(f"Activity log: {log_file}")

    return log_file


def collect_files(directory):
    """Collect all files from a directory."""
    logger = logging.getLogger()
    logger.info(f"Collecting files from: {directory}")

    files = []
    try:
        for entry in os.scandir(directory):
            if entry.is_file():
                files.append(entry.path)

        logger.info(f"Found {len(files)} files in {directory}")
        return files
    except Exception as e:
        logger.error(f"Error collecting files: {e}")
        logger.debug(traceback.format_exc())
        return []


def read_file_bytes(filepath):
    """Read all bytes from a file."""
    logger = logging.getLogger()
    logger.debug(f"Reading bytes from: {filepath}")

    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        logger.debug(f"Read {len(data)} bytes from {filepath}")
        return data
    except Exception as e:
        logger.error(f"Error reading file {filepath}: {e}")
        logger.debug(traceback.format_exc())
        return b''


def collect_all_bytes(files):
    """Collect bytes from all files."""
    logger = logging.getLogger()
    logger.info(f"Collecting bytes from {len(files)} files")

    all_bytes = bytearray()
    for file in files:
        file_bytes = read_file_bytes(file)
        all_bytes.extend(file_bytes)

    logger.info(f"Collected {len(all_bytes)} bytes total")
    return all_bytes



import numpy as np
import math
import logging

def _near_square_dims(n):
    """Find integer (h,w) with h*w >= n and aspect ratio as close to 1 as possible.
    Prefer exact factors; otherwise choose ceil(sqrt(n)) for one side and compute the other.
    """
    if n <= 0:
        return 1, 1
    r = int(math.sqrt(n))
    best = None
    # search around sqrt for factors
    for h in range(r, 0, -1):
        w = (n + h - 1) // h
        if h*w >= n:
            cand = (h, w) if h <= w else (w, h)
            aspect = max(cand)/min(cand)
            if best is None or aspect < best[0] or (aspect == best[0] and cand[0]*cand[1] < best[1][0]*best[1][1]):
                best = (aspect, cand)
    return best[1]


def create_bitmap(target_bytes, source_bytes, key):
    """Create a bitmap where:
    - Red channel encodes goodware (source) bytes (after invert filter)
    - Green and Blue channels encode malware (target) bytes (after XOR filters)
    - Shape chosen to be as boxy as possible
    - Black pixels are added at the beginning for padding
    """
    logger = logging.getLogger()

    target = np.frombuffer(target_bytes, dtype=np.uint8)
    source = np.frombuffer(source_bytes, dtype=np.uint8)

    # Avoid empty arrays
    if source.size == 0:
        source = np.array([123], dtype=np.uint8)  # non-black seed
    if target.size == 0:
        target = np.array([0], dtype=np.uint8)

    # Prepare per-channel streams
    R_stream = source
    mid = len(target) // 2 + (len(target) % 2)  # Add 1 if length is odd
    G_stream = target[:mid]  # Green gets extra byte if odd length
    B_stream = target[mid:]  # Blue gets remaining bytes

    R_stream = R_stream[R_stream != 0]

    length = max(len(G_stream), len(B_stream))
    if len(R_stream) < length:
        # Repeat R_stream to match length
        repeats = (length + len(R_stream) - 1) // len(R_stream)
        R_stream = np.tile(R_stream, repeats)[:length]
    else:
        R_stream = R_stream[:length]

    if length > len(B_stream):
        B_stream = np.append(B_stream, 0)
        R_stream[-1] = 0

    # Calculate dimensions for the image
    h, w = _near_square_dims(length)
    total_pixels = h * w

    # Create initial pixels with data
    pixels = np.zeros((length, 3), dtype=np.uint8)
    pixels[:length, 0] = R_stream
    pixels[:len(G_stream), 1] = G_stream
    pixels[:len(B_stream), 2] = B_stream

    # Add black pixels at the beginning (changed from end)
    if total_pixels > length:
        padding = np.zeros((total_pixels - length, 3), dtype=np.uint8)
        pixels = np.vstack((padding, pixels))  # Stack padding before actual data

    # Apply XOR operations
    pixels[:, 0] = pixels[:, 0] ^ 50  # XOR 50 on red
    pixels[:, 1] = pixels[:, 1] ^ 100  # XOR 100 on green
    pixels[:, 2] = pixels[:, 2] ^ 200  # XOR 200 on blue

    # Reshape to image
    pixels_2d = pixels.reshape(h, w, 3)

    img = Image.fromarray(pixels_2d, mode='RGB')
    return img, max(h, w)

def save_bitmap(img, output_path):
    """Save bitmap to file as a 24-bit little-endian BMP."""
    logger = logging.getLogger()
    logger.info(f"Saving 24-bit little-endian bitmap to: {output_path}")

    try:
        # Ensure image is in RGB mode (24-bit)
        if img.mode != 'RGB':
            img = img.convert('RGB')
            logger.debug("Converted image to RGB mode (24-bit)")

        # Save as 24-bit BMP (little-endian is default for BMP)q
        img.save(output_path, format='BMP')

        # Verify the file was saved
        file_size = os.path.getsize(output_path)
        logger.info(f"✓ Bitmap saved successfully: {output_path} ({file_size} bytes)")
        return True
    except Exception as e:
        logger.error(f"Failed to save bitmap: {e}")
        logger.debug(traceback.format_exc())
        return False


def main():
    # Get script name for default output filename

    parser = argparse.ArgumentParser(description='Create RGB bitmap with embedded data')
    parser.add_argument('target_file', help='File to embed in the bitmap')
    parser.add_argument('source_dir', help='Directory with source files for random bytes')
    parser.add_argument('--output', '-o', help='Output bitmap path')
    parser.add_argument('--key', '-k', help='Initial key value', type=int, default=42)

    args = parser.parse_args()

    # Set default output filename based on target file if not specified
    if not args.output:
        target_basename = os.path.splitext(os.path.basename(args.target_file))[0]
        args.output = f"{target_basename}.bmp"
    # Setup logging
    log_file = setup_logging()
    logger = logging.getLogger()

    print("Picture Maker - RGB Bitmap Steganography Tool")
    print(f"Log file: {log_file}")

    # Validate arguments
    logger.info("=== ARGUMENT VALIDATION ===")
    logger.info(f"Target file: {args.target_file}")
    logger.info(f"Source directory: {args.source_dir}")
    logger.info(f"Output bitmap: {args.output}")
    logger.info(f"Initial key: {args.key}")

    # Ensure file and directory exist
    if not os.path.exists(args.target_file) or not os.path.isfile(args.target_file):
        logger.error(f"Target file not found: {args.target_file}")
        print(f"Error: Target file not found: {args.target_file}")
        return 1

    if not os.path.exists(args.source_dir) or not os.path.isdir(args.source_dir):
        logger.error(f"Source directory not found: {args.source_dir}")
        print(f"Error: Source directory not found: {args.source_dir}")
        return 1

    # Read target file
    logger.info("=== READING TARGET FILE ===")
    target_bytes = read_file_bytes(args.target_file)
    if not target_bytes:
        logger.error("No data found in target file")
        print("Error: No data found in target file")
        return 1

    # Collect source files
    logger.info("=== COLLECTING SOURCE FILES ===")
    source_files = collect_files(args.source_dir)
    if not source_files:
        logger.error("No files found in source directory")
        print("Error: No files found in source directory")
        return 1

    # Read source bytes
    logger.info("=== READING SOURCE BYTES ===")
    source_bytes = collect_all_bytes(source_files)
    if not source_bytes:
        logger.error("No data found in source files")
        print("Error: No data found in source files")
        return 1

    # Create bitmap
    logger.info("=== CREATING BITMAP ===")
    img, image_size = create_bitmap(target_bytes, source_bytes, args.key)

    # Save bitmap
    logger.info("=== SAVING BITMAP ===")
    if save_bitmap(img, args.output):
        print(f"✓ Bitmap created successfully: {args.output}")
        print(f"  - Size: {image_size}x{image_size} pixels")
        print(f"  - Embedded {len(target_bytes)} bytes of data")
        print(f"  - Activity log: {log_file}")
        return 0
    else:
        print(f"✗ Failed to create bitmap. See log for details: {log_file}")
        return 1


if __name__ == "__main__":
    main()
