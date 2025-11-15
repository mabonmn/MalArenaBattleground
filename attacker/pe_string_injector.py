"""
PE String Injector with Error-Only Logging and Minimum Threshold Logic

Logs only errors and failures to file for diagnosis.
Implements minimum threshold logic: 50% of target or everything from source, logs decision.
"""

import sys
import os
import shutil
import argparse
import struct
import traceback
import datetime
import logging
from pathlib import Path
import pefile

def setup_error_logging(script_name="pe_string_injector"):
    """Set up error-only logging configuration."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"{script_name}_errors_{timestamp}.log"
    logger = logging.getLogger()
    logger.setLevel(logging.ERROR)
    logger.handlers.clear()
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.ERROR)
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s')
    file_handler.setFormatter(file_formatter)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return log_file

def threshold_decision(num_strings, target_size, log_file):
    min_thresh = int(target_size * 0.5)
    use_source = num_strings <= min_thresh
    chosen_num = num_strings if use_source else min_thresh
    method = 'source (all)' if use_source else 'threshold (50% of target)'
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, 'a') as f:
        f.write(f"{timestamp} - THRESHOLD - threshold_decision:0 - [THRESHOLD] chosen_count={chosen_num}, method={method}, source_count={num_strings}, target_size={target_size}, min_thresh={min_thresh}\n")
    logger = logging.getLogger()
    logger.error(f"Threshold decision: {chosen_num} ({method})")
    return chosen_num, method

def inject_strings_safe(target_file, strings_list, max_strings=25, output_file=None, create_section=True, log_file=None):
    logger = logging.getLogger()
    if output_file is None:
        output_file = target_file
    if log_file is None:
        log_file = 'injection.log'
    pe = pefile.PE(target_file)
    if hasattr(pe, 'OPTIONAL_HEADER'):
        target_size = pe.OPTIONAL_HEADER.SizeOfImage or 0
    else:
        target_size = os.path.getsize(target_file)
    chosen_num, method = threshold_decision(len(strings_list), target_size, log_file)
    strings_to_inject = strings_list[:chosen_num]
    # Proceed with injection as before, but use strings_to_inject
    injected_count = 0
    try:
        with open(output_file, 'r+b') as f:
            for idx, string_info in enumerate(strings_to_inject):
                string_text = string_info.get('text', '')
                if not string_text or len(string_text) > 80:
                    continue
                try:
                    string_bytes = string_text.encode('utf-8', errors='ignore')[:75] + b'\x00'
                    f.write(string_bytes)
                    injected_count += 1
                except Exception as e:
                    logger.error(f"Injection failed for string {idx}: {e}")
                    continue
        return True, f"Successfully injected {injected_count} (method: {method})"
    except Exception as e:
        logger.error(f"Injection process failed: {e}")
        return False, f"Injection failed: {e}"

def main():
    parser = argparse.ArgumentParser(description='PE String Injector with Error-Only Logging and Threshold Logic')
    parser.add_argument('source_pe', help='Source PE file to extract strings from')
    parser.add_argument('target_pe', help='Target PE file to inject strings into')
    parser.add_argument('--output', help='Output file (default: overwrite target)')
    parser.add_argument('--min-length', type=int, default=5, help='Minimum string length')
    parser.add_argument('--max-strings', type=int, default=20, help='Maximum strings to inject')
    parser.add_argument('--dry-run', action='store_true', help='Analyze only, do not inject')
    args = parser.parse_args()
    log_file = setup_error_logging()
    # For brevity only threshold logic, real extraction logic omitted
    print("PE String Injector - Error-Only Logging and Threshold Logic")
    # Inject logic...
    success, result_msg = inject_strings_safe(args.target_pe, [{'text': 'Example String'}]*42, args.max_strings, args.output, create_section=True, log_file=log_file)
    print(result_msg)

if __name__ == "__main__":
    sys.exit(main())
