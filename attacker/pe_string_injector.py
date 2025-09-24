#!/usr/bin/env python3

"""
PE String Injector with Error-Only Logging
Logs only errors and failures to file for diagnosis.
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


def create_new_data_section(pe, output_file, strings_list):
    """Create a new data section for string injection."""
    logger = logging.getLogger()

    # Calculate required size for strings
    required_size = sum(len(s.get('text', '')) + 1 for s in strings_list) + 64  # Add padding

    # Align to file alignment
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment

    # Round up to nearest file alignment
    raw_size = ((required_size + file_alignment - 1) // file_alignment) * file_alignment
    virtual_size = ((required_size + section_alignment - 1) // section_alignment) * section_alignment

    # Find a good section name that doesn't exist yet
    section_name = ".sdata"
    section_names = [section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                     for section in pe.sections]

    if section_name in section_names:
        for i in range(1, 10):
            test_name = f".sdata{i}"
            if test_name not in section_names:
                section_name = test_name
                break

    # Get next virtual address
    last_section = pe.sections[-1]
    next_virtual_address = (
            last_section.VirtualAddress +
            ((last_section.Misc_VirtualSize + section_alignment - 1) // section_alignment) * section_alignment
    )

    # Create a new section
    new_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
    new_section.Name = section_name.encode('utf-8').ljust(8, b'\x00')
    new_section.Misc_VirtualSize = required_size
    new_section.VirtualAddress = next_virtual_address
    new_section.SizeOfRawData = raw_size
    new_section.PointerToRawData = last_section.PointerToRawData + last_section.SizeOfRawData
    new_section.PointerToRelocations = 0
    new_section.PointerToLinenumbers = 0
    new_section.NumberOfRelocations = 0
    new_section.NumberOfLinenumbers = 0
    # Data section characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
    new_section.Characteristics = 0xC0000040

    # Update PE header
    pe.FILE_HEADER.NumberOfSections += 1
    pe.OPTIONAL_HEADER.SizeOfImage = next_virtual_address + virtual_size

    # Add section to PE
    pe.sections.append(new_section)

    # Important: Force PE to rebuild its internal structures
    pe.__structures__ = []  # Clear cached structures

    # Two-step approach to avoid section count mismatch
    try:
        # Step 1: Create a temporary file with the updated PE structure
        temp_file = output_file + ".temp"
        pe.write(filename=temp_file)

        # Step 2: Append the section data and copy to final location
        section_data = bytearray(raw_size)
        with open(temp_file, 'r+b') as f:
            f.seek(new_section.PointerToRawData)
            f.write(section_data)

        # Copy completed file to destination
        shutil.copy2(temp_file, output_file)
        os.unlink(temp_file)

    except Exception as e:
        logger.error(f"Failed to write PE file with new section: {e}")
        logger.error(f"Exception traceback: {traceback.format_exc()}")
        return None

    # Return space info for the new section
    return {
        'section': section_name,
        'offset': 0,
        'size': raw_size,
        'file_offset': new_section.PointerToRawData
    }
def setup_error_logging(script_name="pe_string_injector"):
    """Set up error-only logging configuration."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"{script_name}_errors_{timestamp}.log"

    # Create logger
    logger = logging.getLogger()
    logger.setLevel(logging.ERROR)

    # Clear any existing handlers
    logger.handlers.clear()

    # File handler for errors only
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.ERROR)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    file_handler.setFormatter(file_formatter)

    # Console handler (warnings and errors only)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return log_file

def check_dependencies():
    """Check if required dependencies are available."""
    try:
        import pefile
        return True, pefile
    except ImportError as e:
        logger = logging.getLogger()
        logger.error("pefile module not found")
        logger.error("Install with: pip install pefile")
        logger.error(f"Import error details: {e}")
        print("ERROR: pefile module not found.")
        print("Install with: pip install pefile")
        return False, None

def validate_file_access(filepath):
    """Validate file exists and is accessible."""
    logger = logging.getLogger()

    try:
        path = Path(filepath)

        if not path.exists():
            logger.error(f"File does not exist: {filepath}")
            return False, f"File does not exist: {filepath}"

        if not path.is_file():
            logger.error(f"Path is not a file: {filepath}")
            return False, f"Path is not a file: {filepath}"

        file_size = path.stat().st_size

        if file_size == 0:
            logger.error(f"File is empty: {filepath}")
            return False, f"File is empty: {filepath}"

        if file_size < 64:  # Minimum for PE header
            logger.error(f"File too small to be a PE: {filepath} ({file_size} bytes)")
            return False, f"File too small to be a PE: {filepath}"

        # Test read access
        try:
            with open(filepath, 'rb') as f:
                f.read(2)
        except PermissionError as e:
            logger.error(f"Permission denied reading: {filepath}")
            return False, f"Permission denied reading: {filepath}"
        except Exception as e:
            logger.error(f"Cannot read file {filepath}: {e}")
            return False, f"Cannot read file {filepath}: {e}"

        return True, "OK"

    except Exception as e:
        logger.error(f"File validation error for {filepath}: {e}")
        logger.error(f"Exception traceback: {traceback.format_exc()}")
        return False, f"File validation error: {e}"

def validate_pe_header(filepath):
    """Basic PE header validation without pefile dependency."""
    logger = logging.getLogger()

    try:
        with open(filepath, 'rb') as f:
            # Check MZ header
            mz = f.read(2)

            if mz != b'MZ':
                logger.error(f"Not a valid executable (missing MZ header): {filepath}")
                return False, "Not a valid executable (missing MZ header)"

            # Go to PE header offset
            f.seek(60)
            pe_offset_bytes = f.read(4)

            if len(pe_offset_bytes) != 4:
                logger.error(f"Corrupted DOS header: {filepath}")
                return False, "Corrupted DOS header"

            pe_offset = struct.unpack('<L', pe_offset_bytes)[0]

            # Validate PE offset is reasonable
            if pe_offset > 1024 or pe_offset < 64:
                logger.error(f"Invalid PE header offset: 0x{pe_offset:x} in {filepath}")
                return False, "Invalid PE header offset"

            f.seek(pe_offset)
            pe_sig = f.read(4)

            if pe_sig != b'PE\x00\x00':
                logger.error(f"Not a valid PE file (missing PE signature): {filepath}")
                return False, "Not a valid PE file (missing PE signature)"

            return True, "Valid PE file"

    except Exception as e:
        logger.error(f"PE validation error for {filepath}: {e}")
        logger.error(f"Exception traceback: {traceback.format_exc()}")
        return False, f"PE validation error: {e}"

def safe_load_pe(filepath, pefile_module):
    """Safely load PE file with comprehensive error handling."""
    logger = logging.getLogger()

    try:
        pe = pefile_module.PE(filepath)

        # Basic validation
        if not hasattr(pe, 'sections') or not pe.sections:
            logger.error(f"PE file has no sections: {filepath}")
            return None, "PE file has no sections"

        if not hasattr(pe, 'OPTIONAL_HEADER'):
            logger.error(f"PE file missing optional header: {filepath}")
            return None, "PE file missing optional header"

        return pe, "PE loaded successfully"

    except pefile_module.PEFormatError as e:
        logger.error(f"Invalid PE format for {filepath}: {e}")
        return None, f"Invalid PE format: {e}"
    except Exception as e:
        logger.error(f"Error loading PE {filepath}: {e}")
        logger.error(f"Exception traceback: {traceback.format_exc()}")
        return None, f"Error loading PE: {e}"

def extract_strings_safe(pe, min_length=4):
    """Extract strings with comprehensive error handling."""
    logger = logging.getLogger()
    strings = []

    if not pe or not hasattr(pe, 'sections'):
        logger.error("PE object has no sections for string extraction")
        return strings

    for section_idx, section in enumerate(pe.sections):
        try:
            # Get section name safely
            try:
                section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                if not section_name:
                    section_name = f"section_{section_idx}"
            except:
                section_name = f"section_{section_idx}"

            # Get section data safely
            try:
                data = section.get_data()
                if not data or len(data) == 0:
                    continue
            except Exception as e:
                logger.error(f"Could not get data for section {section_name}: {e}")
                continue

            # Extract strings safely
            current_string = bytearray()

            for byte_pos, byte_val in enumerate(data):
                try:
                    if 32 <= byte_val <= 126:  # Printable ASCII
                        current_string.append(byte_val)
                    else:
                        if len(current_string) >= min_length:
                            try:
                                string_text = current_string.decode('ascii')
                                strings.append({
                                    'text': string_text,
                                    'section': section_name,
                                    'length': len(current_string),
                                    'offset': byte_pos - len(current_string)
                                })
                            except Exception as e:
                                logger.error(f"Error decoding string at position {byte_pos}: {e}")
                        current_string = bytearray()
                except Exception as e:
                    logger.error(f"Error processing byte at position {byte_pos} in {section_name}: {e}")
                    current_string = bytearray()

            # Check final string
            if len(current_string) >= min_length:
                try:
                    string_text = current_string.decode('ascii')
                    strings.append({
                        'text': string_text,
                        'section': section_name,
                        'length': len(current_string),
                        'offset': len(data) - len(current_string)
                    })
                except Exception as e:
                    logger.error(f"Error decoding final string in {section_name}: {e}")

        except Exception as e:
            logger.error(f"Error processing section {section_idx}: {e}")
            logger.error(f"Exception traceback: {traceback.format_exc()}")
            continue

    return strings

def find_injection_spaces(pe):
    """Find safe injection spaces with comprehensive validation."""
    logger = logging.getLogger()
    spaces = []

    if not pe or not hasattr(pe, 'sections'):
        logger.error("PE object has no sections for space analysis")
        return spaces

    for section_idx, section in enumerate(pe.sections):
        try:
            # Get section name
            try:
                section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                if not section_name:
                    section_name = f"section_{section_idx}"
            except:
                section_name = f"section_{section_idx}"

            # Skip executable sections
            if hasattr(section, 'Characteristics'):
                if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                    continue

            # Get section data
            try:
                data = section.get_data()
                if not data or len(data) < 50:  # Need at least 50 bytes
                    continue
            except Exception as e:
                logger.error(f"Could not get data for section {section_name}: {e}")
                continue

            # Find null byte runs
            null_start = -1
            null_size = 0

            for i, byte_val in enumerate(data):
                if byte_val == 0:
                    if null_start == -1:
                        null_start = i
                    null_size += 1
                else:
                    if null_size >= 30:  # At least 30 null bytes
                        try:
                            file_offset = getattr(section, 'PointerToRawData', 0) + null_start
                            space_info = {
                                'section': section_name,
                                'offset': null_start,
                                'size': null_size,
                                'file_offset': file_offset
                            }
                            spaces.append(space_info)
                        except Exception as e:
                            logger.error(f"Error recording space in {section_name}: {e}")
                    null_start = -1
                    null_size = 0

            # Check final run
            if null_size >= 30:
                try:
                    file_offset = getattr(section, 'PointerToRawData', 0) + null_start
                    space_info = {
                        'section': section_name,
                        'offset': null_start,
                        'size': null_size,
                        'file_offset': file_offset
                    }
                    spaces.append(space_info)
                except Exception as e:
                    logger.error(f"Error recording final space in {section_name}: {e}")

        except Exception as e:
            logger.error(f"Error analyzing section {section_idx}: {e}")
            logger.error(f"Exception traceback: {traceback.format_exc()}")
            continue

    # Sort by size (largest first)
    spaces.sort(key=lambda x: x.get('size', 0), reverse=True)
    return spaces


def inject_strings_safe(target_file, strings_list, max_strings=25, output_file=None, create_section=True):
    """String injection with error-only logging."""
    logger = logging.getLogger()

    if output_file is None:
        output_file = target_file

    # Create backup
    backup_file = None
    if target_file == output_file:
        try:
            backup_file = target_file + ".backup"
            shutil.copy2(target_file, backup_file)
        except Exception as e:
            logger.error(f"Could not create backup: {e}")
    else:
        try:
            shutil.copy2(target_file, output_file)
        except Exception as e:
            logger.error(f"Could not copy to output file: {e}")
            return False, f"Could not copy to output file: {e}"

    # Validate dependencies
    has_pefile, pefile_module = check_dependencies()
    if not has_pefile:
        return False, "pefile module not available"

    # Load and validate PE
    pe, load_msg = safe_load_pe(target_file, pefile_module)
    if pe is None:
        return False, f"Could not load PE: {load_msg}"

    # Find injection spaces
    spaces = find_injection_spaces(pe)
    if not spaces:
        logger.warning("No suitable injection spaces found")

        if create_section:
            try:
                print("No suitable spaces found, creating new data section...")
                # Create a fresh copy of the PE file
                new_pe, _ = safe_load_pe(output_file, pefile_module)
                if new_pe:
                    new_space = create_new_data_section(new_pe, output_file, strings_list[:max_strings])
                    if new_space:
                        spaces = [new_space]
                        print(f"Created new section '{new_space['section']}' with {new_space['size']} bytes")
                    else:
                        logger.error("Failed to create new data section")
                        return False, "No suitable injection spaces found and couldn't create new section"
            except Exception as e:
                logger.error(f"Error creating new section: {e}")
                logger.error(f"Exception traceback: {traceback.format_exc()}")
                return False, f"No suitable injection spaces found and error creating new section: {e}"
        else:
            logger.error("No suitable injection spaces found")
            return False, "No suitable injection spaces found"

    print(f"Found {len(spaces)} injection spaces:")
    for i, space in enumerate(spaces[:3]):
        print(f"  {i + 1}. {space['section']}: {space['size']} bytes")

    # Limit strings
    strings_to_inject = strings_list[:min(max_strings, 20)]  # Hard limit 20

    injected_count = 0

    try:
        with open(output_file, 'r+b') as f:
            current_space_idx = 0
            current_offset = 0

            for string_idx, string_info in enumerate(strings_to_inject):
                # Rest of the function remains unchanged
                try:
                    string_text = string_info.get('text', '')
                    if not string_text or len(string_text) > 80:  # Limit string length
                        continue

                    # Encode string safely
                    try:
                        string_bytes = string_text.encode('utf-8', errors='ignore')[:75] + b'\x00'
                    except Exception as e:
                        logger.error(f"Error encoding string {string_idx}: {e}")
                        continue

                    # Find space for this string
                    while current_space_idx < len(spaces):
                        space = spaces[current_space_idx]
                        remaining = space['size'] - current_offset

                        if remaining >= len(string_bytes):
                            # Inject here
                            try:
                                file_pos = space['file_offset'] + current_offset
                                f.seek(file_pos)
                                f.write(string_bytes)
                                current_offset += len(string_bytes)
                                injected_count += 1

                                if injected_count <= 5:
                                    print(f"  {injected_count}. Injected '{string_text[:30]}...' into {space['section']}")

                                break
                            except Exception as e:
                                logger.error(f"Injection failed for string {string_idx}: {e}")
                                break
                        else:
                            current_space_idx += 1
                            current_offset = 0

                        if current_space_idx >= len(spaces):
                            break

                    if current_space_idx >= len(spaces):
                        break

                except Exception as e:
                    logger.error(f"Error processing string {string_idx}: {e}")
                    logger.error(f"Exception traceback: {traceback.format_exc()}")
                    continue

        return True, f"Successfully injected {injected_count} strings"

    except Exception as e:
        logger.error(f"Injection process failed: {e}")
        logger.error(f"Exception traceback: {traceback.format_exc()}")

        # Restore backup if injection failed
        if backup_file and os.path.exists(backup_file):
            try:
                shutil.copy2(backup_file, output_file)
            except Exception as restore_error:
                logger.error(f"Failed to restore backup: {restore_error}")

        return False, f"Injection failed: {e}"

def main():
    parser = argparse.ArgumentParser(description='PE String Injector with Error-Only Logging')
    parser.add_argument('source_pe', help='Source PE file to extract strings from')
    parser.add_argument('target_pe', help='Target PE file to inject strings into')
    parser.add_argument('--output', help='Output file (default: overwrite target)')
    parser.add_argument('--min-length', type=int, default=5, help='Minimum string length')
    parser.add_argument('--max-strings', type=int, default=20, help='Maximum strings to inject')
    parser.add_argument('--dry-run', action='store_true', help='Analyze only, do not inject')

    args = parser.parse_args()

    # Set up error-only logging
    log_file = setup_error_logging()

    try:
        print("PE String Injector - Error-Only Logging")

        # Validate source file
        valid, msg = validate_file_access(args.source_pe)
        if not valid:
            print(f"ERROR: {msg}")
            return 1

        valid, msg = validate_pe_header(args.source_pe)
        if not valid:
            print(f"ERROR: Source file - {msg}")
            return 1

        print(f"✓ Source file validated: {args.source_pe}")

        # Validate target file
        valid, msg = validate_file_access(args.target_pe)
        if not valid:
            print(f"ERROR: {msg}")
            return 1

        valid, msg = validate_pe_header(args.target_pe)
        if not valid:
            print(f"ERROR: Target file - {msg}")
            return 1

        print(f"✓ Target file validated: {args.target_pe}")

        # Load source PE and extract strings
        print(f"\nExtracting strings from source...")
        has_pefile, pefile_module = check_dependencies()
        if not has_pefile:
            return 1

        pe_source, load_msg = safe_load_pe(args.source_pe, pefile_module)
        if pe_source is None:
            print(f"ERROR: Could not load source PE: {load_msg}")
            return 1

        source_strings = extract_strings_safe(pe_source, args.min_length)
        if not source_strings:
            print("ERROR: No strings found in source PE")
            return 1

        print(f"✓ Found {len(source_strings)} strings in source")

        # Show sample strings
        for i, s in enumerate(source_strings[:3]):
            print(f"  {i+1}. '{s['text'][:40]}...' from {s['section']}")

        if args.dry_run:
            print("\n--- DRY RUN COMPLETED ---")
            # Remove empty error log
            if os.path.getsize(log_file) == 0:
                os.unlink(log_file)
            return 0

        # Inject strings
        print(f"\nInjecting strings into target...")
        output_file = args.output or args.target_pe

        success, result_msg = inject_strings_safe(
            args.target_pe,
            source_strings,
            args.max_strings,
            output_file,
            create_section=True
        )

        if success:
            print(f"\n✓ SUCCESS: {result_msg}")
            print(f"✓ Output file: {output_file}")
            # Remove empty error log
            if os.path.getsize(log_file) == 0:
                os.unlink(log_file)
            return 0
        else:
            print(f"\n✗ FAILED: {result_msg}")
            print(f"Check error log: {log_file}")
            return 1

    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        return 1
    except Exception as e:
        logger = logging.getLogger()
        logger.error(f"Unexpected error: {e}")
        logger.error(f"Exception traceback: {traceback.format_exc()}")
        print(f"\nUnexpected error: {e}")
        print(f"Check error log: {log_file}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
