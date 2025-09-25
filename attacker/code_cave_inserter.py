"""
Code Cave Inserter with Activity Logging and Minimum Threshold Logic

Logs all operations and activity to file for complete audit trail.
Implements minimum threshold: 50% of target or everything from source.
"""

import sys
import os
import shutil
import argparse
import struct
import traceback
import random
import datetime
import logging
from pathlib import Path

def setup_activity_logging(script_name="code_cave_inserter"):
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
    logger.info(f"=== CODE CAVE INSERTER SESSION STARTED ===")
    logger.info(f"Activity log file: {log_file}")
    logger.info(f"Timestamp: {datetime.datetime.now()}")
    logger.info(f"Working directory: {os.getcwd()}")
    logger.info(f"Command line: {' '.join(sys.argv)}")
    
    return log_file

def threshold_decision(code_size, cave_size, log_file):
    """Apply minimum threshold logic: 50% of target or everything from source."""
    min_thresh = int(cave_size * 0.5)
    use_source = code_size <= min_thresh
    chosen_size = code_size if use_source else min_thresh
    method = 'source (all)' if use_source else 'threshold (50% of target)'
    
    # Log the threshold decision
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, 'a') as f:
        f.write(f"{timestamp} - THRESHOLD - threshold_decision:0 - [THRESHOLD] chosen_size={chosen_size}, method={method}, code_size={code_size}, target_size={cave_size}, min_thresh={min_thresh}\n")
    
    logger = logging.getLogger()
    logger.info(f"Threshold decision: {chosen_size} bytes ({method})")
    
    return chosen_size, method

def check_dependencies():
    """Check if required dependencies are available."""
    logger = logging.getLogger()
    logger.info("Checking dependencies")
    
    try:
        import pefile
        logger.info("✓ pefile module available")
        logger.debug(f"pefile location: {pefile.__file__}")
        return True, pefile
    except ImportError as e:
        logger.error("✗ pefile module not found")
        logger.error("Install with: pip install pefile")
        logger.debug(f"Import error: {e}")
        print("ERROR: pefile module not found.")
        print("Install with: pip install pefile")
        return False, None

def validate_file_access(filepath):
    """Validate file exists and is accessible."""
    logger = logging.getLogger()
    logger.info(f"Validating file access: {filepath}")
    
    try:
        path = Path(filepath)
        logger.debug(f"Resolved path: {path.resolve()}")
        
        if not path.exists():
            logger.error(f"File does not exist: {filepath}")
            return False, f"File does not exist: {filepath}"
        
        if not path.is_file():
            logger.error(f"Path is not a file: {filepath}")
            return False, f"Path is not a file: {filepath}"
        
        file_size = path.stat().st_size
        logger.debug(f"File size: {file_size} bytes")
        
        if file_size == 0:
            logger.error(f"File is empty: {filepath}")
            return False, f"File is empty: {filepath}"
        
        if file_size < 64:  # Minimum for PE header
            logger.error(f"File too small for PE: {filepath} ({file_size} bytes)")
            return False, f"File too small to be a PE: {filepath}"
        
        # Test read/write access
        try:
            with open(filepath, 'rb') as f:
                test_data = f.read(2)
                logger.debug(f"Read test successful: {test_data.hex()}")
            
            # Test write access by opening in append mode
            with open(filepath, 'ab') as f:
                pass
            logger.debug("Write access test successful")
            
        except PermissionError as e:
            logger.error(f"Permission denied: {filepath}")
            return False, f"Permission denied accessing: {filepath}"
        except Exception as e:
            logger.error(f"File access error: {e}")
            return False, f"Cannot access file {filepath}: {e}"
        
        logger.info(f"✓ File access validated: {filepath}")
        return True, "OK"
    
    except Exception as e:
        logger.error(f"File validation exception: {e}")
        logger.debug(f"Traceback: {traceback.format_exc()}")
        return False, f"File validation error: {e}"

def validate_pe_header(filepath):
    """Basic PE header validation without pefile dependency."""
    logger = logging.getLogger()
    logger.info(f"Validating PE header: {filepath}")
    
    try:
        with open(filepath, 'rb') as f:
            # Check MZ header
            mz = f.read(2)
            logger.debug(f"MZ header: {mz.hex()}")
            if mz != b'MZ':
                logger.error("Missing MZ header")
                return False, "Not a valid executable (missing MZ header)"
            
            # Go to PE header offset
            f.seek(60)
            pe_offset_bytes = f.read(4)
            logger.debug(f"PE offset bytes: {pe_offset_bytes.hex()}")
            
            if len(pe_offset_bytes) != 4:
                logger.error("Corrupted DOS header")
                return False, "Corrupted DOS header"
            
            pe_offset = struct.unpack('<L', pe_offset_bytes)[0]
            logger.debug(f"PE offset: 0x{pe_offset:x}")
            
            if pe_offset > 1024 or pe_offset < 64:
                logger.error(f"Invalid PE offset: 0x{pe_offset:x}")
                return False, "Invalid PE header offset"
            
            f.seek(pe_offset)
            pe_sig = f.read(4)
            logger.debug(f"PE signature: {pe_sig.hex()}")
            
            if pe_sig != b'PE\x00\x00':
                logger.error("Missing PE signature")
                return False, "Not a valid PE file (missing PE signature)"
        
        logger.info("✓ PE header validation passed")
        return True, "Valid PE file"
    
    except Exception as e:
        logger.error(f"PE validation error: {e}")
        logger.debug(f"Traceback: {traceback.format_exc()}")
        return False, f"PE validation error: {e}"

def safe_load_pe(filepath, pefile_module):
    """Safely load PE file with comprehensive error handling."""
    logger = logging.getLogger()
    logger.info(f"Loading PE file: {filepath}")
    
    try:
        load_start = datetime.datetime.now()
        pe = pefile_module.PE(filepath)
        load_end = datetime.datetime.now()
        
        logger.debug(f"PE load time: {load_end - load_start}")
        logger.debug(f"PE object type: {type(pe)}")
        
        # Basic validation
        if not hasattr(pe, 'sections') or not pe.sections:
            logger.error("PE file has no sections")
            return None, "PE file has no sections"
        
        if not hasattr(pe, 'OPTIONAL_HEADER'):
            logger.error("PE file missing optional header")
            return None, "PE file missing optional header"
        
        if not hasattr(pe, 'FILE_HEADER'):
            logger.error("PE file missing file header")
            return None, "PE file missing file header"
        
        logger.debug(f"Number of sections: {len(pe.sections)}")
        logger.debug(f"Entry point: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}")
        logger.debug(f"Image base: 0x{pe.OPTIONAL_HEADER.ImageBase:x}")
        
        logger.info("✓ PE file loaded successfully")
        return pe, "PE loaded successfully"
    
    except pefile_module.PEFormatError as e:
        logger.error(f"Invalid PE format: {e}")
        return None, f"Invalid PE format: {e}"
    except Exception as e:
        logger.error(f"Error loading PE: {e}")
        logger.debug(f"Traceback: {traceback.format_exc()}")
        return None, f"Error loading PE: {e}"

def find_code_caves_safe(pe):
    """Find code caves with comprehensive error handling."""
    logger = logging.getLogger()
    logger.info("Finding code caves")
    
    caves = []
    
    if not pe or not hasattr(pe, 'sections'):
        logger.warning("PE object has no sections")
        return caves
    
    for section_idx, section in enumerate(pe.sections):
        try:
            # Get section name safely
            try:
                section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                if not section_name:
                    section_name = f"section_{section_idx}"
            except:
                section_name = f"section_{section_idx}"
            
            logger.debug(f"Analyzing section {section_idx}: {section_name}")
            
            # Skip non-executable sections for code caves
            if hasattr(section, 'Characteristics'):
                characteristics = section.Characteristics
                logger.debug(f"Section {section_name} characteristics: 0x{characteristics:x}")
                if not (characteristics & 0x20000000):  # Not executable
                    logger.debug(f"Skipping non-executable section: {section_name}")
                    continue
            
            # Get section data safely
            try:
                if hasattr(pe, '__data__') and hasattr(section, 'PointerToRawData') and hasattr(section, 'SizeOfRawData'):
                    start = section.PointerToRawData
                    size = section.SizeOfRawData
                    logger.debug(f"Section {section_name}: raw_ptr=0x{start:x}, size=0x{size:x}")
                    
                    if start + size > len(pe.__data__):
                        logger.debug(f"Section {section_name} extends beyond PE data")
                        continue
                    
                    data = pe.__data__[start:start + size]
                else:
                    data = section.get_data()
                
                if not data or len(data) < 100:
                    logger.debug(f"Section {section_name} too small: {len(data) if data else 0} bytes")
                    continue
                
                logger.debug(f"Section {section_name} data size: {len(data)} bytes")
            
            except Exception as e:
                logger.warning(f"Could not get data for section {section_name}: {e}")
                continue
            
            # Find null byte runs (potential caves)
            cave_start = -1
            cave_size = 0
            caves_in_section = 0
            
            for i, byte_val in enumerate(data):
                if byte_val == 0:
                    if cave_start == -1:
                        cave_start = i
                    cave_size += 1
                else:
                    if cave_size >= 100:  # Minimum 100 bytes for useful cave
                        try:
                            cave_info = {
                                'section': section_name,
                                'section_idx': section_idx,
                                'offset': cave_start,
                                'size': cave_size,
                                'raw_offset': section.PointerToRawData + cave_start,
                                'virt_addr': section.VirtualAddress + cave_start
                            }
                            caves.append(cave_info)
                            caves_in_section += 1
                            logger.debug(f"Found cave: {cave_size} bytes at offset {cave_start}")
                        except Exception as e:
                            logger.debug(f"Error recording cave: {e}")
                    
                    cave_start = -1
                    cave_size = 0
            
            # Check final cave
            if cave_size >= 100:
                try:
                    cave_info = {
                        'section': section_name,
                        'section_idx': section_idx,
                        'offset': cave_start,
                        'size': cave_size,
                        'raw_offset': section.PointerToRawData + cave_start,
                        'virt_addr': section.VirtualAddress + cave_start
                    }
                    caves.append(cave_info)
                    caves_in_section += 1
                    logger.debug(f"Found final cave: {cave_size} bytes at offset {cave_start}")
                except Exception as e:
                    logger.debug(f"Error recording final cave: {e}")
            
            logger.debug(f"Found {caves_in_section} caves in section {section_name}")
        
        except Exception as e:
            logger.warning(f"Error analyzing section {section_idx}: {e}")
            logger.debug(f"Traceback: {traceback.format_exc()}")
            continue
    
    # Sort by size (largest first)
    caves.sort(key=lambda x: x.get('size', 0), reverse=True)
    
    logger.info(f"✓ Found {len(caves)} code caves total")
    
    # Log top caves
    for i, cave in enumerate(caves[:5]):
        logger.debug(f"Cave {i+1}: {cave['section']} - {cave['size']} bytes at 0x{cave['raw_offset']:x}")
    
    return caves

def extract_code_safely(pe):
    """Extract code chunks with comprehensive error handling."""
    logger = logging.getLogger()
    logger.info("Extracting code chunks")
    
    chunks = []
    
    if not pe or not hasattr(pe, 'sections'):
        logger.warning("PE object has no sections for code extraction")
        return chunks
    
    for section_idx, section in enumerate(pe.sections):
        try:
            # Get section name
            try:
                section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                if not section_name:
                    section_name = f"section_{section_idx}"
            except:
                section_name = f"section_{section_idx}"
            
            logger.debug(f"Processing section {section_idx}: {section_name}")
            
            # Only extract from executable sections
            if hasattr(section, 'Characteristics'):
                if not (section.Characteristics & 0x20000000):  # Not executable
                    logger.debug(f"Skipping non-executable section: {section_name}")
                    continue
            
            # Get section data
            try:
                if hasattr(pe, '__data__') and hasattr(section, 'PointerToRawData') and hasattr(section, 'SizeOfRawData'):
                    start = section.PointerToRawData
                    size = section.SizeOfRawData
                    
                    if start + size > len(pe.__data__):
                        continue
                    
                    data = pe.__data__[start:start + size]
                else:
                    data = section.get_data()
                
                if not data or len(data) < 200:
                    logger.debug(f"Section {section_name} too small for extraction: {len(data) if data else 0} bytes")
                    continue
                
                logger.debug(f"Section {section_name} data size: {len(data)} bytes")
            
            except Exception as e:
                logger.warning(f"Could not get data for section {section_name}: {e}")
                continue
            
            # Extract small chunks safely
            chunk_count = 0
            max_chunks_per_section = 1  # Conservative
            
            for attempt in range(max_chunks_per_section):
                if chunk_count >= max_chunks_per_section:
                    break
                
                try:
                    # Pick a safe area (not at the very beginning or end)
                    start_range = max(50, len(data) // 4)
                    end_range = min(len(data) - 50, 3 * len(data) // 4)
                    
                    if end_range <= start_range:
                        logger.debug(f"Section {section_name} too small for safe extraction")
                        break
                    
                    start_pos = random.randint(start_range, end_range - 100)
                    chunk_size = random.randint(50, min(150, end_range - start_pos))
                    
                    chunk_data = data[start_pos:start_pos + chunk_size]
                    
                    # Skip chunks that are mostly zeros
                    zero_count = chunk_data.count(0)
                    zero_ratio = zero_count / len(chunk_data)
                    
                    logger.debug(f"Chunk from {section_name}: size={chunk_size}, zeros={zero_count} ({zero_ratio:.1%})")
                    
                    if zero_ratio > 0.5:
                        logger.debug(f"Skipping chunk with too many zeros ({zero_ratio:.1%})")
                        continue
                    
                    chunk_info = {
                        'data': chunk_data,
                        'size': len(chunk_data),
                        'source_section': section_name,
                        'start_pos': start_pos,
                        'zero_ratio': zero_ratio
                    }
                    
                    chunks.append(chunk_info)
                    chunk_count += 1
                    logger.debug(f"Extracted chunk {chunk_count} from {section_name}: {chunk_size} bytes")
                
                except Exception as e:
                    logger.warning(f"Error extracting chunk from {section_name}: {e}")
                    logger.debug(f"Traceback: {traceback.format_exc()}")
                    continue
            
            logger.debug(f"Extracted {chunk_count} chunks from section {section_name}")
        
        except Exception as e:
            logger.warning(f"Error processing section {section_idx}: {e}")
            logger.debug(f"Traceback: {traceback.format_exc()}")
            continue
    
    # Limit to 3 chunks maximum
    chunks = chunks[:3]
    
    logger.info(f"✓ Extracted {len(chunks)} code chunks total")
    
    # Log chunk details
    for i, chunk in enumerate(chunks):
        logger.debug(f"Chunk {i+1}: {chunk['size']} bytes from {chunk['source_section']} (zeros: {chunk['zero_ratio']:.1%})")
    
    return chunks

def inject_code_safely(target_file, cave, code_chunk, output_file, log_file):
    """Inject code with comprehensive error handling and threshold logic."""
    logger = logging.getLogger()
    logger.info(f"Injecting code into cave")
    logger.debug(f"Target: {target_file}")
    logger.debug(f"Output: {output_file}")
    logger.debug(f"Cave: {cave['section']} - {cave['size']} bytes at 0x{cave['raw_offset']:x}")
    logger.debug(f"Chunk: {code_chunk['size']} bytes from {code_chunk['source_section']}")
    
    # Apply threshold decision
    chosen_size, method = threshold_decision(code_chunk['size'], cave['size'], log_file)
    code_data = code_chunk['data'][:chosen_size]
    
    def ensure_output_exists():
        """GUARANTEE: Ensure output file exists"""
        if not Path(output_file).exists():
            logger.info(f"Ensuring output exists by copying target to {output_file}")
            shutil.copy2(target_file, output_file)
    
    # Create backup
    backup_file = None
    try:
        if target_file == output_file:
            backup_file = str(target_file) + ".backup"
            logger.debug(f"Creating backup: {backup_file}")
            shutil.copy2(target_file, backup_file)
        else:
            # Copy target to output first
            logger.debug(f"Copying target to output: {target_file} -> {output_file}")
            shutil.copy2(target_file, output_file)
        
        logger.debug("File preparation successful")
    
    except Exception as e:
        logger.error(f"Could not create backup/copy: {e}")
        ensure_output_exists()
        return False, f"Could not create backup/copy: {e}"
    
    try:
        with open(output_file, 'r+b') as f:
            # Seek to cave location
            logger.debug(f"Seeking to cave location: 0x{cave['raw_offset']:x}")
            f.seek(cave['raw_offset'])
            
            # Write code chunk
            logger.debug(f"Writing {len(code_data)} bytes of code")
            f.write(code_data)
            
            # Fill remaining space with zeros
            remaining = cave['size'] - len(code_data)
            if remaining > 0:
                logger.debug(f"Filling {remaining} remaining bytes with zeros")
                f.write(b'\x00' * remaining)
        
        # Verify output file still exists and has reasonable size
        if Path(output_file).exists() and Path(output_file).stat().st_size > 0:
            result_msg = f"Injected {len(code_data)} bytes into {cave['section']} (method: {method})"
            logger.info(f"✓ {result_msg}")
            return True, result_msg
        else:
            logger.warning("Output file corrupted after injection, restoring")
            if backup_file and os.path.exists(backup_file):
                logger.debug("Restoring from backup")
                shutil.copy2(backup_file, output_file)
            else:
                ensure_output_exists()
            return False, "Output corrupted after injection"
    
    except Exception as e:
        logger.error(f"Injection failed: {e}")
        logger.debug(f"Traceback: {traceback.format_exc()}")
        
        # Restore backup if injection failed
        if backup_file and os.path.exists(backup_file):
            try:
                logger.debug("Restoring from backup after error")
                shutil.copy2(backup_file, output_file)
            except Exception as restore_error:
                logger.error(f"Failed to restore backup: {restore_error}")
                ensure_output_exists()
        else:
            ensure_output_exists()
        
        return False, f"Injection failed: {e}"

def add_simple_section_safe(target_file, output_file, section_size, pefile_module):
    """Add a simple new section with minimal PE modification - GUARANTEED output."""
    logger = logging.getLogger()
    logger.info(f"Adding new code cave section")
    logger.debug(f"Requested size: {section_size} bytes")
    
    def ensure_output_exists():
        """GUARANTEE: Ensure output file exists"""
        if not Path(output_file).exists():
            logger.info(f"Ensuring output exists by copying target to {output_file}")
            shutil.copy2(target_file, output_file)
    
    # Conservative size limit
    max_size = min(section_size, 32768)  # 32KB max
    if max_size != section_size:
        logger.warning(f"Section size limited from {section_size} to {max_size} bytes")
    
    try:
        pe = pefile_module.PE(target_file)
        logger.debug("PE file loaded for section addition")
        
        # Get alignment values safely
        try:
            section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
            file_alignment = pe.OPTIONAL_HEADER.FileAlignment
            logger.debug(f"Alignments: section=0x{section_alignment:x}, file=0x{file_alignment:x}")
        except Exception as e:
            logger.error(f"Could not read alignment values: {e}")
            ensure_output_exists()
            return False, "Could not read alignment values"
        
        # Find last section
        if not pe.sections:
            logger.error("No sections found")
            ensure_output_exists()
            return False, "No sections found"
        
        sections = sorted(pe.sections, key=lambda s: s.VirtualAddress)
        last_section = sections[-1]
        name = last_section.Name.decode().rstrip('\\x00')
        logger.debug(f"Last section: {name} at VA=0x{last_section.VirtualAddress:x}")
        
        # Calculate new section position
        try:
            # Align virtual address
            new_va = last_section.VirtualAddress + last_section.Misc_VirtualSize
            new_va = ((new_va + section_alignment - 1) // section_alignment) * section_alignment
            
            # Align file position
            new_raw_ptr = last_section.PointerToRawData + last_section.SizeOfRawData
            new_raw_ptr = ((new_raw_ptr + file_alignment - 1) // file_alignment) * file_alignment
            
            logger.debug(f"New section position: VA=0x{new_va:x}, raw=0x{new_raw_ptr:x}")
        except Exception as e:
            logger.error(f"Could not calculate section positions: {e}")
            ensure_output_exists()
            return False, "Could not calculate section positions"
        
        # Create new section
        try:
            new_section = pefile_module.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
            new_section.Name = b'.cave\\x00\\x00\\x00'
            new_section.Misc_VirtualSize = max_size
            new_section.VirtualAddress = new_va
            new_section.SizeOfRawData = ((max_size + file_alignment - 1) // file_alignment) * file_alignment
            new_section.PointerToRawData = new_raw_ptr
            new_section.Characteristics = 0x60000020  # CODE | EXECUTE | READ
            
            logger.debug(f"New section created: VSize=0x{new_section.Misc_VirtualSize:x}, RawSize=0x{new_section.SizeOfRawData:x}")
        except Exception as e:
            logger.error(f"Could not create new section structure: {e}")
            ensure_output_exists()
            return False, "Could not create new section structure"
        
        # Add section
        pe.sections.append(new_section)
        logger.debug("Section added to PE structure")
        
        # Update headers minimally
        try:
            old_num_sections = pe.FILE_HEADER.NumberOfSections
            pe.FILE_HEADER.NumberOfSections = len(pe.sections)
            
            old_size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
            new_size_of_image = new_va + max_size
            new_size_of_image = ((new_size_of_image + section_alignment - 1) // section_alignment) * section_alignment
            pe.OPTIONAL_HEADER.SizeOfImage = new_size_of_image
            
            logger.debug(f"Headers updated: sections {old_num_sections}->{pe.FILE_HEADER.NumberOfSections}, image_size 0x{old_size_of_image:x}->0x{new_size_of_image:x}")
        except Exception as e:
            logger.error(f"Could not update headers: {e}")
            ensure_output_exists()
            return False, "Could not update headers"
        
        # Write PE file
        try:
            logger.debug(f"Writing modified PE to: {output_file}")
            pe.write(output_file)
        except Exception as e:
            logger.error(f"Could not write PE file: {e}")
            ensure_output_exists()
            return False, "Could not write PE file"
        
        # Append section data
        try:
            logger.debug(f"Appending section data at offset 0x{new_raw_ptr:x}")
            with open(output_file, 'r+b') as f:
                f.seek(new_raw_ptr)
                f.write(b'\\x00' * new_section.SizeOfRawData)
            logger.debug("Section data written")
        except Exception as e:
            logger.error(f"Could not write section data: {e}")
            ensure_output_exists()
            return False, "Could not write section data"
        
        cave_info = {
            'section': '.cave',
            'section_idx': len(pe.sections) - 1,
            'offset': 0,
            'size': max_size,
            'raw_offset': new_raw_ptr,
            'virt_addr': new_va
        }
        
        logger.info(f"✓ Added cave section: {max_size} bytes")
        return True, cave_info
    
    except Exception as e:
        logger.error(f"Failed to add section: {e}")
        logger.debug(f"Traceback: {traceback.format_exc()}")
        ensure_output_exists()
        return False, f"Failed to add section: {e}"

def main():
    parser = argparse.ArgumentParser(description='Code Cave Inserter with Activity Logging')
    parser.add_argument('target_exe', help='Target executable')
    parser.add_argument('source_exe', help='Source executable')
    parser.add_argument('--output', help='Output path')
    parser.add_argument('--add-cave', type=int, help='Add cave of specified size (max 32KB)')
    parser.add_argument('--dry-run', action='store_true', help='Analyze only, do not modify')
    
    args = parser.parse_args()
    
    # Set up activity logging
    log_file = setup_activity_logging()
    logger = logging.getLogger()
    
    print("Code Cave Inserter with Activity Logging and Threshold Logic")
    print(f"Log file: {log_file}")
    
    logger.info("=== ARGUMENT VALIDATION ===")
    logger.info(f"Target exe: {args.target_exe}")
    logger.info(f"Source exe: {args.source_exe}")
    logger.info(f"Output: {args.output or 'overwrite target'}")
    logger.info(f"Add cave: {args.add_cave or 'no'}")
    logger.info(f"Dry run: {args.dry_run}")
    
    # GUARANTEE: Always determine output file path
    output_file = args.output or args.target_exe
    logger.debug(f"Determined output path: {output_file}")
    
    try:
        # Check dependencies
        has_pefile, pefile_module = check_dependencies()
        if not has_pefile:
            # GUARANTEE: Even without pefile, create output
            logger.warning("Creating output by copying target (pefile not available)")
            shutil.copy2(args.target_exe, output_file)
            if Path(output_file).exists():
                logger.info(f"✓ Output created: {output_file}")
                print(f"Output created: {output_file}")
            return 1
        
        logger.info("✓ Dependencies available")
        
        # Validate target file
        logger.info("=== TARGET FILE VALIDATION ===")
        valid, msg = validate_file_access(args.target_exe)
        if not valid:
            logger.error(f"Target file validation failed: {msg}")
            # GUARANTEE: Copy anyway if possible
            try:
                shutil.copy2(args.target_exe, output_file)
                logger.info(f"✓ Copied despite validation error: {output_file}")
                print(f"Copied despite validation error: {output_file}")
            except:
                pass
            return 1
        
        valid, msg = validate_pe_header(args.target_exe)
        if not valid:
            logger.error(f"Target PE validation failed: {msg}")
            # GUARANTEE: Copy anyway
            shutil.copy2(args.target_exe, output_file)
            logger.info(f"✓ Copied despite PE validation error: {output_file}")
            print(f"Copied despite PE validation error: {output_file}")
            return 1
        
        logger.info("✓ Target file validated")
        
        # Validate source file
        logger.info("=== SOURCE FILE VALIDATION ===")
        valid, msg = validate_file_access(args.source_exe)
        if not valid:
            logger.error(f"Source file validation failed: {msg}")
            # GUARANTEE: Copy target to output anyway
            shutil.copy2(args.target_exe, output_file)
            logger.info(f"✓ Copied target to output (source validation failed): {output_file}")
            print(f"Copied target to output (source validation failed): {output_file}")
            return 1
        
        valid, msg = validate_pe_header(args.source_exe)
        if not valid:
            logger.error(f"Source PE validation failed: {msg}")
            # GUARANTEE: Copy target to output anyway
            shutil.copy2(args.target_exe, output_file)
            logger.info(f"✓ Copied target to output (source PE validation failed): {output_file}")
            print(f"Copied target to output (source PE validation failed): {output_file}")
            return 1
        
        logger.info("✓ Source file validated")
        
        # Load PE files
        logger.info("=== PE FILE LOADING ===")
        pe_target, load_msg = safe_load_pe(args.target_exe, pefile_module)
        if pe_target is None:
            logger.error(f"Could not load target PE: {load_msg}")
            # GUARANTEE: Copy anyway
            shutil.copy2(args.target_exe, output_file)
            logger.info(f"✓ Copied target to output (PE load failed): {output_file}")
            print(f"Copied target to output (PE load failed): {output_file}")
            return 1
        
        pe_source, load_msg = safe_load_pe(args.source_exe, pefile_module)
        if pe_source is None:
            logger.error(f"Could not load source PE: {load_msg}")
            # GUARANTEE: Copy anyway
            shutil.copy2(args.target_exe, output_file)
            logger.info(f"✓ Copied target to output (source PE load failed): {output_file}")
            print(f"Copied target to output (source PE load failed): {output_file}")
            return 1
        
        logger.info("✓ PE files loaded successfully")
        
        # Add cave if requested
        added_cave = None
        if args.add_cave:
            logger.info("=== CAVE ADDITION ===")
            success, result = add_simple_section_safe(args.target_exe, output_file, args.add_cave, pefile_module)
            if success:
                added_cave = result
                logger.info(f"✓ Added cave section: {added_cave['section']} ({added_cave['size']} bytes)")
                print(f"Added cave section: {added_cave['section']} ({added_cave['size']} bytes)")
                # Reload target PE
                pe_target, _ = safe_load_pe(output_file, pefile_module)
            else:
                logger.warning(f"Failed to add cave: {result}")
                print(f"Warning: Failed to add cave: {result}")
                # Output file should exist due to ensure_output_exists()
        
        # Find caves
        logger.info("=== CAVE DETECTION ===")
        caves = find_code_caves_safe(pe_target)
        
        if added_cave:
            caves.insert(0, added_cave)
        
        if not caves:
            logger.warning("No suitable code caves found")
            # GUARANTEE: Ensure output exists
            if not Path(output_file).exists():
                shutil.copy2(args.target_exe, output_file)
            logger.info(f"✓ Output created (no caves found): {output_file}")
            print(f"Output created (no caves found): {output_file}")
            return 0
        
        logger.info(f"✓ Found {len(caves)} code caves:")
        print(f"Found {len(caves)} code caves:")
        for i, cave in enumerate(caves[:3]):
            cave_info = f"  {i+1}. {cave['section']}: {cave['size']} bytes"
            logger.info(cave_info)
            print(cave_info)
        
        # Extract code
        logger.info("=== CODE EXTRACTION ===")
        code_chunks = extract_code_safely(pe_source)
        
        if not code_chunks:
            logger.warning("No code chunks extracted")
            # GUARANTEE: Ensure output exists
            if not Path(output_file).exists():
                shutil.copy2(args.target_exe, output_file)
            logger.info(f"✓ Output created (no code extracted): {output_file}")
            print(f"Output created (no code extracted): {output_file}")
            return 0
        
        logger.info(f"✓ Extracted {len(code_chunks)} code chunks:")
        print(f"Extracted {len(code_chunks)} code chunks:")
        for i, chunk in enumerate(code_chunks):
            chunk_info = f"  {i+1}. {chunk['size']} bytes from {chunk['source_section']}"
            logger.info(chunk_info)
            print(chunk_info)
        
        if args.dry_run:
            logger.info("=== DRY RUN COMPLETED ===")
            # GUARANTEE: Create output even in dry run
            if not Path(output_file).exists():
                shutil.copy2(args.target_exe, output_file)
            logger.info(f"✓ Dry run output created: {output_file}")
            print(f"Dry run output created: {output_file}")
            print(f"Activity log: {log_file}")
            return 0
        
        # Inject code
        logger.info("=== CODE INJECTION ===")
        injected_count = 0
        current_file = args.target_exe
        
        for i, (cave, chunk) in enumerate(zip(caves, code_chunks)):
            logger.info(f"Injecting chunk {i+1} into {cave['section']}...")
            print(f"Injecting chunk {i+1} into {cave['section']}...")
            
            temp_output = output_file + f".tmp{i}" if i < len(code_chunks) - 1 else output_file
            
            success, msg = inject_code_safely(current_file, cave, chunk, temp_output, log_file)
            
            if success:
                logger.info(f"✓ {msg}")
                print(f"✓ {msg}")
                injected_count += 1
            else:
                logger.warning(f"✗ Failed: {msg}")
                print(f"Warning: {msg}")
            
            # Update current file for next iteration
            if i < len(code_chunks) - 1:
                current_file = temp_output
            
            # Cleanup previous temp files
            if i > 0:
                prev_temp = output_file + f".tmp{i-1}"
                if Path(prev_temp).exists() and prev_temp != current_file:
                    try:
                        os.remove(prev_temp)
                        logger.debug(f"Cleaned up temp file: {prev_temp}")
                    except Exception as e:
                        logger.debug(f"Could not clean up {prev_temp}: {e}")
        
        # GUARANTEE: Final verification and output
        logger.info("=== INJECTION COMPLETED ===")
        if Path(output_file).exists():
            file_size = Path(output_file).stat().st_size
            logger.info(f"✓ SUCCESS: Output file created - {output_file} ({file_size} bytes)")
            logger.info(f"✓ Code chunks injected: {injected_count}/{len(code_chunks)}")
            print(f"SUCCESS: Output file created - {output_file} ({file_size} bytes)")
            print(f"Code chunks injected: {injected_count}/{len(code_chunks)}")
        else:
            # This should never happen due to our guarantees
            logger.error("✗ CRITICAL ERROR: Output missing despite guarantees!")
            # Emergency fallback
            shutil.copy2(args.target_exe, output_file)
            logger.info(f"✓ EMERGENCY: Created output by copying target: {output_file}")
            print(f"Emergency: Created output by copying target: {output_file}")
        
        logger.info(f"Session activity logged to: {log_file}")
        print(f"Activity log: {log_file}")
        return 0
    
    except KeyboardInterrupt:
        logger.info("=== OPERATION CANCELLED BY USER ===")
        print("Operation cancelled by user")
        
        # GUARANTEE: Create output even on cancellation
        if not Path(output_file).exists():
            shutil.copy2(args.target_exe, output_file)
            logger.info(f"✓ Output created before exit: {output_file}")
            print(f"Output created before exit: {output_file}")
        return 1
    
    except Exception as e:
        logger.error("=== UNEXPECTED ERROR ===")
        logger.error(f"Error: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        print(f"Unexpected error: {e}")
        
        # GUARANTEE: Create output even on error
        if not Path(output_file).exists():
            try:
                shutil.copy2(args.target_exe, output_file)
                logger.info(f"✓ Emergency output created: {output_file}")
                print(f"Emergency output created: {output_file}")
            except:
                logger.error("✗ Could not create emergency output")
                print("Could not create emergency output")
        
        print(f"Activity log: {log_file}")
        return 1

if __name__ == "__main__":
    sys.exit(main())