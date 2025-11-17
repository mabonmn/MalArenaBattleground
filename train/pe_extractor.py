#!/usr/bin/env python3
"""
PE Attribute Extractor for malware analysis.

Extracts string-based attributes from PE files using LIEF, handling errors gracefully.
"""
import re
import math
import lief
import warnings
import sys
from io import StringIO
from typing import Dict, Any

# Suppress general warnings
warnings.filterwarnings('ignore')


class PEAttributeExtractor:
    """Extracts string-based attributes from PE files using LIEF, handling errors gracefully."""
    
    def __init__(self, bytez: bytes):
        """
        Initialize with raw bytes of a PE file.
        
        Args:
            bytez (bytes): Raw bytes of the PE file.
        """
        self.bytez = bytez
        self.lief_binary = None
        self.attributes = {}
        self.libraries = ""
        self.functions = ""
        self.exports = ""
        
        # Suppress LIEF output by redirecting stderr temporarily
        old_stderr = sys.stderr
        sys.stderr = StringIO()
        try:
            self.lief_binary = lief.PE.parse(list(bytez))
        except Exception as e:
            self.attributes["parse_error"] = str(e)
        finally:
            sys.stderr = old_stderr

    def extract_string_metadata(self):
        """Extract string-based metadata like paths, URLs, registry keys, and MZ headers."""
        paths = re.compile(b'c:\\\\', re.IGNORECASE)
        urls = re.compile(b'https?://', re.IGNORECASE)
        registry = re.compile(b'HKEY_')
        mz = re.compile(b'MZ')
        return {
            'string_paths': len(paths.findall(self.bytez)),
            'string_urls': len(urls.findall(self.bytez)),
            'string_registry': len(registry.findall(self.bytez)),
            'string_MZ': len(mz.findall(self.bytez))
        }

    def extract_entropy(self):
        """Calculate Shannon entropy of the byte sequence."""
        if not self.bytez:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(self.bytez.count(bytes([x]))) / len(self.bytez)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def extract(self):
        """Extract PE attributes including headers, imports, exports, and entropy, setting defaults on failure."""
        # Always extract non-LIEF dependent attributes
        self.attributes.update({"size": len(self.bytez)})
        self.attributes.update({"entropy": self.extract_entropy()})
        self.attributes.update(self.extract_string_metadata())

        if not self.lief_binary or not isinstance(self.lief_binary, lief.PE.Binary):
            # Set all LIEF-dependent attributes to defaults if parsing failed
            self.attributes.update({
                "virtual_size": 0,
                "has_debug": 0,
                "imports": 0,
                "exports": 0,
                "has_relocations": 0,
                "has_resources": 0,
                "has_signature": 0,
                "has_tls": 0,
                "symbols": 0,
                "timestamp": 0,
                "machine": "",
                "numberof_sections": 0,
                "numberof_symbols": 0,
                "pointerto_symbol_table": 0,
                "sizeof_optional_header": 0,
                "characteristics": 0,
                "characteristics_list": "",
                "baseof_code": 0,
                "baseof_data": 0,
                "dll_characteristics": 0,
                "dll_characteristics_list": "",
                "file_alignment": 0,
                "imagebase": 0,
                "magic": "",
                "PE_TYPE": 0,
                "major_image_version": 0,
                "minor_image_version": 0,
                "major_linker_version": 0,
                "minor_linker_version": 0,
                "major_operating_system_version": 0,
                "minor_operating_system_version": 0,
                "major_subsystem_version": 0,
                "minor_subsystem_version": 0,
                "numberof_rva_and_size": 0,
                "sizeof_code": 0,
                "sizeof_headers": 0,
                "sizeof_heap_commit": 0,
                "sizeof_image": 0,
                "sizeof_initialized_data": 0,
                "sizeof_uninitialized_data": 0,
                "subsystem": "",
                "functions": "",
                "libraries": "",
                "exports_list": ""
            })
            return self.attributes

        def get_attr(obj, attr, default=0):
            try:
                return getattr(obj, attr)
            except (AttributeError, Exception):
                return default

        # General information
        try:
            self.attributes.update({
                "virtual_size": get_attr(self.lief_binary, "virtual_size", 0),
                "has_debug": int(get_attr(self.lief_binary, "has_debug", False)),
                "imports": len(get_attr(self.lief_binary, "imports", [])),
                "exports": len(get_attr(self.lief_binary, "exported_functions", [])),
                "has_relocations": int(get_attr(self.lief_binary, "has_relocations", False)),
                "has_resources": int(get_attr(self.lief_binary, "has_resources", False)),
                "has_signature": int(get_attr(self.lief_binary, "has_signature", False)),
                "has_tls": int(get_attr(self.lief_binary, "has_tls", False)),
                "symbols": len(get_attr(self.lief_binary, "symbols", [])),
            })
        except Exception:
            pass  # Defaults already set above if full failure, or partial skips

        # Header information
        header = get_attr(self.lief_binary, "header", None)
        if header:
            try:
                self.attributes.update({
                    "timestamp": get_attr(header, "time_date_stamps", 0),
                    "machine": str(get_attr(header, "machine", "")),
                    "numberof_sections": get_attr(header, "numberof_sections", 0),
                    "numberof_symbols": get_attr(header, "numberof_symbols", 0),
                    "pointerto_symbol_table": get_attr(header, "pointerto_symbol_table", 0),
                    "sizeof_optional_header": get_attr(header, "sizeof_optional_header", 0),
                    "characteristics": int(get_attr(header, "characteristics", 0)),
                    "characteristics_list": " ".join([str(c).replace("HEADER_CHARACTERISTICS.", "") for c in get_attr(header, "characteristics_list", [])])
                })
            except Exception:
                pass

        # Optional header information
        optional_header = get_attr(self.lief_binary, "optional_header", None)
        if optional_header:
            try:
                baseof_data = get_attr(optional_header, "baseof_data", 0)
                self.attributes.update({
                    "baseof_code": get_attr(optional_header, "baseof_code", 0),
                    "baseof_data": baseof_data,
                    "dll_characteristics": get_attr(optional_header, "dll_characteristics", 0),
                    "dll_characteristics_list": " ".join([str(d).replace("DLL_CHARACTERISTICS.", "") for d in get_attr(optional_header, "dll_characteristics_lists", [])]),
                    "file_alignment": get_attr(optional_header, "file_alignment", 0),
                    "imagebase": get_attr(optional_header, "imagebase", 0),
                    "magic": str(get_attr(optional_header, "magic", "")).replace("PE_TYPE.", ""),
                    "PE_TYPE": int(get_attr(optional_header, "magic", 0)),
                    "major_image_version": get_attr(optional_header, "major_image_version", 0),
                    "minor_image_version": get_attr(optional_header, "minor_image_version", 0),
                    "major_linker_version": get_attr(optional_header, "major_linker_version", 0),
                    "minor_linker_version": get_attr(optional_header, "minor_linker_version", 0),
                    "major_operating_system_version": get_attr(optional_header, "major_operating_system_version", 0),
                    "minor_operating_system_version": get_attr(optional_header, "minor_operating_system_version", 0),
                    "major_subsystem_version": get_attr(optional_header, "major_subsystem_version", 0),
                    "minor_subsystem_version": get_attr(optional_header, "minor_subsystem_version", 0),
                    "numberof_rva_and_size": get_attr(optional_header, "numberof_rva_and_size", 0),
                    "sizeof_code": get_attr(optional_header, "sizeof_code", 0),
                    "sizeof_headers": get_attr(optional_header, "sizeof_headers", 0),
                    "sizeof_heap_commit": get_attr(optional_header, "sizeof_heap_commit", 0),
                    "sizeof_image": get_attr(optional_header, "sizeof_image", 0),
                    "sizeof_initialized_data": get_attr(optional_header, "sizeof_initialized_data", 0),
                    "sizeof_uninitialized_data": get_attr(optional_header, "sizeof_uninitialized_data", 0),
                    "subsystem": str(get_attr(optional_header, "subsystem", "")).replace("SUBSYSTEM.", "")
                })
            except Exception:
                pass

        # Imports
        try:
            if get_attr(self.lief_binary, "has_imports", False):
                self.libraries = " ".join([l for l in get_attr(self.lief_binary, "libraries", [])])
                self.functions = " ".join([f.name for f in get_attr(self.lief_binary, "imported_functions", [])])
            self.attributes.update({"functions": self.functions, "libraries": self.libraries})
        except Exception:
            self.attributes.update({"functions": "", "libraries": ""})

        # Exports
        try:
            if get_attr(self.lief_binary, "has_exports", False):
                self.exports = " ".join([f.name for f in get_attr(self.lief_binary, "exported_functions", [])])
            self.attributes.update({"exports_list": self.exports})
        except Exception:
            self.attributes.update({"exports_list": ""})

        return self.attributes