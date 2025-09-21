"""
String-based CNN model wrapper for the defender service.
"""
import torch
import torch.nn as nn
import numpy as np
import re
import math
import lief
import warnings
import sys
from io import StringIO
from typing import Tuple, Dict, Any
import os

# Suppress general warnings
warnings.filterwarnings('ignore')

PAD_IDX = 256


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
            self.attributes.update({"functions": self.libraries, "libraries": self.libraries})
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


class TextCNNWithStrings(nn.Module):
    def __init__(self, emb_dim: int, num_kernels: int, kernels: Tuple[int, ...], num_string_features: int = 16, num_classes: int = 1):
        super().__init__()
        # Larger token embedding and multi-layer CNN
        self.embed = nn.Embedding(num_embeddings=PAD_IDX + 1, embedding_dim=emb_dim, padding_idx=PAD_IDX)
        
        # Multiple CNN layers with different kernel sizes
        self.convs_layer1 = nn.ModuleList([nn.Conv1d(in_channels=emb_dim, out_channels=num_kernels, kernel_size=k) for k in kernels])
        self.convs_layer2 = nn.ModuleList([nn.Conv1d(in_channels=num_kernels, out_channels=num_kernels * 2, kernel_size=k) for k in kernels])
        
        # Batch normalization for stability
        self.bn1 = nn.ModuleList([nn.BatchNorm1d(num_kernels) for _ in kernels])
        self.bn2 = nn.ModuleList([nn.BatchNorm1d(num_kernels * 2) for _ in kernels])
        
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(0.3)
        self.dropout_heavy = nn.Dropout(0.5)
        
        # Larger string feature processing with multiple layers
        self.string_fc1 = nn.Linear(num_string_features, 64)
        self.string_fc2 = nn.Linear(64, 128)
        self.string_bn = nn.BatchNorm1d(128)
        
        # Larger combined features with deeper MLP
        combined_size = (num_kernels * 2) * len(kernels) + 128
        self.fc1 = nn.Linear(combined_size, 512)
        self.fc2 = nn.Linear(512, 256)
        self.fc3 = nn.Linear(256, 128)
        self.out = nn.Linear(128, num_classes)
        
        # Batch normalization for FC layers
        self.fc_bn1 = nn.BatchNorm1d(512)
        self.fc_bn2 = nn.BatchNorm1d(256)

    def forward(self, x_tokens: torch.Tensor, x_strings: torch.Tensor) -> torch.Tensor:
        # Token CNN path with multiple layers
        x = self.embed(x_tokens)           # (batch, seq_len, emb)
        x = x.transpose(1, 2)              # (batch, emb, seq_len)
        
        # First CNN layer
        cnn_feats_l1 = []
        for i, conv in enumerate(self.convs_layer1):
            h = self.relu(self.bn1[i](conv(x)))     # (batch, num_kernels, L')
            h = torch.max(h, dim=2).values          # global max-pool -> (batch, num_kernels)
            cnn_feats_l1.append(h)
        
        # Second CNN layer (applied to each branch separately)
        cnn_feats_l2 = []
        for i, (conv1_out, conv2) in enumerate(zip(cnn_feats_l1, self.convs_layer2)):
            # Reshape for conv2: add sequence dimension back
            h_reshaped = conv1_out.unsqueeze(2).expand(-1, -1, 100)  # (batch, num_kernels, 100)
            h = self.relu(self.bn2[i](conv2(h_reshaped)))           # (batch, num_kernels*2, L'')
            h = torch.max(h, dim=2).values                          # global max-pool -> (batch, num_kernels*2)
            cnn_feats_l2.append(h)
        
        cnn_out = torch.cat(cnn_feats_l2, dim=1)   # (batch, num_kernels*2 * len(kernels))
        cnn_out = self.dropout(cnn_out)
        
        # Enhanced string features path
        string_out = self.relu(self.string_fc1(x_strings))  # (batch, 64)
        string_out = self.dropout(string_out)
        string_out = self.relu(self.string_bn(self.string_fc2(string_out)))  # (batch, 128)
        string_out = self.dropout(string_out)
        
        # Combine features with deeper MLP
        combined = torch.cat([cnn_out, string_out], dim=1)  # (batch, combined_size)
        
        # Deep fully connected layers
        z = self.relu(self.fc_bn1(self.fc1(combined)))      # (batch, 512)
        z = self.dropout_heavy(z)
        z = self.relu(self.fc_bn2(self.fc2(z)))             # (batch, 256)
        z = self.dropout(z)
        z = self.relu(self.fc3(z))                          # (batch, 128)
        z = self.dropout(z)
        
        logits = self.out(z).squeeze(1)
        return logits


class StringCNNModel:
    """Wrapper for our string-based CNN model that matches the defender interface."""
    
    def __init__(self, weights_path: str, max_bytes: int = 1048576, threshold: float = 0.5, 
                 device: str = 'cpu', emb_dim: int = 32, num_kernels: int = 128, 
                 kernels: Tuple[int, ...] = (3, 5, 7, 9, 11), strings_only: bool = False):
        self.weights_path = weights_path
        self.max_bytes = max_bytes
        self.threshold = threshold
        self.device = torch.device(device)
        self.strings_only = strings_only
        
        # Initialize model
        self.model = TextCNNWithStrings(
            emb_dim=emb_dim,
            num_kernels=num_kernels,
            kernels=kernels,
            num_string_features=16,
            num_classes=1
        )
        
        # Load weights if file exists
        if os.path.isfile(weights_path):
            state_dict = torch.load(weights_path, map_location=self.device)
            self.model.load_state_dict(state_dict)
            print(f"Loaded StringCNN weights from {weights_path}")
        else:
            print(f"Warning: StringCNN weights not found at {weights_path}, using random weights")
            
        self.model.to(self.device)
        self.model.eval()
    
    def to_tokens(self, bytez: bytes, max_len: int) -> np.ndarray:
        """Convert bytes to tokens."""
        if self.strings_only:
            # Keep printable ASCII plus common whitespace (\t,\n,\r)
            filtered = bytearray()
            for b in bytez:
                if 32 <= b <= 126 or b in (9, 10, 13):
                    filtered.append(b)
            arr = np.frombuffer(bytes(filtered), dtype=np.uint8)
        else:
            arr = np.frombuffer(bytez, dtype=np.uint8)
        if arr.size > max_len:
            arr = arr[:max_len]
        if arr.size < max_len:
            arr = np.pad(arr, (0, max_len - arr.size), mode='constant', constant_values=PAD_IDX)
        return arr.astype(np.int64)
    
    def extract_string_features(self, attributes: Dict[str, Any]) -> np.ndarray:
        """Extract key string-based features from PE attributes."""
        features = [
            float(attributes.get('size', 0)) / 1e6,  # Size in MB
            float(attributes.get('entropy', 0)),
            float(attributes.get('string_paths', 0)),
            float(attributes.get('string_urls', 0)), 
            float(attributes.get('string_registry', 0)),
            float(attributes.get('string_MZ', 0)),
            float(attributes.get('imports', 0)),
            float(attributes.get('exports', 0)),
            float(attributes.get('numberof_sections', 0)),
            float(attributes.get('has_debug', 0)),
            float(attributes.get('has_relocations', 0)),
            float(attributes.get('has_resources', 0)),
            float(attributes.get('has_signature', 0)),
            float(attributes.get('has_tls', 0)),
            float(len(attributes.get('functions', '').split())),  # Function count
            float(len(attributes.get('libraries', '').split())),  # Library count
        ]
        return np.array(features, dtype=np.float32)
    
    def predict(self, bytez: bytes) -> int:
        """Predict if bytes are malware (1) or goodware (0)."""
        try:
            # Check size limit
            if len(bytez) > 50 * 1024 * 1024:  # 50MB limit
                return 0  # Default to goodware for oversized files
            
            # Extract PE attributes
            extractor = PEAttributeExtractor(bytez)
            attributes = extractor.extract()
            
            # Get tokens and string features
            tokens = self.to_tokens(bytez, self.max_bytes)
            string_feats = self.extract_string_features(attributes)
            
            # Convert to tensors
            x_tokens = torch.from_numpy(tokens).unsqueeze(0).to(self.device)  # Add batch dim
            x_strings = torch.from_numpy(string_feats).unsqueeze(0).to(self.device)  # Add batch dim
            
            # Run inference
            with torch.no_grad():
                logits = self.model(x_tokens, x_strings)
                prob = torch.sigmoid(logits).item()
                
            # Apply threshold
            return int(prob >= self.threshold)
            
        except Exception as e:
            print(f"StringCNN prediction error: {e}")
            return 0  # Default to goodware on error
    
    def get_info(self) -> dict:
        """Return model metadata."""
        return {
            "name": "stringcnn",
            "device": str(self.device),
            "max_bytes": self.max_bytes,
            "threshold": self.threshold,
            "strings_only": self.strings_only,
            "weights_path": self.weights_path
        }