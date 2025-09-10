#!/usr/bin/env python3
"""
Debug script to isolate the EMBER vectorization error
"""

import os
import sys
from pathlib import Path

def test_ember_vectorization():
    """Test EMBER vectorization step by step"""
    
    data_dir = Path("ember2018")
    
    try:
        import ember
        print("EMBER library imported successfully")
        
        # Try to understand what create_vectorized_features does internally
        print(f"Data directory: {data_dir}")
        print(f"Files in directory: {list(data_dir.glob('*.jsonl'))}")
        
        # Let's try to call create_vectorized_features with verbose output
        print("Attempting vectorization...")
        ember.create_vectorized_features(data_dir, feature_version=2)
        
    except Exception as e:
        print(f"Error during vectorization: {e}")
        print(f"Error type: {type(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_ember_vectorization()
