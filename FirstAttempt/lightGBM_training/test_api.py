#!/usr/bin/env python3
"""
Test script for malware detection API
Tests the competition format requirements
"""

import requests
import os
import time
import json
from pathlib import Path

def test_api_endpoint(api_url: str = "http://localhost:8080/"):
    """Test the malware detection API endpoint"""
    
    print(f"Testing API at: {api_url}")
    
    # Test health check
    try:
        response = requests.get(f"{api_url}health", timeout=5)
        if response.status_code == 200:
            print("✓ Health check passed")
            print(f"  Status: {response.json()}")
        else:
            print("✗ Health check failed")
            return False
    except Exception as e:
        print(f"✗ Health check error: {e}")
        return False
    
    return True

def test_malware_detection(file_path: str, api_url: str = "http://localhost:8080/"):
    """Test malware detection with a file"""
    
    if not os.path.exists(file_path):
        print(f"✗ Test file not found: {file_path}")
        return
    
    print(f"Testing file: {file_path}")
    
    try:
        # Read file
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        print(f"  File size: {len(file_data)} bytes")
        
        # Check size limit
        if len(file_data) > 2**21:  # 2 MiB
            print("  ⚠️  File exceeds 2 MiB limit")
        
        # Set headers as required by competition
        headers = {'Content-Type': 'application/octet-stream'}
        
        # Make request and measure time
        start_time = time.time()
        response = requests.post(api_url, data=file_data, headers=headers, timeout=6)
        response_time = time.time() - start_time
        
        print(f"  Response time: {response_time:.3f}s")
        
        if response_time > 5.0:
            print("  ⚠️  Response time exceeds 5 second limit")
        
        if response.status_code == 200:
            result = response.json()
            print(f"  ✓ API Response: {result}")
            
            # Validate response format
            if "result" in result and result["result"] in [0, 1]:
                classification = "Benign" if result["result"] == 0 else "Malware"
                print(f"  Classification: {classification}")
            else:
                print("  ✗ Invalid response format")
        else:
            print(f"  ✗ API Error: {response.status_code} - {response.text}")
            
    except requests.exceptions.Timeout:
        print("  ✗ Request timed out (>6s)")
    except Exception as e:
        print(f"  ✗ Error: {e}")

def create_test_file():
    """Create a dummy PE file for testing"""
    # Create a minimal PE header for testing
    pe_header = b'MZ' + b'\x00' * 60 + b'PE\x00\x00'
    test_file = "test_sample.exe"
    
    with open(test_file, 'wb') as f:
        f.write(pe_header + b'\x00' * 1000)  # Add some data
    
    print(f"Created test file: {test_file}")
    return test_file

def main():
    """Main test function"""
    print("=" * 50)
    print("Malware Detection API Test Suite")
    print("=" * 50)
    
    api_url = "http://localhost:8080/"
    
    # Test API availability
    if not test_api_endpoint(api_url):
        print("\n✗ API is not accessible. Make sure it's running on port 8080")
        return
    
    print("\n" + "=" * 30)
    print("Testing with sample files")
    print("=" * 30)
    
    # Look for existing PE files to test
    test_files = []
    
    # Check for Windows system files (if available)
    windows_files = [
        "/mnt/c/Windows/System32/notepad.exe",  # WSL path
        "C:\\Windows\\System32\\notepad.exe",   # Windows path
    ]
    
    for file_path in windows_files:
        if os.path.exists(file_path):
            test_files.append(file_path)
    
    # If no real PE files found, create a test file
    if not test_files:
        test_file = create_test_file()
        test_files.append(test_file)
    
    # Test each file
    for test_file in test_files:
        print(f"\n--- Testing: {test_file} ---")
        test_malware_detection(test_file, api_url)
    
    print("\n" + "=" * 50)
    print("Test completed!")
    print("=" * 50)

if __name__ == "__main__":
    main()
