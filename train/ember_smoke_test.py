#!/usr/bin/env python3
"""
Smoke test for EMBER2024 LightGBM implementation.
Tests basic functionality without requiring the full dataset.
"""
import os
import sys
import tempfile
from pathlib import Path


def test_imports():
    """Test that required packages can be imported."""
    print("Testing imports...")
    
    try:
        import numpy as np
        print("✓ numpy")
    except ImportError as e:
        print(f"✗ numpy: {e}")
        return False
    
    try:
        import lightgbm as lgb
        print("✓ lightgbm")
    except ImportError as e:
        print(f"✗ lightgbm: {e}")
        return False
    
    try:
        import flask
        print("✓ flask")
    except ImportError as e:
        print(f"✗ flask: {e}")
        return False
    
    try:
        import gevent
        print("✓ gevent")
    except ImportError as e:
        print(f"✗ gevent: {e}")
        return False
    
    return True


def test_ember_installation():
    """Test EMBER2024 installation."""
    print("\nTesting EMBER2024...")
    
    try:
        import thrember
        print("✓ thrember imported")
        
        # Test feature extractor
        try:
            extractor = thrember.features.PEFeatureExtractor()
            print(f"✓ Feature extractor created ({extractor.dim} features)")
            return True
        except Exception as e:
            print(f"✗ Feature extractor error: {e}")
            if "libcrypto" in str(e):
                print("  This is likely a system dependency issue.")
                print("  Try: sudo apt-get update && sudo apt-get install libssl-dev")
                print("  Or: pip uninstall thrember && pip install git+https://github.com/FutureComputing4AI/EMBER2024.git")
            return False
        
    except ImportError as e:
        print(f"✗ thrember: {e}")
        print("  Install with: pip install git+https://github.com/FutureComputing4AI/EMBER2024.git")
        return False
    except Exception as e:
        print(f"✗ thrember error: {e}")
        return False


def test_model_class():
    """Test the EMBER LightGBM model class."""
    print("\nTesting model class...")
    
    try:
        # Add current directory to Python path
        import sys
        sys.path.insert(0, os.path.join(os.getcwd(), 'defender'))
        
        from defender.models.ember_lightgbm_model import EmberLightGBMModel
        print("✓ EmberLightGBMModel imported")
        return True
    except ImportError as e:
        print(f"✗ EmberLightGBMModel: {e}")
        return False


def test_file_structure():
    """Test that required files exist."""
    print("\nTesting file structure...")
    
    required_files = [
        "train/setup_ember2024.py",
        "train/train_lightgbm_ember.py", 
        "train/run_ember_pipeline.sh",
        "defender/defender/__main__.py",
        "defender/defender/models/ember_lightgbm_model.py",
        "defender/requirements.txt",
        "defender/docker-requirements.txt",
        "defender/Dockerfile",
        "tools/batch_scan.py"
    ]
    
    all_exist = True
    for file_path in required_files:
        if os.path.isfile(file_path):
            print(f"✓ {file_path}")
        else:
            print(f"✗ {file_path}")
            all_exist = False
    
    return all_exist


def test_scripts_executable():
    """Test that shell scripts are executable."""
    print("\nTesting script permissions...")
    
    scripts = [
        "train/run_ember_pipeline.sh",
        "tools/batch_scan.py"
    ]
    
    all_executable = True
    for script in scripts:
        if os.path.isfile(script) and os.access(script, os.X_OK):
            print(f"✓ {script} (executable)")
        else:
            print(f"✗ {script} (not executable)")
            all_executable = False
    
    return all_executable


def test_docker_build_dry_run():
    """Test Docker build context (dry run)."""
    print("\nTesting Docker build context...")
    
    dockerfile_path = "defender/Dockerfile"
    if not os.path.isfile(dockerfile_path):
        print(f"✗ Dockerfile not found: {dockerfile_path}")
        return False
    
    # Check required files for Docker build
    docker_files = [
        "defender/docker-requirements.txt",
        "defender/defender/__main__.py",
        "defender/defender/models/ember_lightgbm_model.py"
    ]
    
    all_exist = True
    for file_path in docker_files:
        if os.path.isfile(file_path):
            print(f"✓ {file_path}")
        else:
            print(f"✗ {file_path}")
            all_exist = False
    
    return all_exist


def main():
    """Run all smoke tests."""
    print("=" * 50)
    print("EMBER2024 LightGBM Smoke Test")
    print("=" * 50)
    
    tests = [
        ("Basic imports", test_imports),
        ("EMBER2024 installation", test_ember_installation), 
        ("Model class", test_model_class),
        ("File structure", test_file_structure),
        ("Script permissions", test_scripts_executable),
        ("Docker build context", test_docker_build_dry_run)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"✗ {test_name}: Exception - {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 50)
    print("SMOKE TEST SUMMARY")
    print("=" * 50)
    
    passed = 0
    for test_name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"{status:4} | {test_name}")
        if result:
            passed += 1
    
    print(f"\nPassed: {passed}/{len(tests)}")
    
    if passed == len(tests):
        print("\n✓ All smoke tests passed! Ready to run training pipeline.")
        print("\nNext steps:")
        print("1. Run: ./train/run_ember_pipeline.sh")
        print("2. Wait for training to complete (~1-2 hours)")
        print("3. Build Docker: cd defender && docker build -t mydefender .")
        print("4. Run defender: docker run -p 8080:8080 mydefender")
        return 0
    else:
        print(f"\n✗ {len(tests) - passed} smoke tests failed.")
        print("\nPlease fix the issues above before proceeding.")
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
