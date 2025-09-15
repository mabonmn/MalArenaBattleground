#!/usr/bin/env python3
"""
Batch scanning tool for testing the defender malware classification API.
Supports testing with the new EMBER LightGBM model and provides detailed performance metrics.
"""
import argparse
import csv
import json
import os
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
import requests
from tqdm import tqdm


def scan_file(url: str, file_path: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Scan a single file using the defender API.
    
    Args:
        url: API endpoint URL
        file_path: Path to file to scan
        timeout: Request timeout in seconds
    
    Returns:
        Dictionary with scan results and metadata
    """
    start_time = time.time()
    
    result = {
        'file_path': file_path,
        'file_size': 0,
        'prediction': None,
        'response_time': 0,
        'success': False,
        'error': None
    }
    
    try:
        # Get file size
        file_size = os.path.getsize(file_path)
        result['file_size'] = file_size
        
        # Read file
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Make API request
        headers = {'Content-Type': 'application/octet-stream'}
        response = requests.post(url, data=file_data, headers=headers, timeout=timeout)
        
        response_time = time.time() - start_time
        result['response_time'] = response_time
        
        if response.status_code == 200:
            try:
                response_data = response.json()
                result['prediction'] = response_data.get('result')
                result['success'] = True
            except json.JSONDecodeError:
                result['error'] = 'Invalid JSON response'
        else:
            result['error'] = f'HTTP {response.status_code}: {response.text}'
    
    except FileNotFoundError:
        result['error'] = 'File not found'
    except requests.exceptions.Timeout:
        result['error'] = 'Request timeout'
        result['response_time'] = timeout
    except requests.exceptions.ConnectionError:
        result['error'] = 'Connection error'
    except Exception as e:
        result['error'] = str(e)
    
    return result


def collect_files(paths: List[str], recursive: bool = True, extensions: Optional[List[str]] = None) -> List[str]:
    """
    Collect files from given paths.
    
    Args:
        paths: List of file or directory paths
        recursive: Whether to recursively search directories
        extensions: List of file extensions to include (e.g., ['.exe', '.dll'])
    
    Returns:
        List of file paths
    """
    files = []
    
    for path_str in paths:
        path = Path(path_str)
        
        if path.is_file():
            files.append(str(path))
        elif path.is_dir():
            if recursive:
                pattern = '**/*'
            else:
                pattern = '*'
            
            for file_path in path.glob(pattern):
                if file_path.is_file():
                    if extensions is None or file_path.suffix.lower() in extensions:
                        files.append(str(file_path))
        else:
            print(f"Warning: Path not found: {path}")
    
    return files


def analyze_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze batch scan results and compute metrics."""
    
    successful_scans = [r for r in results if r['success']]
    failed_scans = [r for r in results if not r['success']]
    
    if not successful_scans:
        return {
            'total_files': len(results),
            'successful_scans': 0,
            'failed_scans': len(failed_scans),
            'success_rate': 0.0
        }
    
    # Response time statistics
    response_times = [r['response_time'] for r in successful_scans]
    avg_response_time = sum(response_times) / len(response_times)
    max_response_time = max(response_times)
    min_response_time = min(response_times)
    
    # Prediction statistics
    malicious_count = sum(1 for r in successful_scans if r['prediction'] == 1)
    benign_count = sum(1 for r in successful_scans if r['prediction'] == 0)
    
    # File size statistics
    file_sizes = [r['file_size'] for r in successful_scans]
    avg_file_size = sum(file_sizes) / len(file_sizes) if file_sizes else 0
    max_file_size = max(file_sizes) if file_sizes else 0
    
    # Error analysis
    error_counts = {}
    for result in failed_scans:
        error = result.get('error', 'Unknown error')
        error_counts[error] = error_counts.get(error, 0) + 1
    
    analysis = {
        'total_files': len(results),
        'successful_scans': len(successful_scans),
        'failed_scans': len(failed_scans),
        'success_rate': len(successful_scans) / len(results),
        'predictions': {
            'malicious': malicious_count,
            'benign': benign_count,
            'malicious_rate': malicious_count / len(successful_scans) if successful_scans else 0
        },
        'response_times': {
            'avg': avg_response_time,
            'min': min_response_time,
            'max': max_response_time,
            'exceeds_5s': sum(1 for t in response_times if t > 5.0)
        },
        'file_sizes': {
            'avg': avg_file_size,
            'max': max_file_size
        },
        'errors': error_counts
    }
    
    return analysis


def save_results(results: List[Dict[str, Any]], output_path: str, analysis: Dict[str, Any]):
    """Save results to CSV file and analysis to JSON."""
    
    # Save detailed results to CSV
    csv_path = output_path
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        if results:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
    
    print(f"Detailed results saved to: {csv_path}")
    
    # Save analysis to JSON
    json_path = csv_path.replace('.csv', '_analysis.json')
    with open(json_path, 'w') as f:
        json.dump(analysis, f, indent=2)
    
    print(f"Analysis saved to: {json_path}")


def print_analysis(analysis: Dict[str, Any]):
    """Print analysis summary."""
    
    print("\n" + "=" * 50)
    print("BATCH SCAN ANALYSIS")
    print("=" * 50)
    
    print(f"Total files: {analysis['total_files']}")
    print(f"Successful scans: {analysis['successful_scans']}")
    print(f"Failed scans: {analysis['failed_scans']}")
    print(f"Success rate: {analysis['success_rate']:.2%}")
    
    if analysis['successful_scans'] > 0:
        print(f"\nPredictions:")
        print(f"  Malicious: {analysis['predictions']['malicious']}")
        print(f"  Benign: {analysis['predictions']['benign']}")
        print(f"  Malicious rate: {analysis['predictions']['malicious_rate']:.2%}")
        
        print(f"\nResponse times:")
        print(f"  Average: {analysis['response_times']['avg']:.3f}s")
        print(f"  Min: {analysis['response_times']['min']:.3f}s")
        print(f"  Max: {analysis['response_times']['max']:.3f}s")
        print(f"  Exceeds 5s: {analysis['response_times']['exceeds_5s']}")
        
        print(f"\nFile sizes:")
        print(f"  Average: {analysis['file_sizes']['avg'] / 1024:.1f} KB")
        print(f"  Max: {analysis['file_sizes']['max'] / 1024:.1f} KB")
    
    if analysis['errors']:
        print(f"\nErrors:")
        for error, count in analysis['errors'].items():
            print(f"  {error}: {count}")


def main():
    parser = argparse.ArgumentParser(description="Batch scan files using defender API")
    parser.add_argument('--url', default='http://localhost:8080',
                       help='Defender API URL')
    parser.add_argument('--dir', '--directory', dest='directories', action='append',
                       help='Directory to scan (can be specified multiple times)')
    parser.add_argument('--file', dest='files', action='append',
                       help='Individual file to scan (can be specified multiple times)')
    parser.add_argument('--recursive', action='store_true', default=True,
                       help='Recursively scan directories')
    parser.add_argument('--extensions', nargs='+',
                       help='File extensions to include (e.g., .exe .dll .scr)')
    parser.add_argument('--output', '--out-csv', default='scan_results.csv',
                       help='Output CSV file path')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds')
    parser.add_argument('--max-files', type=int,
                       help='Maximum number of files to scan')
    
    args = parser.parse_args()
    
    # Collect input paths
    paths = []
    if args.directories:
        paths.extend(args.directories)
    if args.files:
        paths.extend(args.files)
    
    if not paths:
        print("Error: No files or directories specified")
        print("Use --dir /path/to/directory or --file /path/to/file")
        return 1
    
    # Process extensions
    extensions = None
    if args.extensions:
        extensions = [ext if ext.startswith('.') else f'.{ext}' for ext in args.extensions]
        print(f"Filtering for extensions: {extensions}")
    
    # Collect files
    print("Collecting files...")
    all_files = collect_files(paths, args.recursive, extensions)
    
    if not all_files:
        print("No files found to scan")
        return 1
    
    # Limit number of files if specified
    if args.max_files and len(all_files) > args.max_files:
        print(f"Limiting to first {args.max_files} files (out of {len(all_files)} found)")
        all_files = all_files[:args.max_files]
    
    print(f"Found {len(all_files)} files to scan")
    
    # Test API connectivity
    try:
        response = requests.get(args.url.replace('/', '') + '/', timeout=5)
        print(f"✓ API accessible at {args.url}")
    except Exception as e:
        print(f"✗ Cannot connect to API at {args.url}: {e}")
        print("Make sure the defender is running: docker run -p 8080:8080 mydefender")
        return 1
    
    # Scan files
    print(f"\nScanning files...")
    results = []
    
    for file_path in tqdm(all_files, desc="Scanning"):
        result = scan_file(args.url, file_path, args.timeout)
        results.append(result)
        
        # Show real-time errors
        if not result['success']:
            tqdm.write(f"✗ {file_path}: {result['error']}")
    
    # Analyze results
    analysis = analyze_results(results)
    
    # Save results
    save_results(results, args.output, analysis)
    
    # Print analysis
    print_analysis(analysis)
    
    # Performance warnings
    if analysis['successful_scans'] > 0:
        max_time = analysis['response_times']['max']
        exceeds_5s = analysis['response_times']['exceeds_5s']
        
        if max_time > 5.0:
            print(f"\n⚠️  Warning: {exceeds_5s} files took longer than 5 seconds")
        
        if analysis['response_times']['avg'] > 1.0:
            print(f"⚠️  Warning: Average response time is {analysis['response_times']['avg']:.2f}s")
        
        if analysis['success_rate'] < 0.95:
            print(f"⚠️  Warning: Success rate is only {analysis['success_rate']:.1%}")
    
    return 0


if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)
