#!/usr/bin/env python3
import argparse
import requests
import sys
import os
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple, Optional
from tqdm import tqdm

# Global variable for verbose mode
VERBOSE = False

def log(message: str):
    """Prints debugging messages if verbose mode is enabled."""
    if VERBOSE:
        print(message)

def check_hash_with_type(hash_value: str, hash_type: str) -> Tuple[str, Optional[str]]:
    """
    Queries a hash in the Weakpass API using the range endpoint with a specific type.
    Returns a tuple (hash, password or None).
    """
    try:
        prefix = hash_value[:5]
        url = f"https://weakpass.com/api/v1/range/{prefix}"
        params = {'type': hash_type}
        log(f"Querying {url} with params {params} for hash {hash_value}")
        
        response = requests.get(url, params=params)
        log(f"HTTP response: {response.status_code} for hash {hash_value}")
        if response.status_code == 200:
            results = response.json()
            # Searching for the full hash in the results
            for result in results:
                if result['hash'].lower() == hash_value.lower():
                    log(f"Hash found: {hash_value} -> {result['pass']}")
                    return (hash_value, result['pass'])
            # If the hash is not found in the results, mark it as not cracked
            return (hash_value, None)
        elif response.status_code == 404:
            # If there are no results for that prefix, the hash is not cracked
            return (hash_value, None)
        else:
            print(f"\nError querying hash {hash_value}: {response.status_code}")
            return (hash_value, None)
    except Exception as e:
        print(f"\nError in the request for hash {hash_value}: {str(e)}")
        return (hash_value, None)

def check_hash_generic(hash_value: str) -> Tuple[str, Optional[str]]:
    """
    Queries a hash in the Weakpass API using the generic search endpoint.
    Returns a tuple (hash, password or None).
    """
    try:
        url = f"https://weakpass.com/api/v1/search/{hash_value}"
        log(f"Querying {url} for hash {hash_value}")
        
        response = requests.get(url)
        log(f"HTTP response: {response.status_code} for hash {hash_value}")
        if response.status_code == 200:
            results = response.json()
            if results and len(results) > 0:
                log(f"Hash found: {hash_value} -> {results[0]['pass']}")
                return (hash_value, results[0]['pass'])
            # If the response is empty, the hash is not cracked
            return (hash_value, None)
        elif response.status_code == 404:
            # If the hash is not found, mark it as not cracked
            return (hash_value, None)
        else:
            print(f"\nError querying hash {hash_value}: {response.status_code}")
            return (hash_value, None)
    except Exception as e:
        print(f"\nError in the request for hash {hash_value}: {str(e)}")
        return (hash_value, None)

def validate_hash(hash_value: str, hash_type: str = None) -> bool:
    """
    Validates the hash format based on its type.
    """
    if not all(c in '0123456789abcdefABCDEF' for c in hash_value):
        return False
        
    if hash_type:
        expected_lengths = {
            'md5': 32,
            'ntlm': 32,
            'sha1': 40,
            'sha256': 64
        }
        return len(hash_value) == expected_lengths.get(hash_type)
    else:
        # For generic search, we accept hashes between 32 and 64 characters
        return 32 <= len(hash_value) <= 64

def process_hash(hash_value: str, hash_type: str = None) -> Tuple[str, Optional[str]]:
    """
    Processes a single hash using the appropriate method based on its type.
    Always returns a tuple (hash, password or None).
    """
    log(f"Starting processing of hash {hash_value} with type {hash_type or 'generic'}")
    try:
        if hash_type:
            result = check_hash_with_type(hash_value, hash_type)
        else:
            result = check_hash_generic(hash_value)
        log(f"Finished processing hash {hash_value}")
        return result
    except Exception as e:
        print(f"\nUnexpected error processing hash {hash_value}: {str(e)}")
        return (hash_value, None)

def process_single_hash(hash_value: str, hash_type: str = None):
    """
    Processes a single hash and displays the result on screen.
    """
    if not validate_hash(hash_value, hash_type):
        print(f"Error: Invalid hash format for type {hash_type or 'generic'}")
        sys.exit(1)
    
    print(f"Processing hash{f' type {hash_type}' if hash_type else ''}: {hash_value}")
    result = process_hash(hash_value, hash_type)
    
    if result[1] is not None:
        print(f"\nCracked hash: {result[0]}:{result[1]}")
    else:
        print(f"\nHash not found: {result[0]}")

def process_hashes(input_file: str, hash_type: str = None, workers: int = 1):
    """
    Processes a file of hashes using multiple threads.
    """
    base_name = os.path.splitext(input_file)[0]
    cracked_file = f"{base_name}_cracked.txt"
    uncracked_file = f"{base_name}_uncracked.txt"
    
    try:
        with open(input_file, 'r') as f:
            hashes = [line.strip() for line in f if line.strip()]
        log(f"Read {len(hashes)} hashes from file {input_file}")
    except FileNotFoundError:
        print(f"Error: File {input_file} not found")
        sys.exit(1)
    
    # Validate hash formats
    invalid_hashes = [h for h in hashes if not validate_hash(h, hash_type)]
    if invalid_hashes:
        print(f"Error: Invalid hash format found for type {hash_type or 'generic'}:")
        for h in invalid_hashes:
            print(f"- {h}")
        sys.exit(1)
    
    total = len(hashes)
    cracked = []
    uncracked = []
    
    print(f"Processing {total} hashes{f' type {hash_type}' if hash_type else ''} using {workers} threads...")
    
    # Parallel processing using ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=workers) as executor:
        # Create tasks for each hash
        futures = [executor.submit(process_hash, hash_value, hash_type) for hash_value in hashes]
        
        # Process the results using tqdm to display progress
        for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Processing"):
            try:
                result = future.result()
                if result is None:
                    continue
                hash_value, password = result
                if password is not None:
                    cracked.append(f"{hash_value}:{password}")
                else:
                    uncracked.append(hash_value)
            except Exception as e:
                print(f"\nError processing result: {str(e)}")
                continue
    
    # Save the results
    with open(cracked_file, 'w') as f:
        f.write('\n'.join(cracked) + '\n' if cracked else '')
    
    with open(uncracked_file, 'w') as f:
        f.write('\n'.join(uncracked) + '\n' if uncracked else '')
    
    print("\nResults:")
    print(f"Total hashes processed: {total}")
    print(f"Cracked hashes: {len(cracked)}")
    print(f"Uncracked hashes: {len(uncracked)}")
    print(f"\nResults saved in:")
    print(f"- Cracked: {cracked_file}")
    print(f"- Uncracked: {uncracked_file}")

def main():
    global VERBOSE
    parser = argparse.ArgumentParser(description='Searches hashes in the Weakpass API')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', help='File with list of hashes (one per line)')
    group.add_argument('-H', '--hash', help='Individual hash to search')
    parser.add_argument('-t', '--type', choices=['md5', 'ntlm', 'sha1', 'sha256'], 
                        help='Hash type (optional, if not specified generic search is used)')
    parser.add_argument('-w', '--workers', type=int, default=10,
                        help='Number of threads to use (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose mode to show more debugging details')
    
    args = parser.parse_args()
    VERBOSE = args.verbose  # Enable verbose mode if indicated
    
    if args.file:
        process_hashes(args.file, args.type, args.workers)
    else:
        process_single_hash(args.hash, args.type)

if __name__ == "__main__":
    main()