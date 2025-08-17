#!/usr/bin/env python3
import argparse
import requests
import sys
import os
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple, Optional, Union, Dict, Any
from tqdm import tqdm
from rich.console import Console
from rich.traceback import install as rich_traceback_install

# Global flags
VERBOSE = False
DEBUG = False

# Rich console setup (installed only when debug is enabled inside main)
console = Console()

def log(message: str):
    """Print debugging messages when verbose is enabled."""
    if VERBOSE:
        console.log(message)


def debug_log(message: str):
    """Print detailed debugging messages when debug is enabled."""
    if DEBUG:
        console.log(message)

"""
Note: range endpoint with explicit type has been removed from the CLI to simplify UX.
The generic search endpoint automatically detects types in the current API.
"""

def check_hash_generic(hash_value: str) -> Tuple[str, Optional[str]]:
    """
    Queries a hash in the Weakpass API using the generic search endpoint.
    Returns a tuple (hash, password or None).
    """
    try:
        url = f"https://weakpass.com/api/v1/search/{hash_value}.json"
        headers = {"Accept": "application/json", "User-Agent": "weakpass-lookup/0.1.0"}
        log(f"Querying {url} for hash {hash_value}")
        
        response = requests.get(url, headers=headers, timeout=(5, 20))
        log(f"HTTP response: {response.status_code} for hash {hash_value}")
        debug_log(f"Response headers: {dict(response.headers)}")
        if response.status_code == 200:
            # Some API responses may return a list or a single object, or even 0/'0' when not found
            try:
                results: Union[List[Any], Dict[str, Any], int, str] = response.json()
            except ValueError:
                # Not JSON, try to use text fallback
                text_payload = response.text.strip()
                debug_log(f"Non-JSON payload (truncated): {text_payload[:200]}")
                if text_payload in {"0", "", "[]"}:
                    return (hash_value, None)
                return (hash_value, None)

            debug_log(f"Response JSON (truncated): {str(results)[:500]}")

            # If API returns numeric 0 or string '0' => not found
            if results in (0, "0", None):
                return (hash_value, None)

            # If API returns a list of objects
            if isinstance(results, list):
                for item in results:
                    try:
                        item_hash = str(item.get("hash", "")).lower()
                        if item_hash == hash_value.lower():
                            return (hash_value, item.get("pass"))
                    except AttributeError:
                        continue
                # No exact match found; try first item if it looks valid
                if len(results) > 0 and isinstance(results[0], dict) and "pass" in results[0]:
                    return (hash_value, results[0].get("pass"))
                return (hash_value, None)

            # If API returns a single object
            if isinstance(results, dict):
                # Success object
                if "pass" in results:
                    return (hash_value, results.get("pass"))
                # Error object
                if any(k in results for k in ("error", "message")):
                    log(f"API message for {hash_value}: {results}")
                    return (hash_value, None)
                return (hash_value, None)

            # Any other shape
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

def validate_hash(hash_value: str) -> bool:
    """Validate the hash format for generic search (hex 32-64)."""
    if not all(c in '0123456789abcdefABCDEF' for c in hash_value):
        return False
    # For generic search, accept hashes between 32 and 64 characters
    return 32 <= len(hash_value) <= 64

def process_hash(hash_value: str) -> Tuple[str, Optional[str]]:
    """Process a single hash using the generic search endpoint."""
    log(f"Starting processing of hash {hash_value}")
    try:
        result = check_hash_generic(hash_value)
        log(f"Finished processing hash {hash_value}")
        return result
    except Exception as e:
        print(f"\nUnexpected error processing hash {hash_value}: {str(e)}")
        return (hash_value, None)

def process_single_hash(hash_value: str):
    """Process a single hash and display the result on screen."""
    if not validate_hash(hash_value):
        print("Error: Invalid hash format (expected hex between 32 and 64 characters)")
        sys.exit(1)
    
    print(f"Processing hash: {hash_value}")
    result = process_hash(hash_value)
    
    if result[1] is not None:
        print(f"\nCracked hash: {result[0]}:{result[1]}")
    else:
        print(f"\nHash not found: {result[0]}")

def process_hashes(input_file: str, workers: int = 1):
    """Process a file of hashes using multiple threads."""
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
    invalid_hashes = [h for h in hashes if not validate_hash(h)]
    if invalid_hashes:
        print("Error: Invalid hash format found (expected hex between 32 and 64 characters):")
        for h in invalid_hashes:
            print(f"- {h}")
        sys.exit(1)
    
    total = len(hashes)
    cracked = []
    uncracked = []
    
    print(f"Processing {total} hashes using {workers} threads...")
    
    # Parallel processing using ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=workers) as executor:
        # Create tasks for each hash
        futures = [executor.submit(process_hash, hash_value) for hash_value in hashes]
        
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
    global VERBOSE, DEBUG
    parser = argparse.ArgumentParser(description='Searches hashes in the Weakpass API')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', help='File with list of hashes (one per line)')
    group.add_argument('-H', '--hash', help='Individual hash to search')
    parser.add_argument('-w', '--workers', type=int, default=10,
                        help='Number of threads to use (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose mode to show more debugging details')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Debug mode with rich tracebacks and HTTP details (use only in local/dev)')
    
    args = parser.parse_args()
    VERBOSE = args.verbose or args.debug  # Enable verbose mode if debug or verbose is indicated
    DEBUG = args.debug

    if DEBUG:
        # Enable rich tracebacks only in debug mode
        rich_traceback_install(show_locals=False, width=120)
    
    if args.file:
        process_hashes(args.file, args.workers)
    else:
        process_single_hash(args.hash)

if __name__ == "__main__":
    main()
    