# weakpass-lookup

A Python script that queries the [Weakpass API](https://weakpass.com/api) to attempt cracking various types of password hashes (NTLM, MD5, SHA1, SHA256). This tool is particularly helpful for cracking NTLM hashes obtained via DCSync in a Windows Domain environment, though it supports several other hash types as well.

## Features

- **Generic search**: No need to specify the hash type (supports NTLM, MD5, SHA1, SHA256).
- **Bulk processing**: Reads hashes from a file and checks them concurrently using multiple worker threads.
- **Single hash processing**: Checks a single hash without needing a file.
- **Verbose mode**: Provides additional debug output to help with troubleshooting.
- **Debug mode**: Rich-formatted tracebacks and HTTP details for local/dev troubleshooting.

## Installation

It is recommended to install **weakpass-lookup** using pipx (preferred) or [pip](https://pip.pypa.io/en/stable/).

### Using pipx (Recommended)

```sh
pipx install weakpass-lookup
```

> Make sure you have pipx installed and set up on your system.

### Using pip

```sh
pip install weakpass-lookup
```

## Usage

```sh
usage: weakpass-lookup [-h] (-f FILE | -H HASH) [-w WORKERS] [-v] [-d]

Searches hashes in the Weakpass API

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  File with list of hashes (one per line)
  -H HASH, --hash HASH  Individual hash to search
  -w WORKERS, --workers WORKERS
                        Number of threads to use (default: 10)
  -v, --verbose         Verbose mode to show more debugging details
  -d, --debug           Debug mode with tracebacks and HTTP details (use only in local/dev)
```

### Examples

1. **Crack a single hash:**
    
    ```sh
    weakpass-lookup --hash <HASH_VALUE>
	  ```
    
2. **Crack multiple hashes from a file (default 10 threads):**
    
    ```sh
    weakpass-lookup --file /path/to/hashes.txt --workers 10
	  ```
    
3. **Use verbose mode for debugging:**
    
    ```sh
    weakpass-lookup --file /path/to/hashes.txt --verbose
	  ```
    
4. **Detailed debug:**
    
    ```sh
    weakpass-lookup --hash <HASH_VALUE> --debug
	  ```

## Output

- When processing a file:
    
    - `<filename>_cracked.txt`: Stores all cracked hashes in `<hash>:<password>` format.
    - `<filename>_uncracked.txt`: Stores all remaining uncracked hashes.
- When processing a single hash:
    
    - Prints the result (cracked or uncracked) directly to the terminal.

## Contributing

1. Fork the project.
2. Create a new feature branch (`git checkout -b feature/my-feature`).
3. Commit your changes (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature/my-feature`).
5. Open a Pull Request.

## License

This project is licensed under the MIT License. Feel free to use, modify, and distribute it as per the terms of the license.

---

**Happy cracking with weakpass-lookup!**
