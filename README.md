# crypto-timing-attack-detector
Analyzes cryptographic code for potential timing vulnerabilities by measuring execution time variations for different inputs. - Focused on Basic cryptographic operations

## Install
`git clone https://github.com/ShadowStrikeHQ/crypto-timing-attack-detector`

## Usage
`./crypto-timing-attack-detector [params]`

## Parameters
- `-h`: Show help message and exit
- `--num_runs`: Number of times to run the operation for timing analysis.
- `--string1`: First string for string comparison.
- `--string2`: Second string for string comparison.
- `--message`: Message for HMAC or AES operations.
- `--key`: Key for HMAC or AES operations.
- `--password`: Password for PBKDF2 operation.
- `--salt`: Salt for PBKDF2 operation.

## License
Copyright (c) ShadowStrikeHQ
