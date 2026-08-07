# cipher-id: Advanced Cryptographic & Encoding Identification Framework

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-88%2F88%20Passing-success.svg)](#)

`cipher-id` is an industry-grade, terminal-based identification engine designed for Security Operations Centers (SOC), malware analysts, and penetration testers. Its primary mission is the deterministic identification and analysis of unknown cryptographic strings, encoded data, file signatures, and hashes.

Rather than merely attempting to decode data, `cipher-id` acts as an automated triage engine. It leverages a multi-layered A* Search algorithm, Shannon entropy analysis, multi-lingual heuristics, and cryptographic format verification to rapidly classify data.

## Features & Capabilities

### 1. Advanced Cryptographic Verification
* **Cryptocurrency Wallet Validation:** Mathematically verifies Bitcoin P2PKH/P2SH (Base58Check), Bech32 (SegWit), Ethereum, and Monero (XMR) addresses. Does not rely on naive Regex; validates checksums.
* **PGP & OpenSSL Signatures:** Detects PGP Public/Private key blocks and messages, as well as OpenSSL salted streams (`Salted__`).
* **Hash / KDF Determinism:** Structurally identifies modern KDF formats (Bcrypt, Argon2, scrypt, PBKDF2) and ranks ambiguous fixed-length hashes (MD5, SHA-256, NTLM) by real-world statistical prevalence.

### 2. Intelligent A* Search Engine (v10)
Traditional decoders rely on linear or depth-first searches, leading to combinatorial explosion on complex chains. 
* `cipher-id` utilizes an **A* Search (Priority Queue) Algorithm**, dynamically scoring nodes using a heuristic cost function based on `Shannon Entropy` and `N-Gram` distributions.
* Detects complex obfuscation layers efficiently (e.g., `Base64 -> Zlib -> Hex -> ROT13`).

### 3. Comprehensive Decoding Arsenal
* **Base Encodings:** Base64 (Standard, URL-Safe, Bcrypt, Crypt, IMAP), Base32 (RFC4648, Crockford), Base36, Base45, Base58, Base62, Base85/Ascii85, Base91, Base100 (Emoji).
* **Binary/Data Formats:** Hex (xxd/hexdump parsing), Binary, Octal, Decimal, UUencode, XXencode, yEnc, z85 (ZeroMQ).
* **Teleprinter/Legacy:** Baudot/ITA2 (5-bit), Tap Code, T9 / Multitap.
* **Classical Ciphers (Brute-forced):** Caesar, ROT13/47/5/18, Atbash, Morse Code, Bacon, Polybius, A1Z26, NATO Phonetic, Rail Fence, Affine, Substitution (Simulated Annealing + Hill Climbing), Columnar Transposition.

### 4. Multi-Lingual Cryptanalysis & False-Positive Mitigation
* Scoring is powered by comprehensive N-Gram analysis and multi-lingual dictionary verification (English, Turkish, German, Spanish, French).
* Enforces strict false-positive penalties using Markov-chain heuristics to prevent short strings (<15 chars) from being misidentified as obfuscated data.

### 5. Data Visualization & Entropy Profiling
* Calculates precise Shannon entropy for inputs, mapping byte distributions to distinguish between *Plaintext*, *Structured Data (JSON/XML)*, *Compressed Data*, and *High-Entropy Encrypted Blobs*.
* Detects 16-byte block repetitions characteristic of AES-ECB cipher suites.

### 6. Steganography & Obfuscation Heuristics
* Detects esoteric language obfuscation (Whitespace Language).
* Identifies trailing whitespace/tab patterns indicative of SNOW Steganography.
* Integrates with 50+ file magic bytes to detect embedded payloads (e.g., a PNG hidden inside a Base64 blob).

## Installation

```bash
git clone <github.com/alirizagocer/cipher>
cd ciphertool
pip install -e .
```

## Usage

```bash
# Basic usage
identify "SGVsbG8gV29ybGQh"

# Read from file
identify -f payload.txt

# Pipe from stdin
echo "Uryyb Jbeyq" | identify

# Adjust search depth and limit output candidates
identify -d 4 -n 5 "..."

# Domain-specific Context (ctf, windows, linux, web, pentest)
identify --context pentest "<hash>"

# Automated Crib-dragging for XOR/Vigenere keys
identify --crib 'flag{' "<ciphertext>"

# Output in JSON format for automated pipelines
identify --json "..." | jq
```

## Architecture

* `engine.py`: Contains the A* Search algorithm and resource budgeting node-graph.
* `decoders.py`: Houses the stateless decoding primitives (e.g. `try_base64_bytes`).
* `scorer.py`: The fitness function and multi-lingual heuristics module.
* `hashid.py`: Pattern matching and entropy-based ranking for cryptographic hashes.
* `crack.py`: Expensive cryptographic solvers (XOR, Vigenere, Simulated Annealing).
* `charset.py`: Top-level structural determinism for wallets, API keys, and formats.

## License
MIT License. Developed for cybersecurity and threat intelligence research.