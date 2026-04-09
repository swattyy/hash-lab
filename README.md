# hash-lab

An educational hash analysis and dictionary attack tool built for CTF challenges and security labs. Identify hash types, generate hashes, and run dictionary attacks with common password mutations.

## Features

- **Hash identification** -- automatically detect MD5, SHA1, SHA256, SHA512, NTLM, and bcrypt by length and format
- **Dictionary attacks** -- crack hashes using a wordlist with intelligent mutations
- **Password mutations** -- appended numbers (0-99), capitalization, leet speak (`a->@, e->3, s->$, o->0`), common suffixes
- **Hash generation** -- hash any plaintext with your choice of algorithm
- **Progress reporting** -- live attempt counter and timing stats

## Supported Hash Types

| Algorithm | Example Length | Detected |
|-----------|--------------|----------|
| MD5       | 32 chars     | Yes      |
| SHA1      | 40 chars     | Yes      |
| SHA256    | 64 chars     | Yes      |
| SHA512    | 128 chars    | Yes      |
| NTLM      | 32 chars     | Yes      |
| bcrypt    | 60 chars     | Yes      |

## Installation

```bash
git clone https://github.com/swatyy/hash-lab.git
cd hash-lab
pip install -r requirements.txt
```

## Usage

### Identify a hash

```bash
python main.py 5f4dcc3b5aa765d61d8327deb882cf99
```

Output:
```
hash-lab v1.0

        Hash Analysis
  Property     | Value
  Input        | 5f4dcc3b5aa765d61d8327deb882cf99
  Length       | 32
  Possible types | MD5, NTLM
```

### Crack a hash with a wordlist

```bash
python main.py 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist wordlists/common.txt -a md5
```

Output:
```
CRACKED!

  Plaintext  | password
  Hash       | 5f4dcc3b5aa765d61d8327deb882cf99
  Algorithm  | MD5
  Attempts   | 1
  Time       | 0.00s
```

### Hash a plaintext string

```bash
python main.py "hello world" --hash -a sha256
```

### Specify an algorithm for cracking

```bash
python main.py <hash> --wordlist wordlists/common.txt --algorithm sha256
```

## Project Structure

```
hash-lab/
  main.py              # CLI tool
  wordlists/
    common.txt         # Sample wordlist (~50 passwords)
  requirements.txt     # Python dependencies
  README.md
```

## Disclaimer

**For CTF challenges and authorized security testing only.** This tool is built for educational purposes as a learning aid for understanding how hash functions and dictionary attacks work. Do not use it against systems or data you do not own or have explicit authorization to test.
