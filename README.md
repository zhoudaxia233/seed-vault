# Seed Vault

Seed Vault is a small command-line tool for encrypting a BIP-39 mnemonic and its optional passphrase on an air-gapped computer. The resulting `.enc` file can be backed up in a private GitHub repository.

The design assumes that the source code and encrypted file may eventually become public. Security must depend on the master password, not repository privacy.

## Important warning

- Use a unique, randomly generated master passphrase. Seven or more independently random Diceware words are a sensible target for a high-value wallet. Plain ASCII words are easiest to reproduce reliably across operating systems and keyboard layouts.
- Losing the master password means losing access to this backup permanently.
- Keep a separate, tested recovery method. Do not make one encrypted file your only wallet backup.
- This file contains both the mnemonic and BIP-39 passphrase. Anyone who decrypts it has everything needed to control the wallet; it does not preserve separation between those two factors.
- This tool checks only the standard BIP-39 word count. It does not validate the word list or checksum.
- Review the source and perform a complete recovery test before trusting it with funds.

## Why the code is intentionally small

Simplicity reduces implementation and review risk, but simple code is not automatically secure. Seed Vault keeps the custom logic small and delegates cryptographic operations to the widely used `cryptography` library.

There is one application file, one dependency, one encrypted format version, and no external OpenSSL process.

## Cryptographic design

File format version 1 fixes the following parameters:

- Argon2id with a fresh 16-byte random salt
- 256 MiB memory, 3 passes, and 4 lanes
- AES-256-GCM with a fresh 12-byte random nonce
- A 128-bit authentication tag
- UTF-8 plaintext encoding

AES-GCM provides confidentiality and integrity. A wrong password or any modification to the version marker, salt, nonce, or ciphertext causes decryption to fail. Argon2id is memory-hard and raises the cost of offline password guessing on GPUs and specialized hardware.

The program never places the password in command-line arguments and does not invoke a subprocess. Secret input is hidden. Plaintext is not intentionally written to a file; decryption prints it only to standard output.

## Limitations

No Python program can guarantee complete memory erasure. Python objects, library internals, swap, hibernation, crash dumps, terminal scrollback, clipboard managers, screen capture, keyloggers, or compromised firmware may expose secrets.

Use a clean air-gapped computer. Disable networking, swap, and hibernation where practical. Avoid synchronized clipboards. Do not photograph the screen. Shut the computer down after use rather than suspending it.

A private GitHub repository is defense in depth only. Assume an attacker may obtain the encrypted file and attempt unlimited offline password guesses.

## Repository files

```text
seed-vault/
├── .gitignore
├── README.md
├── requirements.txt
├── seed_vault.py
└── test_seed_vault.py
```

After encryption, `secret.enc` may be added to the private repository. Never add plaintext mnemonics, passphrases, screenshots, logs, shell transcripts, or decrypted output.

## Prepare for an air-gapped computer

Use Python 3.9 or newer. On an online staging computer with the same Python version, operating system, and CPU architecture as the air-gapped computer:

```bash
python -m pip download --only-binary=:all: --dest wheels -r requirements.txt
```

Verify each downloaded wheel's SHA-256 against its PyPI file-details page, then transfer the repository and `wheels` directory using clean removable media.

### Linux and macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --no-index --find-links wheels -r requirements.txt
python -m unittest -v
```

### Windows Git Bash

```bash
py -3 -m venv .venv
source .venv/Scripts/activate
python -m pip install --no-index --find-links wheels -r requirements.txt
python -m unittest -v
```

Keep the exact source commit and matching wheel files with the encrypted backup. Version 1 parameters are part of the file format and must never be silently changed.

## Encrypt

Run only on the air-gapped computer:

```bash
python seed_vault.py encrypt secret.enc
```

The program asks twice for the mnemonic, BIP-39 passphrase, and master password. All entries are hidden. The mnemonic is normalized to one space between words.

The output file is created without overwriting an existing file. After writing, Seed Vault reads the exact stored bytes and performs a full authenticated recovery test.

## Decrypt

```bash
python seed_vault.py decrypt secret.enc
```

The recovered values are printed as JSON to a terminal. The program refuses to decrypt when standard output is redirected, reducing the chance of accidentally creating a plaintext file.

Immediately after creating the first backup:

1. Decrypt it on the air-gapped computer.
2. Compare every mnemonic word and the passphrase with the original.
3. Confirm that the recovered material derives the expected wallet address.
4. Keep at least two independent copies of the encrypted file.
5. Test recovery periodically without exposing the live wallet to an online computer.

## Encrypted file format

A version 1 file is one ASCII line:

```text
seed-vault-v1:<URL-safe Base64>
```

The decoded bytes are:

```text
16-byte salt || 12-byte nonce || AES-256-GCM ciphertext and tag
```

The version marker, salt, and nonce are authenticated as associated data. They are not secret. The master password, derived key, mnemonic, and BIP-39 passphrase are never stored in the file.

## GitHub settings

Keep the repository private, enable two-factor authentication, and do not add collaborators unless necessary. Repository privacy does not compensate for a weak or reused master password.
