#!/usr/bin/env python3
"""Minimal offline encryption for BIP-39 backup material."""

from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import json
import os
import sys
import warnings
from pathlib import Path

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

# Version 1 parameters are part of the file format. Never change them in place.
PREFIX = b"seed-vault-v1:"
ARGON2_MEMORY_KIB = 256 * 1024  # 256 MiB
ARGON2_ITERATIONS = 3
ARGON2_LANES = 4
KEY_BYTES = 32
SALT_BYTES = 16
NONCE_BYTES = 12
GCM_TAG_BYTES = 16

MIN_MASTER_PASSWORD_CHARS = 16
MAX_SECRET_CHARS = 4096
MAX_FILE_BYTES = 64 * 1024
BIP39_WORD_COUNTS = {12, 15, 18, 21, 24}


class VaultError(Exception):
    """An expected error that should be shown without a traceback."""


def wipe(buffer: bytearray) -> None:
    buffer[:] = b"\x00" * len(buffer)


def hidden_input(prompt: str) -> str:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass(prompt)
    except getpass.GetPassWarning as exc:
        raise VaultError("A real terminal with hidden input support is required.") from exc
    except EOFError as exc:
        raise VaultError("Input ended unexpectedly.") from exc


def read_twice(prompt: str, repeat_prompt: str, *, allow_empty: bool) -> str:
    first = hidden_input(prompt)
    second = hidden_input(repeat_prompt)
    if first != second:
        raise VaultError("The two entries do not match.")
    if not allow_empty and not first:
        raise VaultError("Input cannot be empty.")
    if len(first) > MAX_SECRET_CHARS:
        raise VaultError("Input is too long.")
    return first


def read_master_password(*, confirm: bool) -> bytearray:
    password = hidden_input("Master password: ")
    if confirm and password != hidden_input("Repeat master password: "):
        raise VaultError("The master passwords do not match.")
    if len(password) < MIN_MASTER_PASSWORD_CHARS:
        raise VaultError(
            f"Master password must be at least {MIN_MASTER_PASSWORD_CHARS} characters. "
            "Use a long, randomly generated passphrase."
        )
    if len(password) > MAX_SECRET_CHARS:
        raise VaultError("Master password is too long.")
    return bytearray(password.encode("utf-8"))


def normalize_mnemonic(mnemonic: str) -> str:
    mnemonic = " ".join(mnemonic.split())
    count = len(mnemonic.split())
    if count not in BIP39_WORD_COUNTS:
        allowed = ", ".join(map(str, sorted(BIP39_WORD_COUNTS)))
        raise VaultError(f"Mnemonic must contain {allowed} words; received {count}.")
    return mnemonic


def derive_key(password: bytearray, salt: bytes) -> bytes:
    try:
        return Argon2id(
            salt=salt,
            length=KEY_BYTES,
            iterations=ARGON2_ITERATIONS,
            lanes=ARGON2_LANES,
            memory_cost=ARGON2_MEMORY_KIB,
        ).derive(bytes(password))
    except UnsupportedAlgorithm as exc:
        raise VaultError(
            "Argon2id is unavailable. Install the pinned cryptography wheel."
        ) from exc
    except MemoryError as exc:
        raise VaultError(
            f"Not enough memory for Argon2id ({ARGON2_MEMORY_KIB // 1024} MiB)."
        ) from exc


def encode_payload(mnemonic: str, passphrase: str) -> bytes:
    # A two-item list avoids a larger custom plaintext schema.
    return json.dumps(
        [mnemonic, passphrase],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def decode_payload(plaintext: bytes) -> tuple[str, str]:
    try:
        value = json.loads(plaintext)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise VaultError("Authenticated plaintext has an invalid format.") from exc
    if (
        not isinstance(value, list)
        or len(value) != 2
        or not all(isinstance(item, str) for item in value)
    ):
        raise VaultError("Authenticated plaintext has an invalid format.")
    return value[0], value[1]


def encrypt_data(mnemonic: str, passphrase: str, password: bytearray) -> bytes:
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    header = PREFIX + salt + nonce
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, encode_payload(mnemonic, passphrase), header)
    return PREFIX + base64.urlsafe_b64encode(salt + nonce + ciphertext) + b"\n"


def decrypt_data(token: bytes, password: bytearray) -> tuple[str, str]:
    token = token.strip()
    if not token.startswith(PREFIX):
        raise VaultError("Unsupported or invalid encrypted file format.")

    encoded = token[len(PREFIX) :]
    try:
        blob = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise VaultError("Encrypted file contains invalid Base64.") from exc

    minimum = SALT_BYTES + NONCE_BYTES + GCM_TAG_BYTES + 1
    if not minimum <= len(blob) <= MAX_FILE_BYTES:
        raise VaultError("Encrypted file has an invalid length.")

    salt = blob[:SALT_BYTES]
    nonce = blob[SALT_BYTES : SALT_BYTES + NONCE_BYTES]
    ciphertext = blob[SALT_BYTES + NONCE_BYTES :]
    header = PREFIX + salt + nonce
    key = derive_key(password, salt)

    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, header)
    except InvalidTag as exc:
        raise VaultError(
            "Decryption failed: wrong master password or modified encrypted data."
        ) from exc
    return decode_payload(plaintext)


def read_file(path: Path) -> bytes:
    try:
        with path.open("rb") as file:
            data = file.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise VaultError(f"Cannot read {path}: {exc}") from exc
    if len(data) > MAX_FILE_BYTES:
        raise VaultError("Encrypted file is too large.")
    return data


def write_new_file(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise VaultError(f"Refusing to overwrite existing file: {path}") from exc

    try:
        with os.fdopen(fd, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def command_encrypt(output: Path) -> None:
    if not output.parent.exists():
        raise VaultError(f"Output directory does not exist: {output.parent}")

    mnemonic = normalize_mnemonic(
        read_twice(
            "BIP-39 mnemonic (hidden): ",
            "Repeat BIP-39 mnemonic: ",
            allow_empty=False,
        )
    )
    passphrase = read_twice(
        "BIP-39 passphrase (hidden; empty is allowed): ",
        "Repeat BIP-39 passphrase: ",
        allow_empty=True,
    )
    password = read_master_password(confirm=True)

    created = False
    try:
        token = encrypt_data(mnemonic, passphrase, password)
        write_new_file(output, token)
        created = True

        # Verify the exact bytes that were stored, including authentication.
        if decrypt_data(read_file(output), password) != (mnemonic, passphrase):
            raise VaultError(f"Post-write recovery test failed.")
    except Exception:
        if created:
            output.unlink(missing_ok=True)
        raise
    finally:
        wipe(password)

    print(f"Encrypted backup written and verified: {output}", file=sys.stderr)
    print("Decrypt it once more and compare it with the original.", file=sys.stderr)


def command_decrypt(source: Path) -> None:
    if not sys.stdout.isatty():
        raise VaultError(
            "Refusing to print decrypted secrets to redirected standard output."
        )

    token = read_file(source)
    password = read_master_password(confirm=False)
    try:
        mnemonic, passphrase = decrypt_data(token, password)
    finally:
        wipe(password)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="strict")
    print(
        json.dumps(
            {"mnemonic": mnemonic, "passphrase": passphrase},
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="seed-vault",
        description="Encrypt or decrypt BIP-39 backup material offline.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    encrypt = commands.add_parser("encrypt", help="Create a new encrypted backup.")
    encrypt.add_argument("output", type=Path, help="New file, for example secret.enc")
    decrypt = commands.add_parser("decrypt", help="Decrypt a backup to standard output.")
    decrypt.add_argument("input", type=Path, help="Encrypted file")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "encrypt":
            command_encrypt(args.output)
        else:
            command_decrypt(args.input)
        return 0
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130
    except (VaultError, OSError, UnicodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
