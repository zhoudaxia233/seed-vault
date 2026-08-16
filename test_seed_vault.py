from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import seed_vault


class SeedVaultTests(unittest.TestCase):
    def setUp(self) -> None:
        for name, value in (
            ("ARGON2_MEMORY_KIB", 8 * 1024),
            ("ARGON2_ITERATIONS", 1),
            ("ARGON2_LANES", 1),
        ):
            patcher = mock.patch.object(seed_vault, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

        self.mnemonic = " ".join(f"word{number:02d}" for number in range(24))
        self.passphrase = "test passphrase"
        self.password = bytearray(b"correct horse battery staple")

    def test_round_trip(self) -> None:
        token = seed_vault.encrypt_data(self.mnemonic, self.passphrase, self.password)
        self.assertEqual(
            seed_vault.decrypt_data(token, self.password),
            (self.mnemonic, self.passphrase),
        )

    def test_wrong_password_fails(self) -> None:
        token = seed_vault.encrypt_data(self.mnemonic, self.passphrase, self.password)
        with self.assertRaises(seed_vault.VaultError):
            seed_vault.decrypt_data(token, bytearray(b"another sufficiently long password"))

    def test_modified_ciphertext_fails(self) -> None:
        token = bytearray(seed_vault.encrypt_data(self.mnemonic, self.passphrase, self.password))
        token[-3] = ord("A") if token[-3] != ord("A") else ord("B")
        with self.assertRaises(seed_vault.VaultError):
            seed_vault.decrypt_data(bytes(token), self.password)

    def test_existing_file_is_not_overwritten_or_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret.enc"
            path.write_bytes(b"existing")
            with self.assertRaises(seed_vault.VaultError):
                seed_vault.write_new_file(path, b"replacement")
            self.assertEqual(path.read_bytes(), b"existing")

    def test_decrypt_refuses_redirected_output(self) -> None:
        stdout = mock.Mock()
        stdout.isatty.return_value = False
        with mock.patch.object(seed_vault.sys, "stdout", stdout):
            with self.assertRaises(seed_vault.VaultError):
                seed_vault.command_decrypt(Path("not-read.enc"))


if __name__ == "__main__":
    unittest.main()
