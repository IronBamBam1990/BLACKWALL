"""
Log Encryption - Szyfrowanie logow Fernet (AES-128-CBC).
Szyfruje pliki logow na rotacji, narzedzie do dekrypcji.
"""

import base64
import json
import os
from pathlib import Path

try:
    from cryptography.fernet import Fernet
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


class LogEncryptor:
    def __init__(self, config: dict = None):
        config = config or {}
        self.enabled = config.get("enabled", False) and HAS_CRYPTO
        self.key_file = Path(config.get("key_file", "config/log_encryption.key"))
        self._fernet = None

        if self.enabled:
            self._init_key()

    def _init_key(self):
        """Laduje lub generuje klucz szyfrujacy."""
        if self.key_file.exists():
            key = self.key_file.read_bytes().strip()
        else:
            key = Fernet.generate_key()
            self.key_file.parent.mkdir(parents=True, exist_ok=True)
            self.key_file.write_bytes(key)
            # Ustaw restrykcyjne uprawnienia
            try:
                os.chmod(str(self.key_file), 0o600)
            except OSError:
                pass
        self._fernet = Fernet(key)

    def encrypt(self, data: str) -> str:
        """Szyfruje string, zwraca base64."""
        if not self.enabled or not self._fernet:
            return data
        encrypted = self._fernet.encrypt(data.encode("utf-8"))
        return base64.urlsafe_b64encode(encrypted).decode("ascii")

    def decrypt(self, encrypted_data: str) -> str:
        """Odszyfrowuje base64 string."""
        if not self.enabled or not self._fernet:
            return encrypted_data
        try:
            raw = base64.urlsafe_b64decode(encrypted_data.encode("ascii"))
            return self._fernet.decrypt(raw).decode("utf-8")
        except Exception:
            return encrypted_data  # Nie zaszyfrowane lub bledne

    def encrypt_file(self, filepath: str):
        """Szyfruje caly plik in-place."""
        if not self.enabled or not self._fernet:
            return
        path = Path(filepath)
        if not path.exists():
            return
        data = path.read_bytes()
        encrypted = self._fernet.encrypt(data)
        enc_path = path.with_suffix(path.suffix + ".enc")
        enc_path.write_bytes(encrypted)
        path.unlink()  # Usun niezaszyfrowany

    def decrypt_file(self, filepath: str) -> bytes:
        """Odszyfrowuje plik."""
        if not self._fernet:
            return b""
        path = Path(filepath)
        if not path.exists():
            return b""
        encrypted = path.read_bytes()
        return self._fernet.decrypt(encrypted)

    def encrypt_jsonl_line(self, json_line: str) -> str:
        """Szyfruje jedna linie JSONL."""
        if not self.enabled or not self._fernet:
            return json_line
        encrypted = self._fernet.encrypt(json_line.encode("utf-8"))
        return encrypted.decode("ascii")

    def decrypt_jsonl_line(self, encrypted_line: str) -> str:
        """Odszyfrowuje linie JSONL."""
        if not self._fernet:
            return encrypted_line
        try:
            return self._fernet.decrypt(encrypted_line.encode("ascii")).decode("utf-8")
        except Exception:
            return encrypted_line

    def rotate_key(self):
        """Generuje nowy klucz (stary jest tracony - najpierw odszyfruj logi!)."""
        if not HAS_CRYPTO:
            return
        new_key = Fernet.generate_key()
        self.key_file.write_bytes(new_key)
        self._fernet = Fernet(new_key)


def decrypt_log_file(key_file: str, log_file: str) -> str:
    """Utility function: odszyfruj plik logu."""
    key = Path(key_file).read_bytes().strip()
    f = Fernet(key)
    data = Path(log_file).read_bytes()
    return f.decrypt(data).decode("utf-8")
