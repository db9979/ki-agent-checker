"""API-Schlüssel im Schlüsselbund des Betriebssystems ablegen.

Windows: Credential Manager, macOS: Keychain, Linux: Secret Service.
Ohne verfügbaren Schlüsselbund (z. B. in CI) fällt die Engine auf einen
Speicher im Arbeitsspeicher zurück, Schlüssel gehen dann beim Beenden verloren.
"""

from __future__ import annotations

import logging

import keyring
from keyring.errors import KeyringError, NoKeyringError

SERVICE = "ki-agent-checker"
log = logging.getLogger(__name__)


class SecretStore:
    def __init__(self, use_keyring: bool = True) -> None:
        self._memory: dict[str, str] = {}
        self._use_keyring = use_keyring and self._keyring_available()
        if not self._use_keyring:
            log.warning("Kein Schlüsselbund verfügbar, API-Schlüssel nur im Arbeitsspeicher")

    @staticmethod
    def _keyring_available() -> bool:
        try:
            backend = keyring.get_keyring()
        except Exception:  # noqa: BLE001
            return False
        return "fail" not in type(backend).__module__ and "null" not in type(backend).__module__

    @property
    def persistent(self) -> bool:
        return self._use_keyring

    def set(self, key: str, value: str) -> None:
        if self._use_keyring:
            try:
                keyring.set_password(SERVICE, key, value)
                return
            except (KeyringError, NoKeyringError):
                log.exception("Schlüsselbund nicht beschreibbar, nutze Arbeitsspeicher")
                self._use_keyring = False
        self._memory[key] = value

    def get(self, key: str) -> str | None:
        if self._use_keyring:
            try:
                return keyring.get_password(SERVICE, key)
            except (KeyringError, NoKeyringError):
                return None
        return self._memory.get(key)

    def delete(self, key: str) -> None:
        self._memory.pop(key, None)
        if self._use_keyring:
            try:
                keyring.delete_password(SERVICE, key)
            except (KeyringError, NoKeyringError):
                pass
