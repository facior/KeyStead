"""
Główny pakiet logiki biznesowej i kryptografii menedżera haseł.
"""

from core.crypto import (
    CryptoError,
    InvalidVaultHeaderError,
    InvalidPasswordOrCorruptDataError,
    encrypt_payload,
    decrypt_payload,
    compute_sha256
)
from core.vault import Vault, VaultEntry, DEFAULT_CATEGORIES
from core.storage import save_vault, load_vault, VAULT_FILE_EXTENSION
from core.generator import generate_password, generate_passphrase, evaluate_password_strength
from core.totp_service import get_current_totp, get_totp_remaining_seconds, parse_otpauth_uri
