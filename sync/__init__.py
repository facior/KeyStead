"""
Synchronizacja sejfu z własnym serwerem (KeyStead Server) przez Tailscale.
Na serwer trafia wyłącznie zaszyfrowany plik – odszyfrowanie odbywa się tylko lokalnie.
"""

from sync.client import RemoteVaultClient, SyncError, ConflictError, AuthError, NetworkError, TotpRequiredError
from sync.profile import ServerProfile, load_profile, save_profile, delete_profile
from sync.session import SyncSession, SyncStatus, EmptyServerError, OfflineExpiredError
