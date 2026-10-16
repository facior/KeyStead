"""
Pakiet obsługi kopii zapasowych w chmurze i na nośnikach lokalnych.
"""

from backups.base import BaseBackupProvider, BackupStatus
from backups.local_backup import LocalBackupProvider
from backups.webdav_backup import WebDAVBackupProvider
from backups.google_drive import GoogleDriveBackupProvider
from backups.onedrive_backup import OneDriveBackupProvider
from backups.dropbox_backup import DropboxBackupProvider
from backups.manager import BackupManager, vault_snapshot, merge_runtime_state
