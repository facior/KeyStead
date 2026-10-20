"""Diagnostyka Tk na macOS: który wcześniejszy moduł testów sprawia, że pierwszy test z oknem kończy się błędem."""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TARGET = "tests.test_family_phone_ui"
BEFORE = ["tests.test_app_update", "tests.test_audit", "tests.test_backup_hardening", "tests.test_backups",
          "tests.test_crypto", "tests.test_crypto_v2", "tests.test_family_phone"]

for mods in [[TARGET]] + [[m, TARGET] for m in BEFORE]:
    proc = subprocess.run([sys.executable, "-X", "faulthandler", "-m", "unittest", *mods], cwd=ROOT,
                          capture_output=True, text=True, timeout=600)
    print(f"=== {' + '.join(mods)}: exit {proc.returncode}")
    if proc.returncode:
        print("\n".join(line for line in proc.stderr.splitlines() if "File \"/Users" in line)[-2500:])
