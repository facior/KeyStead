"""
Główny punkt wejściowy aplikacji KeyStead Manager.
"""

import sys
import os

# Zapewnienie poprawnej ścieżki do modułów
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.paths import migrate_legacy_files  # noqa: E402

# Przeniesienie ustawień z poprzedniej nazwy aplikacji – przed wczytaniem interfejsu
migrate_legacy_files()

from ui.app import PasswordManagerApp  # noqa: E402


def main():
    app = PasswordManagerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
