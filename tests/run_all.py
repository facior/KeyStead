"""
Uruchamia wszystkie testy aplikacji (tests/test_*.py) – lokalnie i w GitHub Actions na Windows, macOS i Linuksie.

    python tests/run_all.py              # wszystkie
    python tests/run_all.py --no-server  # bez testów wymagających kodu serwera (jak w repozytorium aplikacji)
    python tests/run_all.py -v           # nazwa każdego testu (w GitHub Actions widać, przy którym coś padło)
"""

import glob
import importlib.util
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def main() -> int:
    skip_server = "--no-server" in sys.argv or importlib.util.find_spec("server") is None
    names = []
    for path in sorted(glob.glob(os.path.join(ROOT, "tests", "test_*.py"))):
        name = os.path.splitext(os.path.basename(path))[0]
        if skip_server:
            with open(path, encoding="utf-8") as f:
                text = f.read()
            if "from server" in text or "import server" in text:
                continue
        names.append(f"tests.{name}")
    suite = unittest.defaultTestLoader.loadTestsFromNames(names)
    result = unittest.TextTestRunner(verbosity=2 if "-v" in sys.argv else 1).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
