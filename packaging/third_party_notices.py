"""
Licencje bibliotek wbudowanych w program (THIRD-PARTY-NOTICES.txt) – generowane przy każdym budowaniu.

Licencje MIT, BSD i Apache wymagają dołączenia informacji o prawach autorskich i treści licencji do
rozpowszechnianego programu. Lista nie jest prowadzona ręcznie: skrypt czyta spis plików, które PyInstaller
naprawdę umieścił w programie (COLLECT-00.toc, PYZ-00.toc), i przypisuje każdy plik do zainstalowanego pakietu
(RECORD w *.dist-info). Biblioteki dołączone do samego Pythona (OpenSSL, Tcl/Tk, zlib, libffi…) opisuje jego
plik LICENSE.txt, dołączany w całości.

    python packaging/third_party_notices.py <katalog work PyInstallera> <plik wynikowy>
"""

import ast
import importlib.metadata as md
import os
import re
import sys
from typing import Dict, Iterable, List, Set

LICENSE_FILE = re.compile(r"(^|[/\\])(LICEN[CS]E|COPYING|NOTICE|AUTHORS)[^/\\]*$", re.IGNORECASE)
OWN_PACKAGES = {"core", "ui", "sync", "backups", "importers", "main"}


def _norm(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def bundled_sources(work_dir: str) -> Set[str]:
    """Ścieżki źródłowe wszystkich plików i modułów umieszczonych w programie."""
    sources = set()
    for toc in ("COLLECT-00.toc", "PYZ-00.toc"):
        path = os.path.join(work_dir, toc)
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as f:
            data = ast.literal_eval(f.read())
        # Spisy mają różną budowę (krotka z listą wpisów w środku) – szukamy wpisów (cel, źródło, rodzaj) wszędzie
        stack = [data]
        while stack:
            item = stack.pop()
            if isinstance(item, tuple) and len(item) == 3 and all(isinstance(x, str) for x in item):
                if item[1]:
                    sources.add(_norm(item[1]))
            elif isinstance(item, (list, tuple)):
                stack.extend(item)
    return sources


def distribution_index() -> Dict[str, md.Distribution]:
    index = {}
    for dist in md.distributions():
        for f in dist.files or []:
            try:
                index[_norm(str(dist.locate_file(f)))] = dist
            except Exception:
                continue
    return index


def bundled_distributions(sources: Iterable[str]) -> List[md.Distribution]:
    index = distribution_index()
    found = {}
    for src in sources:
        dist = index.get(src)
        if dist is not None:
            found[dist.metadata["Name"].lower()] = dist
    return [found[k] for k in sorted(found)]


def _license_name(dist: md.Distribution) -> str:
    meta = dist.metadata
    expr = meta.get("License-Expression")
    if expr:
        return expr
    lic = (meta.get("License") or "").strip()
    if lic and len(lic) < 120 and "\n" not in lic:
        return lic
    classifiers = [c.split("::")[-1].strip() for c in meta.get_all("Classifier") or [] if c.startswith("License ::")]
    return ", ".join(classifiers) or (lic.splitlines()[0][:120] if lic else "—")


def _license_texts(dist: md.Distribution) -> List[str]:
    texts = []
    for f in dist.files or []:
        if LICENSE_FILE.search(str(f)):
            try:
                text = f.read_text(encoding="utf-8", errors="replace").strip()
            except Exception:
                continue
            if text and text not in texts:
                texts.append(text)
    if not texts:
        lic = (dist.metadata.get("License") or "").strip()
        if len(lic) > 120:  # pełna treść licencji zapisana w metadanych
            texts.append(lic)
    return texts


def python_license() -> str:
    lib = os.path.join(sys.base_prefix, "lib", f"python{sys.version_info[0]}.{sys.version_info[1]}")
    for path in (os.path.join(sys.base_prefix, "LICENSE.txt"), os.path.join(sys.base_prefix, "LICENSE"),
                 os.path.join(lib, "LICENSE.txt")):  # macOS i Linux: plik licencji w katalogu biblioteki
        if os.path.isfile(path):
            with open(path, encoding="utf-8", errors="replace") as f:
                return f.read().strip()
    return "Python Software Foundation License – https://docs.python.org/3/license.html"


def build_notices(work_dir: str) -> str:
    rule = "=" * 100
    dists = [d for d in bundled_distributions(bundled_sources(work_dir))
             if d.metadata["Name"].lower() not in OWN_PACKAGES]
    out = [
        "KeyStead Manager – licencje użytych bibliotek / third-party software notices",
        "",
        "KeyStead Manager zawiera poniższe oprogramowanie osób trzecich. Każdy składnik jest objęty własną licencją,",
        "której treść podano niżej. Licencja KeyStead (plik LICENSE) nie zmienia warunków tych licencji.",
        "",
        "KeyStead Manager includes the third-party software listed below. Each component is covered by its own",
        "license, reproduced below. The KeyStead license (LICENSE file) does not change the terms of these licenses.",
        "",
        "Python " + sys.version.split()[0] + " – Python Software Foundation License (with OpenSSL, Tcl/Tk, zlib, libffi,",
        "bzip2, xz and other libraries listed in the Python license below)",
    ]
    if sys.platform == "win32":
        out += ["Microsoft Visual C++ Runtime (msvcp140.dll, vcruntime140.dll) – redistributed under the Microsoft "
                "Visual C++", "Redistributable license terms"]
    out += [f"{d.metadata['Name']} {d.version} – {_license_name(d)}" for d in dists]
    out += ["", rule, f"Python {sys.version.split()[0]}", rule, python_license()]
    for d in dists:
        home = d.metadata.get("Home-page") or next((u.split(",", 1)[1].strip() for u in d.metadata.get_all("Project-URL") or []
                                                    if "," in u), "")
        out += ["", rule, f"{d.metadata['Name']} {d.version} – {_license_name(d)}" + (f"\n{home}" if home else ""), rule]
        texts = _license_texts(d)
        out += texts if texts else [f"License: {_license_name(d)} (full text: see the project page)."]
    return "\n".join(out) + "\n"


def main(argv: List[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 2
    text = build_notices(argv[1])
    with open(argv[2], "w", encoding="utf-8-sig") as f:  # BOM – Notatnik i Windows otwierają poprawnie
        f.write(text)
    count = text.count("\n" + "=" * 100 + "\n") // 2
    print(f"THIRD-PARTY-NOTICES: {count} sekcji, {len(text) // 1024} KB")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
