"""
Kontrola tłumaczeń (używana przez tests/test_i18n.py i tests/test_server_i18n.py; można też uruchomić wprost):

    python tests/i18n_check.py app      # raport dla aplikacji
    python tests/i18n_check.py server   # raport dla serwera

1. Każdy polski tekst w kodzie jest opakowany w _() / _n() / N_() (albo oznaczony komentarzem `# i18n: data`
   w tej samej linii – np. nazwy pól zapisywane w sejfie, które muszą zostać takie same w każdym języku).
   Pomijane: docstringi, komunikaty dla logów (logger.*), pliki i18n.
2. Każdy oznaczony tekst ma tłumaczenie w katalogu locales/<język>/*.json, z tymi samymi {zmiennymi}.
"""

import ast
import glob
import json
import os
import re
import sys
from typing import Dict, List, Set, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLISH = re.compile(r"[ąćęłńóśźżĄĆĘŁŃÓŚŹŻ]")
FIELD = re.compile(r"(?<!\{)\{([A-Za-z_][A-Za-z0-9_]*)[^{}]*\}(?!\})")
TRANSLATE_FUNCS = {"_", "_h", "N_"}
LOGGER_METHODS = {"debug", "info", "warning", "error", "exception", "critical", "log"}

AREAS = {
    "app": {
        "py": ["main.py", "ui/*.py", "core/*.py", "sync/*.py", "backups/*.py", "importers/*.py"],
        "templates": [],
        "skip": ["core/i18n.py"],
        "locales": "core/locales",
    },
    "server": {
        "py": ["server/*.py"],
        "templates": ["server/templates/*.html"],
        "skip": ["server/i18n.py"],
        "locales": "server/locales",
    },
}


def _files(patterns: List[str], skip: List[str]) -> List[str]:
    out = []
    for p in patterns:
        out += [f for f in glob.glob(os.path.join(ROOT, p)) if os.path.relpath(f, ROOT).replace("\\", "/") not in skip]
    return sorted(out)


def _call_name(node: ast.Call) -> str:
    f = node.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""


def scan_python(path: str) -> Tuple[Set[str], Set[str], List[str]]:
    """(teksty do tłumaczenia, klucze liczby mnogiej, nieopakowane polskie teksty)."""
    source = open(path, encoding="utf-8").read()
    lines = source.splitlines()
    tree = ast.parse(source)
    keys, plural_keys, problems = set(), set(), []
    ignored = set()

    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                ignored.add(id(first.value))
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name in TRANSLATE_FUNCS and node.args and isinstance(node.args[0], ast.Constant):
                keys.add(node.args[0].value)
                ignored.add(id(node.args[0]))
            elif name == "_n" and len(node.args) >= 4:
                for a in node.args[1:4]:
                    if isinstance(a, ast.Constant):
                        ignored.add(id(a))
                if isinstance(node.args[3], ast.Constant):
                    plural_keys.add(node.args[3].value)
            elif name in LOGGER_METHODS and isinstance(node.func, ast.Attribute) and \
                    "log" in ast.unparse(node.func.value).lower():
                for sub in ast.walk(node):
                    ignored.add(id(sub))

    def mark(node):
        for sub in ast.walk(node):
            ignored.add(id(sub))

    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr) and id(node) not in ignored:
            text = "".join(v.value for v in node.values if isinstance(v, ast.Constant))
            if POLISH.search(text) and "i18n: data" not in lines[node.lineno - 1]:
                problems.append(f"{os.path.relpath(path, ROOT)}:{node.lineno}: f-string: {text[:70]!r}")
            mark(node)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in ignored:
            if POLISH.search(node.value) and "i18n: data" not in lines[node.lineno - 1]:
                problems.append(f"{os.path.relpath(path, ROOT)}:{node.lineno}: {node.value[:70]!r}")
    return keys, plural_keys, problems


_TPL_CALL = re.compile(r"""\b(_|_h|N_)\(\s*(["'])((?:\\.|(?!\2).)*)\2""", re.S)
_TPL_PLURAL = re.compile(r"""\b_n\([^,]+,\s*(["'])(?:\\.|(?!\1).)*\1\s*,\s*(["'])(?:\\.|(?!\2).)*\2\s*,\s*(["'])((?:\\.|(?!\3).)*)\3""", re.S)
_TPL_CODE = re.compile(r"\{\{.*?\}\}|\{%.*?%\}|\{#.*?#\}", re.S)


def _unescape(text: str) -> str:
    return text.encode("utf-8").decode("unicode_escape").encode("latin-1").decode("utf-8") if "\\" in text else text


def scan_template(path: str) -> Tuple[Set[str], Set[str], List[str]]:
    source = open(path, encoding="utf-8").read()
    keys = {_unescape(m.group(3)) for m in _TPL_CALL.finditer(source)}
    plural_keys = {_unescape(m.group(4)) for m in _TPL_PLURAL.finditer(source)}
    problems = []
    stripped = _TPL_CODE.sub(lambda m: "\n" * m.group(0).count("\n"), source)
    stripped = re.sub(r"<style.*?</style>", lambda m: "\n" * m.group(0).count("\n"), stripped, flags=re.S)
    for no, line in enumerate(stripped.splitlines(), 1):
        if POLISH.search(line):
            problems.append(f"{os.path.relpath(path, ROOT)}:{no}: {line.strip()[:70]!r}")
    # polskie teksty wewnątrz {{ }} / {% %} poza wywołaniami _()
    for m in _TPL_CODE.finditer(source):
        code = _TPL_CALL.sub("", m.group(0))
        code = _TPL_PLURAL.sub("", code)
        code = re.sub(r"\b_n\(.*?\)", "", code, flags=re.S)
        if POLISH.search(code):
            no = source.count("\n", 0, m.start()) + 1
            problems.append(f"{os.path.relpath(path, ROOT)}:{no}: w kodzie szablonu: {m.group(0)[:70]!r}")
    return keys, plural_keys, problems


def collect(area: str) -> Tuple[Set[str], Set[str], List[str]]:
    cfg = AREAS[area]
    keys, plural_keys, problems = set(), set(), []
    for f in _files(cfg["py"], cfg["skip"]):
        k, p, pr = scan_python(f)
        keys |= k
        plural_keys |= p
        problems += pr
    for f in _files(cfg["templates"], []):
        k, p, pr = scan_template(f)
        keys |= k
        plural_keys |= p
        problems += pr
    return keys, plural_keys, problems


def load_catalog(area: str, lang: str, conflicts: List[str] = None) -> Dict[str, object]:
    catalog, origin = {}, {}
    for path in sorted(glob.glob(os.path.join(ROOT, AREAS[area]["locales"], lang, "*.json"))):
        with open(path, encoding="utf-8") as f:
            for k, v in json.load(f).items():
                if conflicts is not None and k in catalog and catalog[k] != v:
                    conflicts.append(f"różne tłumaczenia {k[:50]!r}: {catalog[k]!r} ({origin[k]}) / {v!r} "
                                     f"({os.path.basename(path)})")
                catalog[k], origin[k] = v, os.path.basename(path)
    return catalog


def check_catalog(area: str, lang: str = "en") -> List[str]:
    keys, plural_keys, _ = collect(area)
    problems = []
    catalog = load_catalog(area, lang, problems)
    for key in sorted(keys - plural_keys):
        value = catalog.get(key)
        if not isinstance(value, str) or not value.strip():
            problems.append(f"brak tłumaczenia: {key[:90]!r}")
        elif set(FIELD.findall(key)) != set(FIELD.findall(value)):
            problems.append(f"inne zmienne {{…}}: {key[:60]!r} → {value[:60]!r}")
        elif POLISH.search(value):
            problems.append(f"polskie znaki w tłumaczeniu: {value[:90]!r}")
    for key in sorted(plural_keys):
        value = catalog.get(key)
        if not (isinstance(value, list) and len(value) == 2 and all(isinstance(v, str) and v for v in value)):
            problems.append(f"brak tłumaczenia liczby mnogiej [pojedyncza, mnoga]: {key[:80]!r}")
    return problems


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "app"
    _, _, wrap = collect(which)
    missing = check_catalog(which)
    sys.stdout.reconfigure(encoding="utf-8")
    print(f"== nieopakowane polskie teksty: {len(wrap)}")
    print("\n".join(wrap[:400]))
    print(f"== braki w katalogu en: {len(missing)}")
    print("\n".join(missing[:400]))
