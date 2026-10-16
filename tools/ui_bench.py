"""
Pomiar płynności głównego widoku (python tools/ui_bench.py [liczba_wpisów]).
Mierzy czasy operacji, które użytkownik wykonuje najczęściej – im mniej, tym płynniej.
"""

import os
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import customtkinter as ctk  # noqa: E402

from core.vault import Vault, VaultEntry  # noqa: E402
from ui.main_view import MainView  # noqa: E402


def timed(root, label, fn, repeat=1):
    root.update()
    t = time.perf_counter()
    for _ in range(repeat):
        fn()
        root.update()  # łącznie z przerysowaniem okna
    ms = (time.perf_counter() - t) * 1000 / repeat
    print(f"  {label:42} {ms:8.1f} ms")
    return ms


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    vault = Vault("Benchmark")
    cats = ["Loginy", "Bankowość", "Serwery", "Notatki"]
    for i in range(n):
        vault.add_entry(VaultEntry(title=f"Serwis {i:04d}", category=cats[i % 4], username=f"user{i}@firma.pl",
                                   password="x" * 16, url=f"https://s{i}.example.com"))
    path = os.path.join(tempfile.mkdtemp(), "bench.vault")

    root = ctk.CTk()
    root.geometry("1240x800")
    root.update()
    print(f"Wpisów: {n}")
    view = None

    def build():
        nonlocal view
        view = MainView(root, vault, "haslo-benchmark-123", path)
        view.pack(fill="both", expand=True)

    timed(root, "Otwarcie sejfu (budowa widoku)", build)
    ids = list(vault.entries)
    k = iter(range(10 ** 6))
    timed(root, "Kliknięcie wpisu", lambda: view._select_entry(ids[next(k) * 7 % n]), repeat=5)

    def type_char(text):
        view.search_entry.delete(0, "end")
        view.search_entry.insert(0, text)
        view._on_search_typed()
        if hasattr(view, "_flush_search"):
            view._flush_search()

    timed(root, "Wpisanie litery w wyszukiwarce ('s')", lambda: type_char("s"))
    timed(root, "Kolejna litera ('se')", lambda: type_char("se"))
    timed(root, "Wyczyszczenie wyszukiwania", lambda: type_char(""))
    timed(root, "Zmiana kategorii", lambda: view._select_category("Serwery"))
    timed(root, "Powrót do 'Wszystkie'", lambda: view._select_category("Wszystkie"))
    timed(root, "Zapis sejfu (np. po edycji wpisu)", lambda: view._save_vault_to_disk(trigger_backup=False))
    if hasattr(view, "wait_for_saves"):
        view.wait_for_saves()
    root.destroy()


if __name__ == "__main__":
    main()
