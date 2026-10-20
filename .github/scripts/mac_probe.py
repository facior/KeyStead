"""Diagnostyka Tk na macOS: każdy scenariusz w osobnym procesie, wynik (ok / kod błędu) na wyjściu."""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SCENARIOS = {
    "ctk_offscreen": """
import customtkinter as ctk, time
r = ctk.CTk(); r.geometry("400x300+-4000+-4000")
for _ in range(50): r.update(); time.sleep(0.01)
r.destroy()
""",
    "mainview_onscreen": """
import customtkinter as ctk, time, tempfile, os
from core.vault import Vault, VaultEntry
from ui.main_view import MainView
r = ctk.CTk(); r.geometry("1300x850+20+20")
v = Vault("x"); v.add_entry(VaultEntry("A", username="u", password="p"))
m = MainView(r, v, "pw", os.path.join(tempfile.mkdtemp(), "v.vault")); m.pack(fill="both", expand=True)
for _ in range(50): r.update(); time.sleep(0.01)
r.destroy()
""",
    "mainview_offscreen": """
import customtkinter as ctk, time, tempfile, os
from core.vault import Vault, VaultEntry
from ui.main_view import MainView
r = ctk.CTk(); r.geometry("1300x850+-4000+-4000")
v = Vault("x"); v.add_entry(VaultEntry("A", username="u", password="p"))
m = MainView(r, v, "pw", os.path.join(tempfile.mkdtemp(), "v.vault")); m.pack(fill="both", expand=True)
for _ in range(50): r.update(); time.sleep(0.01)
r.destroy()
""",
    "two_roots_onscreen": """
import customtkinter as ctk, time, tempfile, os
from core.vault import Vault, VaultEntry
from ui.main_view import MainView
for i in range(2):
    r = ctk.CTk(); r.geometry("1300x850+20+20")
    v = Vault("x"); v.add_entry(VaultEntry("A", username="u", password="p"))
    m = MainView(r, v, "pw", os.path.join(tempfile.mkdtemp(), "v.vault")); m.pack(fill="both", expand=True)
    for _ in range(50): r.update(); time.sleep(0.01)
    r.destroy()
""",
}

for name, code in SCENARIOS.items():
    proc = subprocess.run([sys.executable, "-X", "faulthandler", "-c", "import tests; " + code], cwd=ROOT,
                          capture_output=True, text=True, timeout=120)
    print(f"=== {name}: exit {proc.returncode}")
    if proc.returncode:
        print(proc.stderr[-3000:])
