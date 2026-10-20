"""Diagnostyka Tk na macOS: które włączone wtyczki wywracają okno główne. Każdy wariant w osobnym procesie."""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CODE = """
import customtkinter as ctk, time, tempfile, os, faulthandler
from core import plugins
from core.vault import Vault, VaultEntry
from ui.main_view import MainView
r = ctk.CTk(); r.geometry("1300x850+-4000+-4000")
v = Vault("x"); v.add_entry(VaultEntry("Netflix", username="dom@gmail.com", password="p", url="netflix.com"))
plugins.set_choices(v.settings, {CHOICES})
m = MainView(r, v, "pw", os.path.join(tempfile.mkdtemp(), "v.vault")); m.pack(fill="both", expand=True)
for _ in range(50): r.update(); time.sleep(0.01)
print("toolbar:", [w.cget("text") for w in m.winfo_children()[0].winfo_children() if "text" in w.keys()][:20])
r.destroy()
"""

VARIANTS = {
    "none": "",
    "family_share": '"family_share": True',
    "phone_handoff": '"phone_handoff": True',
    "both": '"family_share": True, "phone_handoff": True',
}
EMOJI = """
import tkinter as tk, time
r = tk.Tk(); r.geometry("+-4000+-4000")
for ch in {CHARS}:
    l = tk.Label(r, text=ch + " x", font=("Helvetica Neue", 13)); l.pack()
    for _ in range(5): r.update(); time.sleep(0.01)
    print("ok", repr(ch), flush=True)
r.destroy()
"""

for name, choices in VARIANTS.items():
    proc = subprocess.run([sys.executable, "-X", "faulthandler", "-c", "import tests\n" + CODE.replace("CHOICES", choices)],
                          cwd=ROOT, capture_output=True, text=True, timeout=120)
    print(f"=== {name}: exit {proc.returncode} {proc.stdout.strip()[-300:]}")
    if proc.returncode:
        print("\n".join(line for line in proc.stderr.splitlines() if 'File "' in line)[-2000:])

chars = ["👪", "📱", "🔑", "🚨", "🛡️", "☁️", "📥", "⚙️", "🔒", "✉", "🗝️", "🧩"]
proc = subprocess.run([sys.executable, "-X", "faulthandler", "-c", EMOJI.replace("{CHARS}", repr(chars))],
                      cwd=ROOT, capture_output=True, text=True, timeout=120)
print(f"=== emoji: exit {proc.returncode}\n{proc.stdout}")
