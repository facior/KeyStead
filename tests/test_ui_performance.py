"""
Testy płynności i poprawności głównego widoku: lista wpisów na płótnie, wyszukiwanie, zaznaczanie,
pasek kategorii, zapis sejfu w tle (kolejność, trwałość) oraz animacja panelu bocznego.
"""

import os
import shutil
import tempfile
import time
import unittest

from core.storage import background_saver, load_vault, save_vault
from core.vault import Vault, VaultEntry
from ui.theme import COLOR_PRIMARY

try:
    import customtkinter as ctk
    _root_probe = ctk.CTk()
    _root_probe.destroy()
    HAS_DISPLAY = True
except Exception:
    HAS_DISPLAY = False

PASSWORD = "haslo-testowe-123"


def make_vault(n=120):
    vault = Vault("Test")
    for i in range(n):
        vault.add_entry(VaultEntry(title=f"Serwis {i:03d}", category="Loginy" if i % 2 else "Serwery",
                                   username=f"user{i}@firma.pl", password="Abc!def12345xyz"))
    vault.add_category("Serwery")
    return vault


class TestBackgroundSaver(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "s.vault")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_last_save_wins_and_is_persisted(self):
        vault = make_vault(5)
        for i in range(5):
            vault.name = f"Wersja {i}"
            background_saver.submit(vault.to_json().encode(), self.path, PASSWORD)
        background_saver.flush()
        self.assertEqual(load_vault(self.path, PASSWORD).name, "Wersja 4")

    def test_sync_save_after_queued_old_password(self):
        # Zmiana hasła głównego: zapis starym hasłem z kolejki nie może nadpisać pliku po zapisie nowym hasłem
        vault = make_vault(5)
        background_saver.submit(vault.to_json().encode(), self.path, "stare-haslo-123")
        save_vault(vault, self.path, "nowe-haslo-456")
        background_saver.flush()
        self.assertEqual(load_vault(self.path, "nowe-haslo-456").name, "Test")


@unittest.skipUnless(HAS_DISPLAY, "brak środowiska graficznego")
class TestMainViewSmoothness(unittest.TestCase):
    def setUp(self):
        from ui.main_view import MainView
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "v.vault")
        self.vault = make_vault()
        save_vault(self.vault, self.path, PASSWORD)
        self.root = ctk.CTk()
        self.root.geometry("1240x800")
        self.view = MainView(self.root, self.vault, PASSWORD, self.path)
        self.view.pack(fill="both", expand=True)
        self.pump()

    def tearDown(self):
        background_saver.flush()
        self.root.destroy()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def pump(self, seconds=0.0):
        end = time.perf_counter() + seconds
        while True:
            self.root.update()
            if time.perf_counter() >= end:
                break
            time.sleep(0.01)

    def test_click_row_selects_entry_and_is_fast(self):
        lst = self.view.entry_list
        self.assertEqual(len(lst.items), 120)
        self.assertLess(len(lst._rects), 60)  # rysowane tylko widoczne wiersze
        row = 2
        y = lst._row_top(row) + lst.row_h // 2
        t = time.perf_counter()
        lst.canvas.event_generate("<Button-1>", x=40, y=y)
        self.pump()
        elapsed = time.perf_counter() - t
        self.assertEqual(self.view.selected_entry_id, lst.items[row]["id"])
        self.assertLess(elapsed, 1.0, f"kliknięcie trwało {elapsed:.2f} s")

    def test_scroll_draws_more_rows(self):
        lst = self.view.entry_list
        before = len(lst._rects)
        lst.canvas.yview_moveto(0.9)
        self.pump()
        self.assertGreater(len(lst._rects), before)
        self.assertIn(len(lst.items) - 1, lst._rects)

    def test_search_is_debounced_and_filters(self):
        self.view.search_entry.insert(0, "Serwis 00")
        self.view._on_search_typed()
        self.assertEqual(len(self.view.entry_list.items), 120)  # jeszcze bez filtrowania (opóźnienie)
        self.pump(0.3)
        self.assertEqual(len(self.view.entry_list.items), 10)

    def test_category_switch_reuses_sidebar(self):
        buttons = dict(self.view._sidebar_buttons)
        self.view._select_category("Serwery")
        self.pump()
        self.assertEqual(self.view._sidebar_buttons, buttons)  # te same przyciski, tylko inne kolory
        self.assertEqual(len(self.view.entry_list.items), 60)
        self.assertEqual(buttons[("cat", "Serwery")].cget("fg_color"), COLOR_PRIMARY)
        self.assertEqual(buttons[("cat", "Wszystkie")].cget("fg_color"), "transparent")

    def test_edit_saved_in_background(self):
        entry = next(iter(self.vault.entries.values()))
        entry.title = "Zmieniony tytuł"
        t = time.perf_counter()
        self.view._save_vault_to_disk(trigger_backup=False)
        self.assertLess(time.perf_counter() - t, 0.03)  # szyfrowanie nie blokuje okna
        background_saver.flush()
        reloaded = load_vault(self.path, PASSWORD)
        self.assertEqual(reloaded.get_entry(entry.id).title, "Zmieniony tytuł")

    def test_drawer_opens_and_closes(self):
        self.view._open_generator_dialog()
        self.pump(0.4)
        drawer = self.view.drawer
        self.assertTrue(drawer.is_open)
        self.assertFalse(drawer._animating)
        self.assertAlmostEqual(drawer._current_x_fraction, 1.0 - drawer._target_rel_width, places=3)
        drawer.close()
        self.pump(0.4)
        self.assertFalse(drawer.panel.winfo_ismapped())
        self.assertEqual(drawer.content_container.winfo_children(), [])


if __name__ == "__main__":
    unittest.main()
