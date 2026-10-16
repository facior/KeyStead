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

    def labels_text(self):
        def walk(w):
            for c in w.winfo_children():
                yield c
                yield from walk(c)
        panel = self.view._details_cache[next(reversed(self.view._details_cache))][0]
        return " ".join(str(w.cget("text")) for w in walk(panel) if w.winfo_class() == "Label")

    def test_details_panel_reused_with_current_entry(self):
        ids = [e["id"] for e in self.view.entry_list.items]
        a, b = self.vault.get_entry(ids[0]), self.vault.get_entry(ids[2])  # ten sam układ sekcji
        self.view._select_entry(a.id)
        self.pump()
        panel = self.view._details_cache[next(reversed(self.view._details_cache))][0]
        self.view._select_entry(b.id)
        self.pump()
        self.assertIs(self.view._details_cache[next(reversed(self.view._details_cache))][0], panel)
        self.assertIn(b.username, self.labels_text())
        self.assertNotIn(a.username, self.labels_text())
        # przyciski działają na pokazanym wpisie, nie na tym, dla którego panel zbudowano
        self.assertIs(self.view._details_entry, b)
        # „Pokaż hasło” na ponownie użytym panelu
        self.view._toggle_details_password(b.password)
        self.assertEqual(self.view.pwd_display_lbl.cget("text"), b.password)
        self.assertIn("Ukryj", self.view._pwd_toggle_btn.cget("text"))
        self.view._select_entry(a.id)  # nowy wpis – hasło znów ukryte
        self.pump()
        self.assertNotIn(a.password, self.view.pwd_display_lbl.cget("text"))
        self.assertIn("Pokaż", self.view._pwd_toggle_btn.cget("text"))

    def test_different_layout_gets_own_panel_and_old_one_is_kept(self):
        ids = [e["id"] for e in self.view.entry_list.items]
        first = self.vault.get_entry(ids[0])
        self.view._select_entry(first.id)
        self.pump()
        other = self.vault.get_entry(ids[1])
        other.notes = "Notatka tylko w tym wpisie"
        self.view._select_entry(other.id)
        self.pump()
        self.assertEqual(len(self.view._details_cache), 2)
        self.assertIn("Notatka tylko w tym wpisie", self.labels_text())
        mapped = [p.winfo_ismapped() for p, _s in self.view._details_cache.values()]
        self.assertEqual(sorted(mapped), [False, True])  # widoczny tylko jeden panel

    def test_mouse_wheel_shared_handler_and_smooth_scroll(self):
        def wheel_bindings():
            return self.root.tk.call("bind", "all", "<MouseWheel>").count("\n") + 1
        for _ in range(5):  # szuflady i pasek boczny tworzą nowe przewijane ramki
            self.view._open_settings_dialog()
            self.pump(0.1)
            self.view.drawer.close()
            self.view._toggle_sidebar_manually()
            self.pump(0.3)
        before = wheel_bindings()
        self.view._open_import_dialog()
        self.pump(0.1)
        self.assertEqual(wheel_bindings(), before)  # kolejne ramki nie dokładają globalnych procedur
        self.view.drawer.close()
        self.pump(0.3)

        entry = next(iter(self.vault.entries.values()))
        entry.notes = "Długa notatka. " * 400
        self.view._select_entry(entry.id)
        self.pump()
        canvas = self.view.details_scroll._parent_canvas
        bar = self.view.details_scroll._scrollbar
        canvas.event_generate("<MouseWheel>", delta=-240, x=10, y=10)
        self.pump(0.05)
        midway = canvas.canvasy(0)
        self.pump(0.4)
        self.assertGreater(canvas.canvasy(0), midway)  # animacja dojeżdża w kilku klatkach
        self.assertGreater(midway, 0)
        self.assertGreater(bar._start_value, 0)  # suwak nadąża za treścią

    def test_maximize_freezes_drawing_until_layout_is_done(self):
        import ctypes
        import sys as _sys
        from ui import perf
        if not _sys.platform.startswith("win"):
            self.skipTest("tylko Windows")
        freeze = perf.ResizeFreeze(self.root)
        freezes = []
        original = freeze._freeze
        freeze._freeze = lambda: (freezes.append(1), original())
        self.root.geometry("1900x1000")
        self.root.update()
        self.assertEqual(len(freezes), 1)  # duża zmiana naraz – rysowanie wstrzymane na czas układania
        self.pump(0.25)
        self.assertFalse(freeze.frozen)
        self.assertTrue(ctypes.windll.user32.IsWindowVisible(self.root.winfo_id()))  # rysowanie przywrócone
        self.root.geometry("1930x1000")  # małe przeciągnięcie krawędzi – bez wstrzymywania
        self.root.update()
        self.assertEqual(len(freezes), 1)

    def test_flat_button_click_and_window_breakpoints(self):
        from ui.flat_button import FlatButton
        clicked = []
        btn = FlatButton(self.view.details_scroll, text="✏️ Edytuj", width=75, command=lambda: clicked.append(1))
        btn.pack()
        self.pump()
        btn.event_generate("<ButtonRelease-1>", x=5, y=5)
        btn.event_generate("<ButtonRelease-1>", x=-50, y=5)  # puszczone poza przyciskiem – bez akcji
        self.assertEqual(clicked, [1])
        self.root.geometry("820x600")
        self.pump(0.3)
        self.assertTrue(self.view._is_compact_sidebar)
        self.assertEqual(self.view._toolbar_buttons[1][0].cget("text"), "⚡")
        self.root.geometry("1300x800")
        self.pump(0.3)
        self.assertFalse(self.view._is_compact_sidebar)
        self.assertEqual(self.view._toolbar_buttons[1][0].cget("text"), "⚡ Generator")


if __name__ == "__main__":
    unittest.main()
