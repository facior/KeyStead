"""Tłumaczenia aplikacji: mechanizm _() / _n(), wybór języka i kompletność katalogu angielskiego."""

import json
import os
import tempfile
import unittest
from unittest import mock

from core import i18n
from tests import i18n_check


class TestTranslate(unittest.TestCase):
    def setUp(self):
        self.addCleanup(i18n.set_language, i18n.current_language())
        self.catalog = {"Zapisz": "Save", "Login „{title}” skopiowany": "Username for “{title}” copied",
                        "{n} wpisów": ["{n} entry", "{n} entries"], "Zepsute {x}": "Broken {y}"}

    def use(self, lang):
        i18n.set_language(lang)
        if lang == "en":
            i18n._catalog = dict(self.catalog)

    def test_polish_is_source(self):
        self.use("pl")
        self.assertEqual(i18n._("Zapisz"), "Zapisz")
        self.assertEqual(i18n._("Login „{title}” skopiowany", title="GitHub"), "Login „GitHub” skopiowany")
        self.assertEqual([i18n._n(n, "{n} wpis", "{n} wpisy", "{n} wpisów") for n in (1, 2, 5, 12, 22)],
                         ["1 wpis", "2 wpisy", "5 wpisów", "12 wpisów", "22 wpisy"])

    def test_english(self):
        self.use("en")
        self.assertEqual(i18n._("Zapisz"), "Save")
        self.assertEqual(i18n._("Login „{title}” skopiowany", title="GitHub"), "Username for “GitHub” copied")
        self.assertEqual([i18n._n(n, "{n} wpis", "{n} wpisy", "{n} wpisów") for n in (1, 5)], ["1 entry", "5 entries"])

    def test_missing_or_broken_translation_falls_back_to_polish(self):
        self.use("en")
        self.assertEqual(i18n._("Nieprzetłumaczone"), "Nieprzetłumaczone")
        self.assertEqual(i18n._("Zepsute {x}", x=1), "Zepsute 1")

    def test_braces_without_arguments_are_kept(self):
        self.use("pl")
        self.assertEqual(i18n._("{USERNAME}{TAB}{PASSWORD}"), "{USERNAME}{TAB}{PASSWORD}")

    def test_saved_choice_and_system_default(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(i18n, "PREFS_FILE", os.path.join(d, "language.json")), \
                mock.patch.object(i18n, "APP_DIR", d):
            self.assertIsNone(i18n.saved_language())
            i18n.save_language("en")
            self.assertEqual(i18n.saved_language(), "en")
            with open(i18n.PREFS_FILE, "w", encoding="utf-8") as f:
                json.dump({"language": "xx"}, f)
            self.assertIsNone(i18n.saved_language())
            with self.assertRaises(ValueError):
                i18n.save_language("xx")
        self.assertIn(i18n.system_language(), i18n.LANGUAGES)


class TestCatalogComplete(unittest.TestCase):
    """Każdy tekst interfejsu jest oznaczony do tłumaczenia i ma tłumaczenie angielskie."""

    def test_all_polish_texts_are_marked(self):
        _, _, problems = i18n_check.collect("app")
        self.assertEqual(problems, [], "\n" + "\n".join(problems[:60]))

    def test_english_catalog_is_complete(self):
        problems = i18n_check.check_catalog("app", "en")
        self.assertEqual(problems, [], "\n" + "\n".join(problems[:60]))

    def test_shipped_catalog_loads(self):
        catalog = i18n.load_catalog("en")
        self.assertTrue(catalog)
        self.assertTrue(all(isinstance(v, (str, list)) for v in catalog.values()))


if __name__ == "__main__":
    unittest.main()
