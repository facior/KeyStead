"""Ikony stron: domeny, blokada sieci wewnętrznej, limity obrazów, pamięć podręczna, kafelki zastępcze."""

import io
import os
import shutil
import tempfile
import unittest
from unittest import mock

from PIL import Image

from core import site_icons
from core.site_icons import IconCache, _decode_icon, site_domain
from ui.site_icons_ui import avatar_for


def png_bytes(size=(32, 32), color=(255, 0, 0, 255)):
    buf = io.BytesIO()
    Image.new("RGBA", size, color).save(buf, "PNG")
    return buf.getvalue()


class FakeResponse:
    def __init__(self, data, url, status=200):
        self.status_code, self.url = status, url
        self.raw = io.BytesIO(data)
        self.raw.read = lambda n=-1, decode_content=True, _r=self.raw.read: _r(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeSession:
    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def get(self, url, **kw):
        self.calls.append(url)
        data, final = self.routes.get(url, (None, url))
        return FakeResponse(data or b"", final, 200 if data is not None else 404)


def public_dns(host, *a, **kw):
    return [(2, 1, 6, "", ("93.184.216.34", 443))]


class TestDomains(unittest.TestCase):
    def test_site_domain(self):
        self.assertEqual(site_domain("https://www.github.com/login"), "github.com")
        self.assertEqual(site_domain("allegro.pl"), "allegro.pl")
        for no_icon in ("", "https://192.168.0.1", "http://router.local", "ftp://x.pl", "javascript:alert(1)",
                        "https://intranet", "https://srv.corp", "https://[::1]/"):
            self.assertIsNone(site_domain(no_icon), no_icon)

    def test_avatar_fallbacks(self):
        d, letter, color = avatar_for("Mój bank", "https://online.mbank.pl")
        self.assertEqual((d, letter), ("online.mbank.pl", "M"))
        self.assertTrue(color.startswith("#"))
        self.assertEqual(avatar_for("Notatka", "", "📝")[1], "📝")
        self.assertEqual(avatar_for("zadanie", "")[1], "Z")
        self.assertEqual(avatar_for("A", "https://x.pl")[2], avatar_for("B", "https://x.pl")[2])  # kolor wg domeny


class TestFetching(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cache = IconCache(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_icon_from_html_link(self):
        html = b'<html><head><link rel="icon" href="/static/ikona.png"></head></html>'
        s = FakeSession({"https://example.pl/": (html, "https://example.pl/"),
                         "https://example.pl/static/ikona.png": (png_bytes(), "https://example.pl/static/ikona.png")})
        with mock.patch.object(site_icons.socket, "getaddrinfo", public_dns):
            path = self.cache.fetch("example.pl", s)
        self.assertTrue(path and os.path.isfile(path))
        self.assertEqual(Image.open(path).size, (32, 32))
        self.assertFalse(self.cache.needs_fetch("example.pl"))

    def test_private_network_never_contacted(self):
        s = FakeSession({})
        with mock.patch.object(site_icons.socket, "getaddrinfo",
                               lambda *a, **k: [(2, 1, 6, "", ("10.0.0.5", 443))]):
            self.assertIsNone(self.cache.fetch("intranet-firmy.pl", s))
        self.assertEqual(s.calls, [])

    def test_redirect_to_private_rejected(self):
        s = FakeSession({"https://zly.pl/": (b"<html></html>", "https://192.168.1.1/"),
                         "https://zly.pl/favicon.ico": (png_bytes(), "https://192.168.1.1/favicon.ico")})

        def dns(host, *a, **k):
            return [(2, 1, 6, "", ("192.168.1.1" if host.startswith("192.") else "93.184.216.34", 443))]
        with mock.patch.object(site_icons.socket, "getaddrinfo", dns):
            self.assertIsNone(self.cache.fetch("zly.pl", s))

    def test_missing_icon_remembered(self):
        s = FakeSession({})
        with mock.patch.object(site_icons.socket, "getaddrinfo", public_dns):
            self.assertIsNone(self.cache.fetch("bez-ikony.pl", s))
        self.assertFalse(self.cache.needs_fetch("bez-ikony.pl"))  # ponowna próba dopiero po kilku dniach

    def test_image_bombs_and_garbage_rejected(self):
        self.assertIsNone(_decode_icon(b"to nie jest obraz"))
        self.assertIsNone(_decode_icon(png_bytes(size=(4000, 4000))))  # zbyt wiele pikseli
        self.assertIsNone(_decode_icon(png_bytes(size=(2, 2))))       # za mała
        self.assertIsNotNone(_decode_icon(png_bytes(size=(180, 180))))

    def test_oversized_download_rejected(self):
        big = b"x" * (site_icons.MAX_ICON_BYTES + 10)
        s = FakeSession({"https://duzy.pl/favicon.ico": (big, "https://duzy.pl/favicon.ico")})
        with mock.patch.object(site_icons.socket, "getaddrinfo", public_dns):
            self.assertIsNone(self.cache.fetch("duzy.pl", s))


if __name__ == "__main__":
    unittest.main()
