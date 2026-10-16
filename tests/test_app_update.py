"""
Testy aktualizacji aplikacji: weryfikacja podpisów SSHSIG w czystym Pythonie (zgodność z ssh-keygen),
wybór wydania z GitHuba (tylko tagi app-v*), pobieranie z kontrolą podpisu i sumy kontrolnej.
"""

import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest

from core import app_update, sshsig
from core.app_update import AppRelease, UpdateError, asset_names


def _find_ssh_keygen():
    for path in (shutil.which("ssh-keygen"), r"C:\Program Files\Git\usr\bin\ssh-keygen.exe"):
        if path and os.path.exists(path):
            return path
    return None


SSH_KEYGEN = _find_ssh_keygen()

NS = app_update.SIGNING_NAMESPACE


def make_key(folder, name="k"):
    path = os.path.join(folder, name)
    subprocess.run([SSH_KEYGEN, "-q", "-t", "ed25519", "-N", "", "-f", path], check=True, capture_output=True)
    with open(path + ".pub", encoding="ascii") as f:
        return path, f.read().strip()


def sign(key, data, namespace=NS):
    return subprocess.run([SSH_KEYGEN, "-Y", "sign", "-f", key, "-n", namespace], input=data,
                          capture_output=True, check=True).stdout


@unittest.skipUnless(SSH_KEYGEN, "brak ssh-keygen")
class TestSshSig(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.key, cls.pub = make_key(cls.tmp)
        cls.other_key, _ = make_key(cls.tmp, "other")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_valid(self):
        sshsig.verify(self.pub, b"hello", sign(self.key, b"hello"), NS)
        sshsig.verify(f"keystead-release {self.pub}", b"", sign(self.key, b""), NS)  # format allowed_signers

    def test_rejections(self):
        good = sign(self.key, b"hello")
        cases = {
            "zmieniona treść": (b"hellO", good, NS),
            "inny cel": (b"hello", sign(self.key, b"hello", "file"), NS),
            "inny klucz": (b"hello", sign(self.other_key, b"hello"), NS),
            "śmieci": (b"hello", b"-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----", NS),
            "brak opakowania": (b"hello", b"xyz", NS),
        }
        for label, (msg, sig, ns) in cases.items():
            with self.assertRaises(sshsig.SignatureError, msg=label):
                sshsig.verify(self.pub, msg, sig, ns)

    def test_bit_flip_in_signature(self):
        sig = bytearray(sign(self.key, b"hello"))
        lines = sig.split(b"\n")
        body = bytearray(lines[3])  # środek danych base64 (sam podpis)
        body[10] = ord("A") if body[10] != ord("A") else ord("B")
        lines[3] = bytes(body)
        with self.assertRaises(sshsig.SignatureError):
            sshsig.verify(self.pub, b"hello", b"\n".join(lines), NS)

    def test_embedded_release_key_parses(self):
        sshsig.parse_public_key(app_update.RELEASE_PUBLIC_KEY)
        server_pub = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                  "server", "deploy", "release-signing.pub")
        if os.path.exists(server_pub):  # w repozytorium aplikacji katalogu serwera nie ma
            with open(server_pub, encoding="ascii") as f:
                server_key = f.read().split()
            self.assertEqual(app_update.RELEASE_PUBLIC_KEY.split()[:2], server_key[1:3])  # jeden klucz wydawcy


class FakeResponse:
    def __init__(self, status=200, content=b"", json_data=None):
        self.status_code = status
        self.content = content
        self._json = json_data
        self.headers = {"Content-Length": str(len(content))}

    def json(self):
        return self._json

    def iter_content(self, size):
        for i in range(0, len(self.content), size):
            yield self.content[i:i + size]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeHttp:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get(self, url, **kw):
        self.calls.append(url)
        r = self.routes.get(url)
        return r if r is not None else FakeResponse(404)


def gh_release(tag, assets=(), draft=False, prerelease=False):
    return {"tag_name": tag, "draft": draft, "prerelease": prerelease, "html_url": f"https://gh/{tag}", "body": "",
            "assets": [{"name": n, "browser_download_url": f"https://dl/{n}"} for n in assets]}


class TestCheck(unittest.TestCase):
    API = f"https://api.github.com/repos/{app_update.REPOSITORY}/releases"

    def check(self, releases, current="1.0.0"):
        return app_update.check_for_update(current, http=FakeHttp({self.API: FakeResponse(json_data=releases)}))

    def test_picks_highest_release(self):
        rel = self.check([gh_release("v1.2.0"), gh_release("v1.10.0"), gh_release("nightly"),
                          gh_release("v2.0.0", prerelease=True), gh_release("v3.0.0", draft=True),
                          gh_release("vX"), gh_release("v1.2")])
        self.assertEqual(rel.version, "1.10.0")  # szkice, wydania testowe i nietypowe tagi pomijane

    def test_no_update(self):
        self.assertIsNone(self.check([gh_release("v1.0.0"), gh_release("v0.9.0")]))
        self.assertIsNone(self.check([]))

    def test_github_error(self):
        with self.assertRaises(UpdateError):
            app_update.check_for_update("1.0.0", http=FakeHttp({self.API: FakeResponse(403)}))


@unittest.skipUnless(SSH_KEYGEN, "brak ssh-keygen")
class TestDownload(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.key, self.pub = make_key(self.tmp)
        self.names = asset_names("1.1.0")
        self.setup_bytes = os.urandom(700_000)
        self.sums = f"{hashlib.sha256(self.setup_bytes).hexdigest()}  {self.names['setup']}\n".encode()
        self.release = AppRelease("1.1.0", "https://gh", assets={n: f"https://dl/{n}" for n in self.names.values()})

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def http(self, setup=None, sums=None, sig=None):
        sums = sums if sums is not None else self.sums
        return FakeHttp({
            f"https://dl/{self.names['setup']}": FakeResponse(content=setup if setup is not None else self.setup_bytes),
            f"https://dl/{self.names['sums']}": FakeResponse(content=sums),
            f"https://dl/{self.names['sig']}": FakeResponse(content=sig if sig is not None else sign(self.key, sums)),
        })

    def download(self, http):
        return app_update.download_update(self.release, dest_dir=os.path.join(self.tmp, "dl"), public_key=self.pub, http=http)

    def test_ok(self):
        seen = []
        path = app_update.download_update(self.release, dest_dir=os.path.join(self.tmp, "dl"), public_key=self.pub,
                                          http=self.http(), progress=lambda d, t: seen.append(d))
        with open(path, "rb") as f:
            self.assertEqual(f.read(), self.setup_bytes)
        self.assertEqual(seen[-1], len(self.setup_bytes))

    def test_tampered_installer(self):
        with self.assertRaisesRegex(UpdateError, "Suma kontrolna"):
            self.download(self.http(setup=self.setup_bytes + b"x"))
        self.assertEqual(os.listdir(os.path.join(self.tmp, "dl")), [])  # nic nie zostaje na dysku

    def test_forged_sums(self):
        evil = os.urandom(1000)
        forged = f"{hashlib.sha256(evil).hexdigest()}  {self.names['setup']}\n".encode()
        with self.assertRaisesRegex(UpdateError, "PODPIS"):
            self.download(self.http(setup=evil, sums=forged, sig=sign(self.key, self.sums)))
        other_key, _ = make_key(self.tmp, "attacker")
        with self.assertRaisesRegex(UpdateError, "PODPIS"):
            self.download(self.http(setup=evil, sums=forged, sig=sign(other_key, forged)))

    def test_server_release_signature_not_reusable(self):
        # Podpisana lista serwera nie zawiera instalatora aplikacji
        sums = b"abc  keystead-server-1.2.1.tar.gz\n"
        with self.assertRaisesRegex(UpdateError, "nie zawiera instalatora"):
            self.download(self.http(sums=sums))

    def test_missing_assets(self):
        self.release.assets.pop(self.names["sig"])
        with self.assertRaisesRegex(UpdateError, "SHA256SUMS.sig"):
            self.download(self.http())


class TestModes(unittest.TestCase):
    def test_source_run_never_self_installs(self):
        self.assertFalse(app_update.is_frozen())
        self.assertFalse(app_update.can_self_install())


if __name__ == "__main__":
    unittest.main()
