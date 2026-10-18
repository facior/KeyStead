"""
Klucze SSH w sejfie: odczyt kluczy (OpenSSH, PEM, PuTTY .ppk – także oficjalne pliki testowe), podpisy,
protokół agenta oraz oba kanały (potok Windows OpenSSH i okno Pageanta) z prawdziwymi ssh-add / ssh-keygen.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
import uuid

from cryptography.hazmat.primitives.asymmetric import ed25519

from core import plugins, ssh_keys
from core.ssh_agent import (SSH_AGENT_FAILURE, SSH_AGENT_IDENTITIES_ANSWER, SSH_AGENT_SIGN_RESPONSE,
                            SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENTC_SIGN_REQUEST, AgentService, SshAgent,
                            pageant_request)
from core.ssh_keys import Reader, ssh_string
from core.vault import VaultEntry

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "ppk")
OPENSSH = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "OpenSSH")
HAS_OPENSSH = os.name == "nt" and os.path.isfile(os.path.join(OPENSSH, "ssh-add.exe"))

# Klucze publiczne z niezależnego zestawu (sprawdzone przez OpenSSH ssh-keygen) – patrz fixtures/ppk/README.md
GOLDEN = {
    "ed25519": "AAAAC3NzaC1lZDI1NTE5AAAAIDAdJiRkkBM8yC8seTEoAn2PfwbLKrkcahZ0xxPoWICJ",
    "rsa2048": "AAAAB3NzaC1yc2EAAAADAQABAAABAQCBjWQHMpKAQnU3vZZF/iHn4RA867Ox+U03/GOHivW0SgGIQbhKcSSWvTzYOE+GQdtX9T2K"
               "Jxr76z/lB4nghkcWkpLoQW91gNBfPUagMvaBxKXC8cNqaMm99uw5KpRg8SpTJWxwYPlQtzmyxav0PRFeOMSsiRsnjNuXpolMDSu6"
               "vmkkuKrPzvinPZbsXoZeMybcm1gn2Zq+7ik4us0icaGxRJRuF+nVqYagEmO9jmQoytyqoNWzvPYEh/dh85hESwtIKXiaMOjQg52d"
               "W5BuELPGV7ZxaKRK7ZnwRGW6CtoGYulo0mJz5IZslDrRK/EK2bSGDbrlAcYaajROB6aBDyaJ",
}

# Oficjalny wektor testowy PuTTY (test/cryptsuite.py, testPPKLoadSave), hasło „test-passphrase”
PUTTY_ENCRYPTED = """PuTTY-User-Key-File-2: ssh-ed25519
Encryption: aes256-cbc
Comment: ed25519-key-20200105
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIHJCszOHaI9X/yGLtjn22f0hO6VPMQDVtctkym6F
JH1W
Private-Lines: 1
4/jKlTgC652oa9HLVGrMjHZw7tj0sKRuZaJPOuLhGTvb25Jzpcqpbi+Uf+y+uo+Z
Private-MAC: 5b1f6f4cc43eb0060d2c3e181bc0129343adba2b
"""


def fixture(name):
    with open(os.path.join(FIXTURES, name + ".ppk"), encoding="utf-8") as f:
        return f.read()


class KeyLoadingTests(unittest.TestCase):
    def test_ppk_fixtures_match_independent_public_keys(self):
        for name, password, golden in (("v2-ed25519-none", "", "ed25519"), ("v2-ed25519-aes256-cbc", "123456", "ed25519"),
                                       ("v3-ed25519-none", "", "ed25519"),
                                       ("v3-rsa-argon2id-aes256-cbc", "changeit", "rsa2048"),
                                       ("v3-rsa-argon2i-aes256-cbc", "changeit", "rsa2048"),
                                       ("v3-rsa-argon2d-aes256-cbc", "changeit", "rsa2048")):
            key = ssh_keys.load_key(fixture(name), password)
            self.assertEqual(key.public_line().split()[1], GOLDEN[golden], name)

    def test_ppk_wrong_or_missing_passphrase(self):
        for name in ("v2-ed25519-aes256-cbc", "v3-rsa-argon2id-aes256-cbc"):
            with self.assertRaisesRegex(ssh_keys.SshKeyError, "Złe hasło"):
                ssh_keys.load_key(fixture(name), "zle")
            with self.assertRaisesRegex(ssh_keys.SshKeyError, "zabezpieczony hasłem"):
                ssh_keys.load_key(fixture(name), "")

    def test_ppk_tampered_file_rejected(self):
        text = fixture("v3-ed25519-none").replace("Comment: root@sshj", "Comment: ktos@inny")
        with self.assertRaisesRegex(ssh_keys.SshKeyError, "Uszkodzony"):
            ssh_keys.load_key(text)

    def test_putty_official_vector(self):
        key = ssh_keys.load_key(PUTTY_ENCRYPTED, "test-passphrase")
        self.assertEqual(key.comment, "ed25519-key-20200105")
        self.assertEqual(key.public_blob.hex(), "0000000b7373682d65643235353139000000207242b33387688f57ff218bb639"
                                                "f6d9fd213ba54f3100d5b5cb64ca6e85247d56")

    def test_short_rsa_and_public_key_rejected(self):
        with self.assertRaisesRegex(ssh_keys.SshKeyError, "2048"):
            ssh_keys.load_key(fixture("v2-rsa-none"))
        with self.assertRaisesRegex(ssh_keys.SshKeyError, "PUBLICZNY"):
            ssh_keys.load_key("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDAdJiRkkBM8yC8seTEoAn2PfwbLKrkcahZ0xxPoWICJ x")
        with self.assertRaises(ssh_keys.SshKeyError):
            ssh_keys.load_key("cokolwiek")

    def test_generated_key_round_trip_with_comment(self):
        text = ssh_keys.generate_ed25519("jan@firma")
        key = ssh_keys.load_key(text, "haslo-do-serwera")  # klucz bez hasła + hasło wpisu – też działa
        self.assertEqual(key.comment, "jan@firma")
        self.assertTrue(key.public_line().startswith("ssh-ed25519 ") and key.public_line().endswith(" jan@firma"))
        self.assertTrue(key.fingerprint().startswith("SHA256:"))

    @unittest.skipUnless(HAS_OPENSSH, "brak Windows OpenSSH")
    def test_keys_from_real_ssh_keygen(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        for kind, extra in (("ed25519", []), ("ecdsa", []), ("rsa", ["-b", "2048"]), ("rsa", ["-b", "2048", "-m", "PEM"])):
            path = os.path.join(tmp, f"k{len(os.listdir(tmp))}")
            subprocess.run([os.path.join(OPENSSH, "ssh-keygen.exe"), "-q", "-t", kind, *extra, "-N", "tajne",
                            "-C", f"test-{kind}", "-f", path], check=True, capture_output=True)
            with open(path) as f:
                key = ssh_keys.load_key(f.read(), "tajne")
            with open(path + ".pub") as f:
                self.assertEqual(key.public_line().split()[:2], f.read().split()[:2])

    def test_key_from_entry(self):
        e = VaultEntry("Serwer", password="123456", custom_fields={ssh_keys.KEY_FIELD: fixture("v2-ed25519-aes256-cbc")})
        key = ssh_keys.key_from_entry(e)
        self.assertEqual((key.entry_id, key.entry_title), (e.id, "Serwer"))


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.key = ssh_keys.load_key(ssh_keys.generate_ed25519("test"))
        self.allowed = True
        self.used = []
        self.agent = SshAgent(lambda: [self.key], lambda k, c: self.used.append(c) or self.allowed)

    def sign(self, data=b"dane", blob=None):
        return self.agent.handle(bytes([SSH_AGENTC_SIGN_REQUEST]) + ssh_string(blob or self.key.public_blob)
                                 + ssh_string(data) + b"\0\0\0\0", "ssh.exe")

    def test_identities(self):
        reply = self.agent.handle(bytes([SSH_AGENTC_REQUEST_IDENTITIES]))
        self.assertEqual(reply[0], SSH_AGENT_IDENTITIES_ANSWER)
        r = Reader(reply[1:])
        self.assertEqual(r.uint32(), 1)
        self.assertEqual(r.string(), self.key.public_blob)
        self.assertEqual(r.string(), b"test")

    def test_sign_verifies(self):
        reply = self.sign(b"wiadomosc")
        self.assertEqual(reply[0], SSH_AGENT_SIGN_RESPONSE)
        sig = Reader(Reader(reply[1:]).string())
        self.assertEqual(sig.string(), b"ssh-ed25519")
        blob = Reader(self.key.public_blob)
        self.assertEqual(blob.string(), b"ssh-ed25519")
        ed25519.Ed25519PublicKey.from_public_bytes(blob.string()).verify(sig.string(), b"wiadomosc")
        self.assertEqual(self.used, ["ssh.exe"])

    def test_refusals(self):
        self.allowed = False
        self.assertEqual(self.sign(), bytes([SSH_AGENT_FAILURE]))           # użytkownik odmówił
        self.allowed = True
        other = ssh_keys.load_key(ssh_keys.generate_ed25519("x")).public_blob
        self.assertEqual(self.sign(blob=other), bytes([SSH_AGENT_FAILURE]))  # nieznany klucz
        for msg in (b"", b"\x11" + b"\0" * 8, b"\x12", b"\x13\0", b"\x0d\xff\xff\xff\xff"):  # dodawanie, usuwanie, śmieci
            self.assertEqual(self.agent.handle(msg), bytes([SSH_AGENT_FAILURE]))
        self.agent.enabled = False                                          # sejf zablokowany
        self.assertEqual(self.agent.handle(bytes([SSH_AGENTC_REQUEST_IDENTITIES])), bytes([SSH_AGENT_FAILURE]))

    def test_rsa_sha2_flags(self):
        rsa = ssh_keys.load_key(fixture("v3-rsa-argon2id-aes256-cbc"), "changeit")
        for flags, name in ((0, b"ssh-rsa"), (2, b"rsa-sha2-256"), (4, b"rsa-sha2-512")):
            self.assertEqual(Reader(rsa.sign(b"x", flags)).string(), name)


@unittest.skipUnless(os.name == "nt", "kanały agenta są tylko w Windows")
class ChannelTests(unittest.TestCase):
    """Kanały pod testowymi nazwami – prawdziwe „openssh-ssh-agent” i „Pageant” pozostają nietknięte."""

    def setUp(self):
        self.pipe = rf"\\.\pipe\keystead-test-{uuid.uuid4().hex[:8]}"
        self.window = f"KeySteadTest{uuid.uuid4().hex[:8]}"
        self.key = ssh_keys.load_key(ssh_keys.generate_ed25519("e2e"))
        self.used = []
        self.service = AgentService(lambda: [self.key], lambda k, c: self.used.append(c) or True,
                                    pipe_name=self.pipe, pageant_class=self.window)
        self.assertEqual(self.service.start(), {"openssh": "running", "pageant": "running"})
        self.addCleanup(self.service.stop)

    def test_second_agent_does_not_steal_channels(self):
        other = AgentService(lambda: [], lambda k, c: True, pipe_name=self.pipe, pageant_class=self.window)
        self.assertEqual(other.start(), {"openssh": "busy", "pageant": "busy"})
        other.stop()

    def test_pageant_window(self):
        reply = pageant_request(bytes([SSH_AGENTC_REQUEST_IDENTITIES]), self.window)
        self.assertEqual(reply[0], SSH_AGENT_IDENTITIES_ANSWER)
        self.assertEqual(Reader(reply[1:]).uint32(), 1)
        self.service.stop()
        self.assertIsNone(pageant_request(bytes([SSH_AGENTC_REQUEST_IDENTITIES]), self.window))

    @unittest.skipUnless(HAS_OPENSSH, "brak Windows OpenSSH")
    def test_real_ssh_add_and_ssh_keygen_signature(self):
        env = dict(os.environ, SSH_AUTH_SOCK=self.pipe)
        listed = subprocess.run([os.path.join(OPENSSH, "ssh-add.exe"), "-l"], env=env, capture_output=True, text=True)
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertIn(self.key.fingerprint(), listed.stdout)

        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        data, pub, allowed = (os.path.join(tmp, n) for n in ("data.txt", "key.pub", "allowed"))
        for path, text in ((data, "podpisz mnie"), (pub, self.key.public_line()),
                           (allowed, "tester " + " ".join(self.key.public_line().split()[:2]))):
            with open(path, "w") as f:
                f.write(text + "\n")
        signed = subprocess.run([os.path.join(OPENSSH, "ssh-keygen.exe"), "-Y", "sign", "-f", pub, "-n", "file", data],
                                env=env, capture_output=True, text=True)
        self.assertEqual(signed.returncode, 0, signed.stderr)
        with open(data, "rb") as f:
            verified = subprocess.run([os.path.join(OPENSSH, "ssh-keygen.exe"), "-Y", "verify", "-f", allowed, "-I",
                                       "tester", "-n", "file", "-s", data + ".sig"], stdin=f, capture_output=True, text=True)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(self.used, ["ssh-keygen.exe"])

        self.service.stop()
        listed = subprocess.run([os.path.join(OPENSSH, "ssh-add.exe"), "-l"], env=env, capture_output=True, text=True)
        self.assertNotEqual(listed.returncode, 0)  # po zablokowaniu sejfu agenta nie ma


class PluginOptionsTests(unittest.TestCase):
    def test_options_round_trip(self):
        settings = {}
        self.assertEqual(plugins.options(settings, "ssh_agent"), {})
        plugins.set_options(settings, "ssh_agent", {"confirm": True})
        self.assertTrue(plugins.options(settings, "ssh_agent")["confirm"])
        settings["plugin_options"] = "zepsute"
        self.assertEqual(plugins.options(settings, "ssh_agent"), {})


if __name__ == "__main__":
    unittest.main()
