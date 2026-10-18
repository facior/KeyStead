"""
YubiKey jako drugi składnik hasła głównego – z „udawanym” kluczem (HMAC-SHA1 z tajnym kluczem, jak w YubiKey).
Prawdziwy YubiKey musi sprawdzić użytkownik (patrz pamięć projektu) – tu sprawdzamy kryptografię i ścieżki awaryjne.
"""

import hashlib
import hmac
import os
import unittest
from unittest import mock

from core import crypto, yubikey
from core.crypto import (InvalidPasswordOrCorruptDataError, Keyring, YubiKeyRequiredError, password_yubikey, seal,
                         unseal, unseal_with_recovery_code)

DATA = b'{"entries": []}'


class FakeYubiKey:
    """Zachowuje się jak YubiKey w trybie challenge-response (HMAC-SHA1, wyzwanie zmiennej długości)."""

    def __init__(self, secret=None):
        self.secret = secret or os.urandom(20)
        self.calls = 0

    def __call__(self, challenge: bytes, slot: int = 2) -> bytes:
        self.calls += 1
        return hmac.new(self.secret, challenge, hashlib.sha1).digest()


class YubiKeyVaultTests(unittest.TestCase):
    def setUp(self):
        self.key = FakeYubiKey()
        yubikey.clear_cache()
        self.addCleanup(yubikey.clear_cache)
        patcher = mock.patch.object(yubikey, "respond", side_effect=lambda c, s=2: self.key(c, s))
        patcher.start()
        self.addCleanup(patcher.stop)

    def protected(self, password="Haslo-glowne-1", keyfile=None):
        ring = Keyring.new(password, keyfile)
        code = ring.add_recovery_code()
        challenge = os.urandom(32)
        ring.enable_yubikey(password, keyfile, challenge, self.key(challenge))
        return seal(DATA, password, keyfile, ring), ring, code

    def test_needs_the_same_yubikey(self):
        blob, _ring, _code = self.protected()
        self.assertEqual(password_yubikey(blob)["slot"], 2)
        data, ring = unseal(blob, "Haslo-glowne-1")
        self.assertEqual(data, DATA)
        self.assertIsNotNone(ring.yubikey)
        calls = self.key.calls
        unseal(blob, "Haslo-glowne-1")                # np. nowa wersja z serwera – bez ponownego dotyku
        self.assertEqual(self.key.calls, calls)
        yubikey.clear_cache()                          # blokada sejfu
        self.key = FakeYubiKey()  # inny YubiKey
        with self.assertRaisesRegex(InvalidPasswordOrCorruptDataError, "YubiKey"):
            unseal(blob, "Haslo-glowne-1")

    def test_wrong_key_attempt_does_not_poison_session(self):
        # Najpierw ktoś podłącza inny YubiKey (odmowa), potem właściwy – musi otworzyć bez restartu programu
        blob, _ring, _code = self.protected()
        yubikey.clear_cache()
        right, self.key = self.key, FakeYubiKey()
        with self.assertRaises(InvalidPasswordOrCorruptDataError):
            unseal(blob, "Haslo-glowne-1")
        self.key = right
        self.assertEqual(unseal(blob, "Haslo-glowne-1")[0], DATA)
        with self.assertRaises(InvalidPasswordOrCorruptDataError):
            unseal(blob, "zle-haslo")  # złe hasło przy dobrym kluczu nadal odrzucane

    def test_password_alone_is_not_enough(self):
        blob, _ring, _code = self.protected()
        yubikey.clear_cache()
        with mock.patch.object(yubikey, "respond", side_effect=yubikey.YubiKeyError("brak klucza")):
            with self.assertRaisesRegex(YubiKeyRequiredError, "brak klucza"):
                unseal(blob, "Haslo-glowne-1")
        with self.assertRaises(InvalidPasswordOrCorruptDataError):
            unseal(blob, "zle-haslo")

    def test_saves_and_password_change_do_not_ask_again(self):
        blob, _ring, _code = self.protected()
        _data, ring = unseal(blob, "Haslo-glowne-1")
        calls = self.key.calls
        blob = seal(DATA, "Haslo-glowne-1", None, ring)   # zwykły zapis – bez dotykania klucza
        blob = seal(DATA, "Nowe-haslo-22", None, ring)    # zmiana hasła – odpowiedź z otwarcia
        self.assertEqual(self.key.calls, calls)
        self.assertIsNotNone(password_yubikey(blob))      # YubiKey nadal wymagany
        self.assertEqual(unseal(blob, "Nowe-haslo-22")[0], DATA)

    def test_keyfile_and_yubikey_together(self):
        blob, _ring, _code = self.protected(keyfile=b"plik-klucz")
        yubikey.clear_cache()
        self.assertEqual(unseal(blob, "Haslo-glowne-1", b"plik-klucz")[0], DATA)
        with self.assertRaises(InvalidPasswordOrCorruptDataError):
            unseal(blob, "Haslo-glowne-1")

    def test_lost_yubikey_recovery_code_removes_it(self):
        blob, _ring, code = self.protected()
        yubikey.clear_cache()
        self.key = FakeYubiKey()  # stary klucz zgubiony
        data, ring = unseal_with_recovery_code(blob, code)
        self.assertEqual(data, DATA)
        ring.set_password("Nowe-haslo-po-odzyskaniu")
        blob = ring.encrypt(DATA)
        self.assertIsNone(password_yubikey(blob))
        with mock.patch.object(yubikey, "respond", side_effect=AssertionError("nie powinien pytać o YubiKey")):
            self.assertEqual(unseal(blob, "Nowe-haslo-po-odzyskaniu")[0], DATA)

    def test_disable(self):
        blob, _ring, _code = self.protected()
        _data, ring = unseal(blob, "Haslo-glowne-1")
        ring.disable_yubikey("Haslo-glowne-1", None)
        blob = ring.encrypt(DATA)
        self.assertIsNone(password_yubikey(blob))
        with mock.patch.object(yubikey, "respond", side_effect=AssertionError("nie powinien pytać o YubiKey")):
            self.assertEqual(unseal(blob, "Haslo-glowne-1")[0], DATA)

    def test_tampered_header_rejected(self):
        ring = Keyring.new("x" * 12)
        ring.slots[0]["yubikey"] = {"challenge": "!!!", "slot": 2}
        with self.assertRaises(crypto.InvalidVaultHeaderError):
            unseal(ring.encrypt(DATA), "x" * 12)
        ring.slots[0]["yubikey"] = {"challenge": crypto._e(b"a" * 32), "slot": 7}
        with self.assertRaises(crypto.InvalidVaultHeaderError):
            password_yubikey(ring.encrypt(DATA))

    def test_removing_yubikey_from_header_does_not_help(self):
        # Ktoś przejmuje plik i usuwa pole "yubikey" – nagłówek jest w AAD, a klucz dostępu i tak wymaga odpowiedzi
        import json
        import struct
        blob, _ring, _code = self.protected()
        slots, aad, nonce, ciphertext = crypto._parse_v2(blob)
        for slot in slots:
            slot.pop("yubikey", None)
        header = json.dumps({"slots": slots}, separators=(",", ":")).encode()
        forged = crypto.MAGIC_HEADER + struct.pack(">BI", 2, len(header)) + header + nonce + ciphertext
        self.assertIsNone(password_yubikey(forged))
        with mock.patch.object(yubikey, "respond", side_effect=AssertionError("nie powinien pytać o YubiKey")):
            with self.assertRaises(InvalidPasswordOrCorruptDataError):
                unseal(forged, "Haslo-glowne-1")

    def test_v1_vaults_unaffected(self):
        blob = seal(DATA, "Haslo-glowne-1")
        self.assertIsNone(password_yubikey(blob))
        self.assertEqual(unseal(blob, "Haslo-glowne-1")[0], DATA)


class YubiKeyDeviceTests(unittest.TestCase):
    def test_library_available_and_no_key_message(self):
        self.assertTrue(yubikey.available())
        with mock.patch.object(yubikey, "_devices", return_value=[]):
            with self.assertRaisesRegex(yubikey.YubiKeyError, "Podłącz YubiKey"):
                yubikey.respond(b"x" * 32)
        with mock.patch.object(yubikey, "_devices", return_value=[object(), object()]):
            with self.assertRaisesRegex(yubikey.YubiKeyError, "kilka"):
                yubikey.respond(b"x" * 32)

    def test_device_protocol_with_fake_session(self):
        """Cała ścieżka respond() z udawaną sesją yubikit: slot, odpowiedź, powiadomienie o dotyku."""
        secret = os.urandom(20)

        class Session:
            def __init__(self, conn):
                pass

            def get_config_state(self):
                return mock.Mock(is_configured=lambda slot: int(slot) == 2)

            def calculate_hmac_sha1(self, slot, challenge, event=None, on_keepalive=None):
                on_keepalive(2)  # czeka na dotknięcie
                return hmac.new(secret, challenge, hashlib.sha1).digest()

        device = mock.MagicMock()
        touched = []
        with mock.patch.object(yubikey, "_devices", return_value=[device]), \
                mock.patch("yubikit.yubiotp.YubiOtpSession", Session), \
                mock.patch.object(yubikey, "on_touch_needed", lambda: touched.append(1)):
            self.assertEqual(yubikey.respond(b"c" * 32), hmac.new(secret, b"c" * 32, hashlib.sha1).digest())
            self.assertEqual(touched, [1])
            with self.assertRaisesRegex(yubikey.YubiKeyError, "Slot 1"):
                yubikey.respond(b"c" * 32, slot=1)


if __name__ == "__main__":
    unittest.main()
