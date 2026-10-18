"""
Kody QR: pokazanie hasła jako QR (wtyczka „Hasło jako kod QR”) i odczyt kodu 2FA z obrazka
(wtyczka „Kod QR 2FA z obrazka”). Biblioteka zxing-cpp działa lokalnie – obraz nie opuszcza komputera.
"""

from typing import List, Optional

from core.i18n import _
from core.vault import VaultEntry

SSID_FIELD = "SSID"  # i18n: data – pole wpisu Wi-Fi (szablon „Sieć Wi-Fi”)
SECURITY_FIELD = "Zabezpieczenia"  # i18n: data – WPA/WPA2/WPA3, WEP albo brak

try:
    import zxingcpp
except ImportError:  # pragma: no cover – brak biblioteki w środowisku deweloperskim
    zxingcpp = None


def available() -> bool:
    return zxingcpp is not None


def make_image(text: str, scale: int = 8):
    """Obraz PIL z kodem QR (czarne moduły na białym tle, z marginesem)."""
    if zxingcpp is None:
        raise RuntimeError(_("Brak biblioteki do kodów QR (zxing-cpp)."))
    from PIL import Image, ImageOps
    barcode = zxingcpp.create_barcode(text, zxingcpp.BarcodeFormat.QRCode)
    # Obraz z biblioteki musi istnieć, dopóki czytamy jego bufor (inaczej odczyt zwolnionej pamięci)
    bitmap = barcode.to_image(scale=scale)
    with memoryview(bitmap) as pixels:  # 8-bitowa skala szarości, (wysokość, szerokość)
        img = Image.frombytes("L", (pixels.shape[1], pixels.shape[0]), pixels.tobytes())
    del bitmap
    return ImageOps.expand(img.convert("L"), border=scale * 2, fill=255)


def read_codes(image) -> List[str]:
    """Teksty wszystkich kodów QR znalezionych na obrazku (PIL)."""
    if zxingcpp is None:
        raise RuntimeError(_("Brak biblioteki do kodów QR (zxing-cpp)."))
    if image.mode not in ("L", "RGB"):
        image = image.convert("RGB")
    return [r.text for r in zxingcpp.read_barcodes(image) if r.text]


def find_otpauth(texts: List[str]) -> Optional[str]:
    for text in texts:
        if text.lower().startswith("otpauth://"):
            return text
    return None


def _wifi_escape(value: str) -> str:
    return "".join("\\" + c if c in '\\;,:"' else c for c in value)


def wifi_payload(entry: VaultEntry) -> Optional[str]:
    """Kod „połącz z Wi-Fi” (format WIFI:…) dla wpisów z polem SSID; telefon łączy się po zeskanowaniu."""
    ssid = entry.custom_fields.get(SSID_FIELD, "").strip()
    if not ssid:
        return None
    security = entry.custom_fields.get(SECURITY_FIELD, "").upper()
    kind = "nopass" if not entry.password else "WEP" if "WEP" in security else "WPA"
    payload = f"WIFI:T:{kind};S:{_wifi_escape(ssid)};"
    if entry.password:
        payload += f"P:{_wifi_escape(entry.password)};"
    return payload + ";"
