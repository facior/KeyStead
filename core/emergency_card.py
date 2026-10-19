"""
Karta awaryjna (PDF do wydruku): wszystko, czego Ty lub bliscy potrzebujecie, żeby dostać się do sejfu,
gdy zapomnisz hasła, zepsuje się komputer albo Ciebie zabraknie.

Strona A4 rysowana biblioteką Pillow i zapisywana jako PDF (bez dodatkowych bibliotek). Hasło główne NIGDY
nie jest drukowane automatycznie – karta ma tylko miejsce, by wpisać je ręcznie, jeśli użytkownik tak zdecyduje.
"""

import os
from dataclasses import dataclass
from datetime import date
from typing import List

from core.i18n import _

DPI = 150
PAGE = (1240, 1754)          # A4 przy 150 dpi
MARGIN = 90
INK, MUTED, ACCENT, LINE, WARN = "#111827", "#4b5563", "#4338ca", "#9ca3af", "#b91c1c"

FONT_FILES = [(r"C:\Windows\Fonts\segoeui.ttf", r"C:\Windows\Fonts\segoeuib.ttf"),
              (r"C:\Windows\Fonts\arial.ttf", r"C:\Windows\Fonts\arialbd.ttf"),
              ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")]


@dataclass
class CardInfo:
    vault_name: str
    mode: str                       # "file" | "server"
    location: str                   # ścieżka pliku sejfu albo adres serwera
    account: str = ""               # login na serwerze
    keyfile: bool = False
    yubikey: bool = False
    recovery_code: str = ""         # świeżo utworzony kod (jeśli użytkownik chciał go na karcie)
    has_recovery: bool = False      # sejf ma kod odzyskiwania (ale nie jest drukowany)
    org_recovery: bool = False      # firma może przywrócić dostęp
    download_url: str = ""
    password_box: bool = True       # miejsce na ręczne wpisanie hasła głównego


def _fonts():
    from PIL import ImageFont
    for regular, bold in FONT_FILES:
        if os.path.isfile(regular) and os.path.isfile(bold):
            return lambda size, b=False: ImageFont.truetype(bold if b else regular, size)
    return lambda size, b=False: ImageFont.load_default(size)


def _wrap(draw, text: str, font, width: int) -> List[str]:
    lines = []
    for paragraph in text.split("\n"):
        words, line = paragraph.split(" "), ""
        for word in words:
            candidate = f"{line} {word}".strip()
            if draw.textlength(candidate, font=font) <= width or not line:
                line = candidate
            else:
                lines.append(line)
                line = word
        lines.append(line)
    return lines


def render(info: CardInfo):
    """Obraz strony (PIL) – osobno od zapisu, żeby dało się go sprawdzić testami."""
    from PIL import Image, ImageDraw
    from core import qr
    font = _fonts()
    img = Image.new("RGB", PAGE, "white")
    d = ImageDraw.Draw(img)
    x, y, width = MARGIN, MARGIN, PAGE[0] - 2 * MARGIN

    def text(t, size=24, bold=False, color=INK, gap=8, indent=0):
        nonlocal y
        f = font(size, bold)
        for line in _wrap(d, t, f, width - indent):
            d.text((x + indent, y), line, font=f, fill=color)
            y += int(size * 1.35)
        y += gap

    def section(title):
        nonlocal y
        y += 14
        d.line((x, y, x + width, y), fill=LINE, width=2)
        y += 16
        text(title, 30, True, ACCENT, gap=6)

    # Nagłówek
    text(_("KeyStead – karta awaryjna"), 46, True, gap=4)
    text(_("Sejf: {name}   ·   Utworzono: {date}", name=info.vault_name, date=date.today().strftime("%d.%m.%Y")),
         22, color=MUTED, gap=6)
    text(_("Przechowuj tę kartę w bezpiecznym miejscu (sejf domowy, u zaufanej osoby lub notariusza). Kto ma tę kartę "
           "i hasło główne, ma dostęp do wszystkich Twoich haseł."), 22, color=WARN)

    section(_("Gdzie jest sejf"))
    if info.mode == "server":
        text(_("Serwer KeyStead: {url}", url=info.location), 26, True)
        if info.account:
            text(_("Login: {account}", account=info.account), 24)
        text(_("Na nowym komputerze potrzebny jest kod aktywacyjny od administratora serwera."), 22, color=MUTED)
    else:
        text(_("Plik sejfu: {path}", path=info.location), 24, True)
        text(_("Kopie zapasowe sejfu (jeśli są włączone) są w chmurze lub na dysku wskazanym w Ustawieniach "
               "→ Kopie i chmura."), 22, color=MUTED)

    section(_("Co jest potrzebne do otwarcia"))
    needs = [_("• hasło główne")]
    if info.keyfile:
        needs.append(_("• plik-klucz (ten sam plik, który wskazujesz przy logowaniu – zrób jego kopię!)"))
    if info.yubikey:
        needs.append(_("• klucz YubiKey (dotknięcie przy otwieraniu)"))
    for line in needs:
        text(line, 24, gap=2)
    y += 6

    if info.password_box:
        text(_("Hasło główne – wpisz ręcznie, tylko jeśli chcesz (np. dla bliskich w kopercie):"), 22, color=MUTED, gap=6)
        d.rectangle((x, y, x + width, y + 70), outline=LINE, width=2)
        y += 90

    section(_("Gdy zapomnisz hasła głównego"))
    if info.recovery_code:
        text(_("Kod odzyskiwania (pozwala ustawić nowe hasło główne):"), 24, gap=4)
        text(info.recovery_code, 40, True, ACCENT, gap=4)
        text(_("Na ekranie logowania kliknij „Nie pamiętam hasła” i wpisz ten kod."), 22, color=MUTED)
        if info.yubikey:
            text(_("Kod odzyskiwania otwiera sejf także bez klucza YubiKey."), 22, color=MUTED)
    elif info.has_recovery:
        text(_("Sejf ma kod odzyskiwania – przechowujesz go osobno (nie jest wydrukowany na tej karcie)."), 24)
    else:
        text(_("Sejf NIE ma kodu odzyskiwania – zapomniane hasło oznacza utratę dostępu. Utwórz kod: Ustawienia → "
               "Odzyskiwanie dostępu."), 24, color=WARN)
    if info.org_recovery:
        text(_("Dostęp może też przywrócić administrator serwera firmy."), 22, color=MUTED)

    section(_("Jak otworzyć sejf na nowym komputerze"))
    steps = [_("1. Pobierz i zainstaluj KeyStead Manager (kod QR obok)."),
             _("2. Uruchom program i wybierz zakładkę „Serwer” – podaj adres i kod aktywacyjny.")
             if info.mode == "server" else _("2. Wybierz zakładkę „Odblokuj sejf” i wskaż plik sejfu (albo jego kopię)."),
             _("3. Wpisz hasło główne – albo kliknij „Nie pamiętam hasła” i użyj kodu odzyskiwania.")]
    top = y
    qr_size = 260
    for line in steps:
        f = font(24)
        for wrapped in _wrap(d, line, f, width - qr_size - 40):
            d.text((x, y), wrapped, font=f, fill=INK)
            y += 33
        y += 6
    if info.download_url:
        code = qr.make_image(info.download_url, scale=6).resize((qr_size, qr_size))
        img.paste(code.convert("RGB"), (x + width - qr_size, top))
        f = font(16)
        url_width = d.textlength(info.download_url, font=f)
        d.text((x + width - url_width, top + qr_size + 6), info.download_url, font=f, fill=MUTED)
        y = max(y, top + qr_size + 70)

    d.text((x, PAGE[1] - MARGIN), _("KeyStead Manager – karta awaryjna. Nie wysyłaj jej zdjęcia ani skanu przez "
                                    "internet."), font=font(18), fill=MUTED)
    return img


def save_pdf(info: CardInfo, path: str) -> str:
    img = render(info)
    img.save(path, "PDF", resolution=DPI)
    return path

