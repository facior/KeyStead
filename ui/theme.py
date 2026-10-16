"""
Definicje motywu, kolorystyki i nowoczesnych stałych stylistycznych (Modern Design System).
Inspirowane nowoczesnymi interfejsami aplikacji takich jak 1Password, Raycast i Linear.
"""

import customtkinter as ctk

# Ustawienia bazowe CustomTkinter
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Nowoczesna, głęboka paleta kolorów (Slate / Obsidian / Indigo)
COLOR_BG_DARK = "#090d16"         # Główne tło okna (bardzo głęboki granat/grafit)
COLOR_PANEL_DARK = "#111827"      # Panele, paski boczne, paski nawigacji (Gray 900)
COLOR_CARD_DARK = "#1a2234"       # Karty wpisów, tła formularzy
COLOR_CARD_HOVER = "#243047"      # Aktywny element / podświetlenie karty
COLOR_BORDER = "#2e3b52"          # Subtelne obramowania kart i separatorów

# Akcenty wiodące
COLOR_PRIMARY = "#4f46e5"         # Nowoczesny Indigo (Indigo 600)
COLOR_PRIMARY_HOVER = "#4338ca"   # Indigo 700
COLOR_PRIMARY_LIGHT = "#818cf8"   # Indigo 400

COLOR_SECONDARY = "#242e42"       # Stonowane tło przycisków pomocniczych
COLOR_SECONDARY_HOVER = "#323f59"

# Statusy i bezpieczeństwo
COLOR_SUCCESS = "#10b981"         # Szmaragdowa zieleń (Emerald 500)
COLOR_SUCCESS_HOVER = "#059669"
COLOR_DANGER = "#f43f5e"          # Nowoczesna czerwień (Rose 500)
COLOR_DANGER_HOVER = "#e11d48"
COLOR_WARNING = "#f59e0b"         # Bursztyn (Amber 500)
COLOR_PURPLE = "#8b5cf6"          # Fiolet audytu bezpieczeństwa (Purple 500)
COLOR_PURPLE_HOVER = "#7c3aed"

# Typografia i kolory tekstu
COLOR_TEXT_PRIMARY = "#f8fafc"    # Jasny, czytelny biały (Slate 50)
COLOR_TEXT_MUTED = "#94a3b8"      # Stonowany tekst pomocniczy (Slate 400)
COLOR_TEXT_ACCENT = "#38bdf8"     # Jasny błękit wyróżnień (Sky 400)

FONT_FAMILY = "Segoe UI"
FONT_TITLE_HERO = (FONT_FAMILY, 24, "bold")
FONT_TITLE = (FONT_FAMILY, 19, "bold")
FONT_SUBTITLE = (FONT_FAMILY, 14, "bold")
FONT_BODY = (FONT_FAMILY, 13)
FONT_BODY_BOLD = (FONT_FAMILY, 13, "bold")
FONT_CODE = ("Consolas", 13)
FONT_SMALL = (FONT_FAMILY, 11)
FONT_TOTP = ("Consolas", 23, "bold")
