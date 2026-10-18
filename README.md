# 🛡️ KeyStead Manager

**A zero-knowledge password manager for Windows, built for IT departments and small businesses.**

Your passwords are encrypted on your own computer and never leave it in readable form. Use KeyStead on its own,
with a local encrypted vault, or connect it to your company's self-hosted
**[KeyStead Server](https://github.com/facior/KeyStead-Manager)** to sync across devices and let IT manage
accounts, policies and recovery.

> **Languages:** KeyStead is available in **English** and **Polish**. It starts in your Windows language. You can switch
> at any time on the login screen (top right) or in **Settings → 🌐 Language**.

---

## ⬇️ Download and install

**Requirements:** Windows 10 or 11 (64-bit).

Get the latest version from **[Releases → Latest](https://github.com/facior/KeyStead/releases/latest)**:

| File | What it is |
|---|---|
| `KeyStead-Manager-Setup-X.Y.Z.exe` | Installer. No administrator rights needed; adds a Start menu shortcut. |
| `KeyStead-Manager-X.Y.Z-portable.zip` | Portable version. Unzip and run, no installation. |

If your company uses KeyStead Server, IT will give you a download link
(`https://<your-server>/download`) and an **activation code**.

**Windows SmartScreen** may warn about an unknown publisher on first launch. Click **More info → Run anyway**.

**Automatic updates:** the app checks for new versions and installs them when you click. Only releases
signed with the publisher's key are accepted (Ed25519 signature over `SHA256SUMS`), so a tampered download is rejected.

---

## 🚀 Getting started

### On your own (local vault)

1. Start KeyStead Manager. A short first-run guide opens.
2. Create your vault and choose a **master password**. This is the only password you need to remember. It cannot be
   recovered by anyone, so make it long and memorable (a phrase of several words works well).
3. Optional: add a **keyfile** (for example, a file on a USB stick) as a second factor.
4. Recommended: create a **personal recovery code** in **Settings → 🔑 Account recovery**. Print it or store it
   somewhere safe. It lets you regain access if you forget your master password.

### With your company's KeyStead Server

1. On the login screen, open the **🌐 Server** tab.
2. Enter the server address from IT, or click **🔍 Tailscale** to find it automatically if your company uses Tailscale.
3. Enter the **activation code** from IT (one-time, valid for 24 hours by default).
4. Enter your master password.

On first connection you can upload an existing vault or create a new one. On each additional computer, ask IT for
a new activation code and use the same master password. Corporate proxies are detected automatically from Windows
settings.

---

## ✨ Features

### Everyday use
- **Entries** for logins, secure notes, payment cards and identities, with categories, tags, favourites and site icons.
- **Instant search** by title, username, address, notes and tags.
- **Safe copying:** copied passwords are cleared from the clipboard automatically (after 30 seconds by default).
- **Built-in authenticator (2FA / TOTP):** live codes with a countdown. Paste an `otpauth://` link from a QR code.
- **Password generator:** random passwords (8–64 characters, optionally without look-alike characters such as
  `0 O 1 l I`) and easy-to-remember word phrases, with a strength meter.
- **Password history:** every change keeps the previous password with its date.
- **Attachments:** store scans, licence files or keys inside an entry. They are encrypted like the rest of the vault.
- **Trash:** deleted entries can be restored.

### Quick access from any program
| Shortcut | What it does |
|---|---|
| **Ctrl+Shift+Space** | Quick search window. **Enter** copies the password, **Shift+Enter** the username, **Ctrl+Enter** the 2FA code. |
| **Ctrl+Shift+L** | **Autotype:** types your username and password into the login form you are looking at. |

Shortcuts can be changed or turned off in the settings.

**Autotype in web browsers checks the real web address.** In Chrome, Edge, Firefox, Opera and other browsers based on
them, KeyStead reads the address bar, not just the window title. A fake page that copies your bank's title but has
a different address gets **nothing typed**. KeyStead shows a warning instead: *"⚠️ This may be a fake website"*.
The address is checked once more right before typing.

- If a service uses more than one login address (for example, Microsoft 365), list the extra addresses in the
  entry's custom field **Autotype addresses**, separated by commas. Or confirm the warning once with
  *"This is my site – type it"*, and KeyStead remembers the address.
- To change what gets typed, add a custom field **Autotype sequence**, for example
  `{USERNAME}{TAB}{PASSWORD}{TAB}{TOTP}{ENTER}`.
- The Polish field names *Autotype adresy* and *Sekwencja autotype* work too, so entries behave the same in both
  languages.
- In desktop programs (not browsers), Autotype matches the window title to the entry name or website.

### Locking and unlocking
- **Auto-lock** after inactivity (5 minutes by default) and when you lock Windows (**Win+L**).
- **Windows Hello:** unlock with your PIN, fingerprint or face. You still type the master password every 14 days.

### Security monitoring
- **Breach watch (Have I Been Pwned):** once a day KeyStead can check whether your passwords appear in known data
  breaches. It asks for your consent first. Your passwords never leave your computer: only the first 5 characters of
  a SHA-1 hash are sent (k-anonymity).
- **Security audit (Watchtower):** finds breached, reused, weak and old passwords (older than 180 days) and accounts
  without 2FA, with a one-click fix to generate a new password.
- **PDF report** of your vault's security status.

### Import from other password managers
| Source | Formats |
|---|---|
| Bitwarden | unencrypted JSON export, CSV |
| KeePass | `.kdbx` database (with its password and optional keyfile), XML, CSV |
| 1Password | `.1pux`, CSV |
| LastPass | CSV |
| Browsers | CSV export from Chrome, Edge, Brave, Firefox |

When duplicates are found, you choose whether to skip them, add them as new entries or update the existing ones.
**Import → 🧹 Tidy up entries** cleans up imported titles afterwards.

### Backups
All backups are encrypted with your vault key (AES-256-GCM) and include a SHA-256 checksum.
- **Local disk, USB stick or network drive**, with timestamped copies and automatic rotation.
- **WebDAV** (Nextcloud, ownCloud, Synology, QNAP) over HTTPS.
- **Google Drive, OneDrive, Dropbox:** sign in through the provider's own page (OAuth 2.0 with PKCE), so KeyStead
  never sees your cloud password. Each provider needs a one-time *Client ID*; the app shows how to get one.
- **Automatic backup** after every change, in the background.

Your company may disable private backups through a server policy.

### 🧩 Plugins
Extra features you turn on one by one in **Settings → Plugins**. They are built
into KeyStead: nothing is downloaded and no third-party code ever sees your vault. All are off by default, and your
company can block any of them through a server policy.

| Plugin | What it does |
|---|---|
| **Connect** | A button on entries with an `rdp://`, `ssh://`, `winbox://`, `anydesk://` or `teamviewer://` address opens the session and signs you in. Remote Desktop credentials sit in Windows Credential Manager for 30 seconds only; for SSH the password goes to the auto-clearing clipboard. |
| **Password expiry** | A *valid until* date per entry, reminders after unlocking and a **To change** list. |
| **2FA QR from image** | Paste a screenshot (Win+Shift+S) or pick an image instead of retyping a 2FA key. |
| **Password as QR code** | Shows the password, or a Wi-Fi join code, as a QR code for a phone. Closes after a minute and is hidden from screen capture. |
| **Entry templates** | Windows/Linux server, MikroTik, network device, Wi-Fi, licence, e-mail, database, VPN, plus your own templates. |
| **Coloured password** | Digits and symbols in different colours when the password is revealed. |
| **Floating panel** | A small always-on-top window with favourites and search for one-click copying. |
| **Selected characters** | Shows and copies only the characters a bank asks for (e.g. the 3rd, 5th and 8th). |
| **SSH keys in the vault** | KeyStead acts as Pageant and as the Windows OpenSSH agent, so PuTTY, WinSCP, `ssh`, `scp` and git use keys stored in entries (OpenSSH, PEM or PuTTY `.ppk`, or a newly generated Ed25519 key). Keys stop working when the vault locks; optional confirmation before each use. |
| **Secure password link** | A one-time link for someone outside KeyStead. The app encrypts the content and the key travels only in the part of the link after `#`, so the company server can't read it. Opening the page doesn't use up the link; clicking **Show** does. Optional extra password, max. 5 attempts. Needs a KeyStead Server. |
| **YubiKey** | The master password plus a touch of your YubiKey (HMAC-SHA1 challenge-response, slot 2) is needed to open the vault, also with Windows Hello. A recovery code is required first; it stays the way back if the key is lost. |

Coming later: passkeys (needs Windows 11).

---

## 🔒 Security model

- **Zero-knowledge:** encryption and decryption happen only on your computer. A KeyStead Server stores encrypted
  vaults only.
- **Key derivation:** Argon2id (RFC 9106): 64 MB of memory, 3 iterations, 4 threads, 256-bit salt.
- **Encryption:** AES-256-GCM with a random 96-bit nonce and a 128-bit authentication tag, which detects any
  tampering with the file.
- **Protection against old-version replay:** each save carries a revision number inside the encrypted data, so
  a server cannot silently hand back an older copy of your vault.
- **Signed updates:** the app installs only releases signed by the publisher, and re-checks the installer right
  before running it.
- **Device credentials** for the server are protected with Windows DPAPI.

---

## 🔢 Versions

The first two numbers are shared by the app and the server; the last one is for fixes in one part only.
App **2.1.x** works with server **2.1.x** and newer.

## Author and licence

- **Author:** Łukasz Kubieniec – [github.com/facior](https://github.com/facior)
- **Licence:** © 2026 Łukasz Kubieniec. All rights reserved. This is proprietary software. Publishing the source code
  does not grant a licence; see [LICENSE](LICENSE).
