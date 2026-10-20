"""
Hasło na telefon przez domowe Wi-Fi, bez aplikacji (wtyczka „Hasło na telefon”).

Komputer na chwilę (domyślnie 60 s) udostępnia w sieci lokalnej stronę http://<IP komputera>:<port>/h/<token>.
Kod QR zawiera ten adres i – po „#” – losowy klucz. Telefon pobiera stronę, a potem jeden raz zaszyfrowane hasło;
strona odszyfrowuje je u siebie (ChaCha20, napisany w JavaScript – na stronie http przeglądarka nie udostępnia
WebCrypto). Klucz nie przechodzi przez sieć (część po „#” zostaje w telefonie), więc inne urządzenia w sieci
widzą tylko szyfrogram. Po pierwszym pobraniu, po czasie albo po serii złych prób serwer się wyłącza.
"""

import base64
import json
import os
import secrets
import socket
import threading
from http.server import BaseHTTPRequestHandler
from typing import Callable, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

from core.i18n import _
from core.local_http import LocalThreadingHTTPServer

LIFETIME_SECONDS = 60
MAX_BAD_REQUESTS = 20
MAGIC = "KS1"


class HandoffError(Exception):
    pass


def lan_ip() -> str:
    """Adres tego komputera w sieci lokalnej (bez wysyłania czegokolwiek – UDP connect tylko wybiera trasę)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
    except OSError:
        ip = ""
    finally:
        s.close()
    if not ip or ip.startswith("127.") or ip == "0.0.0.0":
        raise HandoffError(_("Komputer nie jest połączony z siecią lokalną (Wi-Fi lub kablem)."))
    return ip


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """ChaCha20 (RFC 8439, licznik od 0) – ten sam algorytm, który liczy strona w telefonie."""
    return Cipher(algorithms.ChaCha20(key, b"\0\0\0\0" + nonce), None).encryptor().update(plaintext)


class HandoffServer:
    def __init__(self, title: str, secret: str, host: Optional[str] = None, lifetime: int = LIFETIME_SECONDS,
                 on_fetched: Optional[Callable[[], None]] = None, on_closed: Optional[Callable[[str], None]] = None):
        self.host = host or lan_ip()
        self.token = secrets.token_urlsafe(16)
        self.key, self.nonce = os.urandom(32), os.urandom(12)
        payload = json.dumps({"m": MAGIC, "t": title, "p": secret}, ensure_ascii=False).encode("utf-8")
        self._cipher = {"n": base64.b64encode(self.nonce).decode(), "c": base64.b64encode(encrypt(self.key, self.nonce, payload)).decode()}
        self.on_fetched, self.on_closed = on_fetched, on_closed
        self.lifetime = lifetime
        self.page = render_page()
        self.fetched = False
        self._bad = 0
        self._lock = threading.Lock()
        self._closed = False
        self._server = LocalThreadingHTTPServer((self.host, 0), self._handler())
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]
        self._timer = threading.Timer(lifetime, lambda: self.close("timeout"))
        self._timer.daemon = True

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/h/{self.token}#{_b64url(self.key)}"

    def start(self) -> "HandoffServer":
        threading.Thread(target=self._server.serve_forever, daemon=True, name="phone-handoff").start()
        self._timer.start()
        return self

    def close(self, reason: str = "closed") -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._cipher = None  # szyfrogram znika z pamięci
        self._timer.cancel()
        threading.Thread(target=self._server.shutdown, daemon=True).start()
        if self.on_closed:
            self.on_closed(reason)

    def _take_cipher(self):
        with self._lock:
            if self._closed or self.fetched or self._cipher is None:
                return None
            self.fetched = True
            data, self._cipher = self._cipher, None
            return data

    def _bad_request(self) -> None:
        with self._lock:
            self._bad += 1
            too_many = self._bad >= MAX_BAD_REQUESTS
        if too_many:
            self.close("attack")

    def _handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # bez zapisywania adresów i tokenów w konsoli
                pass

            def _send(self, status: int, body: bytes, ctype: str):
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Security-Policy",
                                 "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                                 "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                base = f"/h/{server.token}"
                if self.path == base:
                    self._send(200, server.page.encode("utf-8"), "text/html; charset=utf-8")
                elif self.path == base + "/data":
                    data = server._take_cipher()
                    if data is None:
                        self._send(410, b"{}", "application/json")
                        return
                    self._send(200, json.dumps(data).encode(), "application/json")
                    if server.on_fetched:
                        server.on_fetched()
                    threading.Timer(2.0, lambda: server.close("fetched")).start()
                else:
                    server._bad_request()
                    self._send(404, b"Not Found", "text/plain")

        return Handler


def render_page() -> str:
    from core.i18n import current_language
    texts = {"incomplete": _("Niepełny link – zeskanuj kod QR jeszcze raz."),
             "gone": _("Hasło zostało już odebrane albo minął czas. Wygeneruj nowy kod w KeyStead."),
             "copy": _("Kopiuj hasło"), "copied": _("Skopiowano ✓"),
             "note": _("Hasło nie jest nigdzie zapisane. Zamknij tę kartę po użyciu.")}
    # </ w tekście nie może zamknąć skryptu
    return PAGE.replace("__LANG__", current_language()).replace(
        "__TEXTS__", json.dumps(texts, ensure_ascii=False).replace("</", "<\\/"))


PAGE = """<!doctype html><html lang="__LANG__"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">
<title>KeyStead</title><style>
body{margin:0;font:17px/1.5 system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;min-height:100vh;
align-items:center;justify-content:center;padding:16px;box-sizing:border-box}
main{width:100%;max-width:460px;background:#1e293b;border-radius:14px;padding:22px}
h1{font-size:20px;margin:0 0 12px} .p{font:24px/1.4 Consolas,monospace;background:#0f172a;padding:14px;border-radius:10px;
word-break:break-all;user-select:all;margin:10px 0} button{width:100%;padding:12px;border:0;border-radius:10px;
background:#4f46e5;color:#fff;font-size:17px} .m{color:#94a3b8;font-size:14px} .e{color:#f43f5e}
</style></head><body><main><h1>🔐 KeyStead</h1><div id="out" class="m">…</div></main><script>
(function(){
var T=__TEXTS__,out=document.getElementById("out");
function b64(s){s=s.replace(/-/g,"+").replace(/_/g,"/");while(s.length%4)s+="=";var b=atob(s),a=new Uint8Array(b.length);
for(var i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a}
function r(v,c){return (v<<c)|(v>>>(32-c))}
function block(k,n,ctr){var s=[0x61707865,0x3320646e,0x79622d32,0x6b206574],i;var dv=new DataView(k.buffer,k.byteOffset,32);
for(i=0;i<8;i++)s.push(dv.getUint32(i*4,true));s.push(ctr>>>0);var nv=new DataView(n.buffer,n.byteOffset,12);
for(i=0;i<3;i++)s.push(nv.getUint32(i*4,true));var x=s.slice();
function q(a,b,c,d){x[a]=(x[a]+x[b])|0;x[d]=r(x[d]^x[a],16);x[c]=(x[c]+x[d])|0;x[b]=r(x[b]^x[c],12);
x[a]=(x[a]+x[b])|0;x[d]=r(x[d]^x[a],8);x[c]=(x[c]+x[d])|0;x[b]=r(x[b]^x[c],7)}
for(i=0;i<10;i++){q(0,4,8,12);q(1,5,9,13);q(2,6,10,14);q(3,7,11,15);q(0,5,10,15);q(1,6,11,12);q(2,7,8,13);q(3,4,9,14)}
var o=new Uint8Array(64),ov=new DataView(o.buffer);for(i=0;i<16;i++)ov.setUint32(i*4,(x[i]+s[i])|0,true);return o}
function chacha(k,n,d){var o=new Uint8Array(d.length);for(var p=0,c=0;p<d.length;p+=64,c++){var ks=block(k,n,c);
for(var j=0;j<64&&p+j<d.length;j++)o[p+j]=d[p+j]^ks[j]}return o}
function fail(t){out.className="e";out.textContent=t}
var key;try{key=b64(location.hash.slice(1))}catch(e){}
history.replaceState(null,"",location.pathname);
if(!key||key.length!==32){fail(T.incomplete);return}
fetch(location.pathname+"/data",{cache:"no-store"}).then(function(r){if(!r.ok)throw r.status;return r.json()}).then(function(d){
var plain=chacha(key,b64(d.n),b64(d.c)),data=JSON.parse(new TextDecoder().decode(plain));if(data.m!=="KS1")throw 0;
out.className="";out.innerHTML="";var h=document.createElement("div");h.className="m";h.textContent=data.t;
var p=document.createElement("div");p.className="p";p.textContent=data.p;var b=document.createElement("button");
b.textContent=T.copy;b.onclick=function(){var ok=false;try{navigator.clipboard.writeText(data.p);ok=true}catch(e){}
if(!ok){var s=window.getSelection(),g=document.createRange();g.selectNodeContents(p);s.removeAllRanges();s.addRange(g);
try{document.execCommand("copy")}catch(e){}}b.textContent=T.copied};
var n=document.createElement("p");n.className="m";n.textContent=T.note;
out.append(h,p,b,n)}).catch(function(){fail(T.gone)});
})();
</script></body></html>"""
