"""
Mini-serwery HTTP aplikacji (logowanie do chmury, hasło na telefon) bez pytania DNS o nazwę komputera.

HTTPServer z biblioteki standardowej przy starcie woła socket.getfqdn() – na macOS potrafi to trwać kilka sekund,
a w tym czasie serwer jeszcze nie przyjmuje połączeń. Nazwa nie jest nam do niczego potrzebna.
"""

import socketserver
from http.server import HTTPServer, ThreadingHTTPServer


class _NoNameLookup:
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name, self.server_port = host, port


class LocalHTTPServer(_NoNameLookup, HTTPServer):
    pass


class LocalThreadingHTTPServer(_NoNameLookup, ThreadingHTTPServer):
    pass
