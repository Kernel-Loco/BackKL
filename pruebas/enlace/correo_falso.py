"""Resend simulado para pruebas/test_enlace.py (#28, RC-63). Solo biblioteca estándar.

POST /emails guarda el JSON recibido (con la cabecera Authorization) y responde 200 como Resend, o el código que se
pida con POST /respuesta {"codigo": 429}. GET /correos devuelve lo guardado y DELETE /correos lo borra. Vive en la red
aislada del compose de pruebas/enlace: nadie de afuera lo alcanza y la API no sale a internet.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_correos, _codigo, _candado = [], [200], threading.Lock()


class Manejador(BaseHTTPRequestHandler):
    def _json(self, codigo, datos):
        cuerpo = json.dumps(datos).encode()
        self.send_response(codigo)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(cuerpo)))
        self.end_headers()
        self.wfile.write(cuerpo)

    def _cuerpo(self):
        return json.loads(self.rfile.read(int(self.headers.get('Content-Length') or 0)) or b'{}')

    def do_POST(self):
        if self.path == '/emails':
            datos = self._cuerpo()
            with _candado:
                _correos.append({'authorization': self.headers.get('Authorization'), 'correo': datos})
                codigo = _codigo[0]
            return self._json(codigo, {'id': 'prueba-%d' % len(_correos)} if codigo == 200 else {'message': 'x'})
        if self.path == '/respuesta':
            with _candado:
                _codigo[0] = int(self._cuerpo()['codigo'])
            return self._json(200, {})
        self._json(404, {})

    def do_GET(self):
        if self.path == '/correos':
            with _candado:
                return self._json(200, list(_correos))
        self._json(404, {})

    def do_DELETE(self):
        if self.path == '/correos':
            with _candado:
                _correos.clear()
                _codigo[0] = 200
            return self._json(200, {})
        self._json(404, {})

    def log_message(self, *args):
        pass  # sin el cuerpo en el log: lleva el enlace


if __name__ == '__main__':
    ThreadingHTTPServer(('0.0.0.0', 8025), Manejador).serve_forever()
