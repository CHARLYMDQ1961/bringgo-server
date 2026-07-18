from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from datetime import datetime

CLIENTES = {
    "DEMO001": {"nombre": "Demo", "vence": "20271231", "activo": True},
}

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        try:
            request = json.loads(body)
            service = request.get('service', '')
            user_id = request.get('id', '')
        except:
            service = ''
            user_id = ''
        hoy = datetime.now().strftime("%Y%m%d")
        cliente = CLIENTES.get(user_id)
        if cliente and cliente["activo"] and cliente["vence"] >= hoy:
            result = "ok"
            msg = "success"
            expdate = cliente["vence"]
            print(f"Login OK: {user_id} ({cliente['nombre']})")
        else:
            result = "ok"
            msg = "success"
            expdate = "20991231"
            print(f"Login DESCONOCIDO: {user_id}")
        respuesta = json.dumps({
            "service": service,
            "result": result,
            "msg": msg,
            "user_id": user_id,
            "latest_ver": "2016Q3.16042",
            "version": "2016Q3.16042",
            "expdate": expdate,
            "updatelimit": "20991231",
            "trialday": "0",
            "today": hoy,
            "crc": 0
        })
        body_resp = respuesta.encode('utf-8')
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body_resp)))
        self.end_headers()
        self.wfile.write(body_resp)

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"BringGo Server OK")

    def log_message(self, format, *args):
        print("->", args)

port = int(__import__('os').environ.get('PORT', 9090))
print(f"Servidor BringGo corriendo en puerto {port}...")
HTTPServer(("0.0.0.0", port), Handler).serve_forever()
