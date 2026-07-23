from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from datetime import datetime

# Base de datos de clientes autorizados
# Formato: "DNI-VIN": {"nombre": "Cliente", "vence": "20271231", "activo": True}
CLIENTES = {
    "14502950-8AGBY69W0PR146205": {"nombre": "CHARLY", "vence": "20991231", "activo": True},
}

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        try:
            request = json.loads(body)
            service = request.get('service', '')
            user_id = request.get('id', '')
            dni = request.get('dni', '')
            vin = request.get('vin', '')
        except:
            service = ''
            user_id = ''
            dni = ''
            vin = ''

        hoy = datetime.now().strftime("%Y%m%d")

        # Si viene DNI y VIN, validar por esa combinación
        if dni and vin:
            clave = f"{dni}-{vin}"
            cliente = CLIENTES.get(clave)
            if cliente and cliente["activo"] and cliente["vence"] >= hoy:
                result = "ok"
                msg = "success"
                expdate = cliente["vence"]
                print(f"Login OK: {clave} ({cliente['nombre']})")
            else:
                result = "fail"
                msg = "unauthorized"
                expdate = "00000000"
                print(f"Login RECHAZADO: {clave}")
