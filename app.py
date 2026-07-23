from flask import Flask, request, jsonify
from datetime import datetime

app = Flask(__name__)

CLIENTES = {
    "14502950-8AGBY69W0PR146205": {"nombre": "CHARLY", "vence": "20991231", "activo": True},
}

@app.route('/', methods=['GET'])
def health():
    return "BringGo Server OK"

@app.route('/', methods=['POST'])
def login():
    try:
        data = request.get_json(force=True)
        service = data.get('service', '')
        user_id = data.get('id', '')
        dni = data.get('dni', '')
        vin = data.get('vin', '')
    except:
        service = ''
        user_id = ''
        dni = ''
        vin = ''

    hoy = datetime.now().strftime("%Y%m%d")

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
    else:
        result = "ok"
        msg = "success"
        expdate = "20991231"
        print(f"Login sin validacion: {user_id}")

    return jsonify({
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

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 9090))
