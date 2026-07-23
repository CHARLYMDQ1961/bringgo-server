from flask import Flask, request, jsonify
from datetime import datetime
import os
import psycopg2

app = Flask(__name__)

DATABASE_URL = os.environ.get('DATABASE_URL', '')

CLIENTES = {
    "14502950-8AGBY69W0PR146205": {"nombre": "CHARLY", "vence": "20991231", "activo": True},
}

def get_db():
    return psycopg2.connect(DATABASE_URL)

def init_db():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS activaciones (
                clave VARCHAR(100) PRIMARY KEY,
                fecha_activacion VARCHAR(20),
                activo BOOLEAN DEFAULT TRUE
            )
        ''')
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print("Error init_db: " + str(e))

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
        clave = dni + "-" + vin
        cliente = CLIENTES.get(clave)

        if not cliente or not cliente["activo"] or cliente["vence"] < hoy:
            result = "fail"
            msg = "unauthorized"
            expdate = "00000000"
            print("Login RECHAZADO no autorizado: " + clave)
        else:
            try:
                conn = get_db()
                cur = conn.cursor()
                cur.execute("SELECT clave, activo FROM activaciones WHERE clave = %s", (clave,))
                row = cur.fetchone()

                if row is None:
                    cur.execute("INSERT INTO activaciones (clave, fecha_activacion, activo) VALUES (%s, %s, %s)",
                                (clave, hoy, True))
                    conn.commit()
                    result = "ok"
                    msg = "success"
                    expdate = cliente["vence"]
                    print("Login OK - PRIMERA ACTIVACION: " + clave)
                elif row[1]:
                    result = "ok"
                    msg = "success"
                    expdate = cliente["vence"]
                    print("Login OK - YA ACTIVADO: " + clave)
                else:
                    result = "fail"
                    msg = "already_used"
                    expdate = "00000000"
                    print("Login RECHAZADO - YA USADO EN OTRO DISPOSITIVO: " + clave)

                cur.close()
                conn.close()
            except Exception as e:
                print("Error DB: " + str(e))
                result = "ok"
                msg = "success"
                expdate = cliente["vence"]
    else:
        result = "ok"
        msg = "success"
        expdate = "20991231"
        print("Login sin validacion: " + user_id)

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

with app.app_context():
    init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 9090))
    app.run(host='0.0.0.0', port=port)
