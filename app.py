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
        print(f"Error init_db: {e}")

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

        if not cliente or not cliente["activo"] or cliente["vence"] < hoy:
            result = "fail"
            msg = "unauthorized"
            expdate = "00000000"
            print(f"Login RECHAZADO (no autorizado):
