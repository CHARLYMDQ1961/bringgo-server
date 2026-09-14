from flask import Flask, request, jsonify
from datetime import datetime
import os
import psycopg2

app = Flask(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL", "")
AUTHORIZED_CLIENTS = os.environ.get("AUTHORIZED_CLIENTS", "")


def get_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL no configurada")
    return psycopg2.connect(DATABASE_URL)


def get_authorized_clients():
    """
    Formato:
    DNI-VIN,otroDNI-otroVIN
    La información real queda solamente en las variables
    de entorno de Render, no dentro del APK ni del repositorio.
    """
    return {
        item.strip()
        for item in AUTHORIZED_CLIENTS.split(",")
        if item.strip()
    }


def init_db():
    try:
        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS activaciones (
                clave VARCHAR(100) PRIMARY KEY,
                fecha_activacion VARCHAR(20),
                activo BOOLEAN DEFAULT TRUE,
                device_id VARCHAR(200)
            )
        """)

        conn.commit()
        cur.close()
        conn.close()

    except Exception as e:
        print("Error init_db: " + str(e))


@app.route("/", methods=["GET"])
def health():
    return "BringGo Server OK"


@app.route("/", methods=["POST"])
def login():

    try:
        data = request.get_json(force=True)

        service = data.get("service", "")
        user_id = data.get("id", "")
        dni = data.get("dni", "")
        vin = data.get("vin", "")
        device_id = data.get("device_id", "")

    except Exception:
        service = ""
        user_id = ""
        dni = ""
        vin = ""
        device_id = ""

    hoy = datetime.now().strftime("%Y%m%d")

    # --------------------------------------------------
    # IDENTIDAD OBLIGATORIA
    # --------------------------------------------------

    if not dni or not vin:
        return jsonify({
            "service": service,
            "result": "fail",
            "msg": "identity_required",
            "user_id": user_id,
            "latest_ver": "2016Q3.16042",
            "version": "2016Q3.16042",
            "expdate": "00000000",
            "updatelimit": "00000000",
            "trialday": "0",
            "today": hoy,
            "crc": 0
        })

    clave = dni + "-" + vin

    # --------------------------------------------------
    # CLIENTE AUTORIZADO
    # --------------------------------------------------

    if clave not in get_authorized_clients():

        print("Login RECHAZADO: cliente no autorizado")

        return jsonify({
            "service": service,
            "result": "fail",
            "msg": "unauthorized",
            "user_id": user_id,
            "latest_ver": "2016Q3.16042",
            "version": "2016Q3.16042",
            "expdate": "00000000",
            "updatelimit": "00000000",
            "trialday": "0",
            "today": hoy,
            "crc": 0
        })

    # --------------------------------------------------
    # BASE DE DATOS
    # --------------------------------------------------

    try:

        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
            SELECT clave, activo, device_id
            FROM activaciones
            WHERE clave = %s
        """, (clave,))

        row = cur.fetchone()

        # Primera activación
        if row is None:

            cur.execute("""
                INSERT INTO activaciones
                (clave, fecha_activacion, activo, device_id)
                VALUES (%s, %s, %s, %s)
            """, (clave, hoy, True, device_id))

            conn.commit()

            result = "ok"
            msg = "success"
            expdate = "20991231"

            print("Login OK - PRIMERA ACTIVACION")

        else:

            # Cliente desactivado
            if not row[1]:

                cur.close()
                conn.close()

                return jsonify({
                    "service": service,
                    "result": "fail",
                    "msg": "already_used",
                    "user_id": user_id,
                    "latest_ver": "2016Q3.16042",
                    "version": "2016Q3.16042",
                    "expdate": "00000000",
                    "updatelimit": "00000000",
                    "trialday": "0",
                    "today": hoy,
                    "crc": 0
                })

            # Si ya está asociado a otro dispositivo,
            # no permitir una segunda instalación.
            stored_device = row[2]

            if stored_device and device_id and stored_device != device_id:

                cur.close()
                conn.close()

                print("Login RECHAZADO: dispositivo diferente")

                return jsonify({
                    "service": service,
                    "result": "fail",
                    "msg": "device_mismatch",
                    "user_id": user_id,
                    "latest_ver": "2016Q3.16042",
                    "version": "2016Q3.16042",
                    "expdate": "00000000",
                    "updatelimit": "00000000",
                    "trialday": "0",
                    "today": hoy,
                    "crc": 0
                })

            result = "ok"
            msg = "success"
            expdate = "20991231"

        cur.close()
        conn.close()

    except Exception as e:

        print("Error DB: " + str(e))

        return jsonify({
            "service": service,
            "result": "fail",
            "msg": "server_error",
            "user_id": user_id,
            "latest_ver": "2016Q3.16042",
            "version": "2016Q3.16042",
            "expdate": "00000000",
            "updatelimit": "00000000",
            "trialday": "0",
            "today": hoy,
            "crc": 0
        })

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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 9090))
    app.run(host="0.0.0.0", port=port)