import os, json, time, hashlib, hmac, base64
from flask import Flask, request, jsonify

app = Flask(__name__)

SERVER_SECRET = os.getenv("ACTIVATION_SECRET", "")
TOKEN_TTL = int(os.getenv("TOKEN_TTL_SECONDS", "31536000"))

def approved_hashes():
    raw = os.getenv("APPROVED_DEVICE_HASHES", "")
    return {x.strip().lower() for x in raw.replace("\n", ",").split(",") if x.strip()}

def device_hash(device_id):
    return hashlib.sha256(device_id.encode("utf-8")).hexdigest()

def make_token(app_id, dev_hash, exp):
    payload = {
        "app_id": app_id,
        "device_hash": dev_hash,
        "exp": exp,
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    sig = hmac.new(SERVER_SECRET.encode(), raw, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode() + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

def activation(body):
    # Supports both the native API names and the names used by CHARLYMDQ.APK.
    app_id = body.get("app_id") or body.get("id")
    device_id = body.get("device_id") or body.get("passwd")
    service = body.get("service", "")

    if not app_id or not device_id:
        return {
            "service": service or "login_ext_5",
            "result": "error",
            "msg": "missing_device_or_app",
            "authorized": False,
        }

    dh = device_hash(str(device_id))
    allowed = dh.lower() in approved_hashes()

    if not allowed:
        return {
            "service": service or "login_ext_5",
            "result": "error",
            "msg": "device_not_authorized",
            "authorized": False,
            "device_hash": dh,
        }

    exp = int(time.time()) + TOKEN_TTL
    token = make_token(str(app_id), dh, exp) if SERVER_SECRET else ""

    return {
        "service": service or "login_ext_5",
        "result": "ok",
        "msg": "authorized",
        "authorized": True,
        "device_hash": dh,
        "exp": exp,
        "token": token,
    }

@app.get("/")
def health():
    return jsonify(service="BringGo Server", status="ok")

@app.post("/")
def legacy_login():
    return jsonify(activation(request.get_json(silent=True) or {}))

@app.post("/v1/activate")
def activate():
    return jsonify(activation(request.get_json(silent=True) or {}))

@app.post("/v1/check")
def check():
    body = request.get_json(silent=True) or {}
    token = body.get("token", "")
    device_id = body.get("device_id") or body.get("passwd")
    app_id = body.get("app_id") or body.get("id")

    if not token or not device_id or not app_id or not SERVER_SECRET:
        return jsonify(authorized=False), 200

    try:
        encoded_payload, encoded_sig = token.split(".", 1)
        pad = "=" * (-len(encoded_payload) % 4)
        raw = base64.urlsafe_b64decode(encoded_payload + pad)
        pad = "=" * (-len(encoded_sig) % 4)
        sig = base64.urlsafe_b64decode(encoded_sig + pad)
        expected = hmac.new(SERVER_SECRET.encode(), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return jsonify(authorized=False), 200
        payload = json.loads(raw.decode())
        dh = device_hash(str(device_id))
        ok = (
            payload.get("app_id") == str(app_id)
            and payload.get("device_hash") == dh
            and int(payload.get("exp", 0)) > int(time.time())
            and dh.lower() in approved_hashes()
        )
        return jsonify(authorized=ok), 200
    except Exception:
        return jsonify(authorized=False), 200
