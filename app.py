import base64, hashlib, hmac, json, os, time
from flask import Flask, jsonify, request

app = Flask(__name__)
APP_ID = "CHARLY_MDQ"
TOKEN_TTL = int(os.getenv("TOKEN_TTL_SECONDS", "86400"))
APPROVED = {x.strip().lower() for x in os.getenv("APPROVED_DEVICE_HASHES", "").split(",") if x.strip()}
SECRET = os.getenv("ACTIVATION_SECRET", "")

def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def token(device_hash):
    now = int(time.time())
    h = b64u(json.dumps({"alg":"HS256","typ":"BGAT1"}, separators=(",",":")).encode())
    p = b64u(json.dumps({"app":APP_ID,"device":device_hash,"iat":now,"exp":now+TOKEN_TTL}, separators=(",",":")).encode())
    s = hmac.new(SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64u(s)}"

@app.get("/")
def health():
    return jsonify(service="BringGo Server", status="ok")

@app.post("/v1/activate")
def activate():
    b = request.get_json(silent=True) or {}
    if b.get("app_id") != APP_ID or not str(b.get("device_id","")).strip():
        return jsonify(authorized=False, error="invalid_request"), 400
    if not SECRET:
        return jsonify(authorized=False, error="server_not_configured"), 503
    dh = hashlib.sha256(str(b["device_id"]).strip().encode()).hexdigest()
    if dh not in APPROVED:
        return jsonify(authorized=False, error="device_not_authorized"), 403
    return jsonify(authorized=True, token=token(dh), expires_in=TOKEN_TTL)

@app.post("/v1/check")
def check():
    return jsonify(authorized=False, error="not_enabled"), 501

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT","10000")))
