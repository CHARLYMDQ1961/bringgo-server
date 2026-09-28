cd /d "%USERPROFILE%\Desktop"

powershell -NoProfile -Command "$p='servidor\app.py'; $s=@'
import base64, hashlib, hmac, json, os, time
from flask import Flask, jsonify, request

app = Flask(__name__)

APP_ID = "CHARLY_MDQ"
TOKEN_TTL = int(os.getenv("TOKEN_TTL_SECONDS", "86400"))
APPROVED = {
    x.strip().lower()
    for x in os.getenv("APPROVED_DEVICE_HASHES", "").split(",")
    if x.strip()
}
SECRET = os.getenv("ACTIVATION_SECRET", "")


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def device_hash(device_id):
    return hashlib.sha256(
        str(device_id).strip().encode("utf-8")
    ).hexdigest()


def request_code(dh):
    return dh[:12].upper()


def token(dh):
    now = int(time.time())

    h = b64u(json.dumps(
        {"alg": "HS256", "typ": "BGAT1"},
        separators=(",", ":")
    ).encode())

    p = b64u(json.dumps(
        {
            "app": APP_ID,
            "device": dh,
            "iat": now,
            "exp": now + TOKEN_TTL
        },
        separators=(",", ":")
    ).encode())

    s = hmac.new(
        SECRET.encode("utf-8"),
        f"{h}.{p}".encode("utf-8"),
        hashlib.sha256
    ).digest()

    return f"{h}.{p}.{b64u(s)}"


@app.get("/")
def health():
    return jsonify(
        service="BringGo Server",
        status="ok"
    )


@app.post("/v1/activate")
def activate():
    b = request.get_json(silent=True) or {}

    if b.get("app_id") != APP_ID:
        return jsonify(
            authorized=False,
            error="invalid_request"
        ), 400

    device_id = str(b.get("device_id", "")).strip()

    if not device_id:
        return jsonify(
            authorized=False,
            error="invalid_request"
        ), 400

    if not SECRET:
        return jsonify(
            authorized=False,
            error="server_not_configured"
        ), 503

    dh = device_hash(device_id)

    if dh not in APPROVED:
        return jsonify(
            authorized=False,
            error="device_not_authorized",
            activation_required=True,
            request_code=request_code(dh)
        ), 403

    return jsonify(
        authorized=True,
        token=token(dh),
        expires_in=TOKEN_TTL
    )


@app.post("/v1/check")
def check():
    b = request.get_json(silent=True) or {}

    if b.get("app_id") != APP_ID:
        return jsonify(
            authorized=False,
            error="invalid_request"
        ), 400

    device_id = str(b.get("device_id", "")).strip()
    supplied_token = str(b.get("token", "")).strip()

    if not device_id:
        return jsonify(
            authorized=False,
            error="invalid_request"
        ), 400

    if not supplied_token:
        return jsonify(
            authorized=False,
            error="missing_token"
        ), 401

    if not SECRET:
        return jsonify(
            authorized=False,
            error="server_not_configured"
        ), 503

    dh = device_hash(device_id)

    if dh not in APPROVED:
        return jsonify(
            authorized=False,
            error="device_not_authorized",
            activation_required=True,
            request_code=request_code(dh)
        ), 403

    expected = token(dh)

    if not hmac.compare_digest(supplied_token, expected):
        return jsonify(
            authorized=False,
            error="invalid_token"
        ), 401

    return jsonify(
        authorized=True,
        expires_in=TOKEN_TTL
    )


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", "10000"))
    )
'@; [IO.File]::WriteAllText((Resolve-Path $p),$s,(New-Object System.Text.UTF8Encoding($false)))"

type "servidor\app.py"
