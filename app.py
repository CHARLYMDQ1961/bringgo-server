import base64
import hashlib
import hmac
import json
import os
import time
from flask import Flask, jsonify, request

app = Flask(__name__)

APP_ID = "CHARLY_MDQ"
TOKEN_TTL = int(os.getenv("TOKEN_TTL_SECONDS", "86400"))
APPROVED = {
    value.strip().lower()
    for value in os.getenv("APPROVED_DEVICE_HASHES", "").split(",")
    if value.strip()
}
SECRET = os.getenv("ACTIVATION_SECRET", "")


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def device_hash(device_id):
    return hashlib.sha256(str(device_id).strip().encode("utf-8")).hexdigest()


def request_code(dh):
    return dh[:12].upper()


def token(dh):
    now = int(time.time())
    header = b64u(json.dumps({"alg": "HS256", "typ": "BGAT1"}, separators=(",", ":")).encode())
    payload = b64u(json.dumps({"app": APP_ID, "device": dh, "iat": now, "exp": now + TOKEN_TTL}, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = hmac.new(SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{b64u(signature)}"


def verify_token(supplied_token, dh):
    try:
        parts = supplied_token.split(".")
        if len(parts) != 3 or any(not part for part in parts):
            return False
        header_segment, payload_segment, signature_segment = parts
        header = json.loads(unb64u(header_segment))
        payload = json.loads(unb64u(payload_segment))
        if not isinstance(header, dict) or header != {"alg": "HS256", "typ": "BGAT1"}:
            return False
        if not isinstance(payload, dict):
            return False
        if payload.get("app") != APP_ID or payload.get("device") != dh:
            return False
        iat, exp = payload.get("iat"), payload.get("exp")
        if type(iat) is not int or type(exp) is not int:
            return False
        now = int(time.time())
        if iat > now or exp <= now or exp <= iat or exp - iat != TOKEN_TTL:
            return False
        supplied_signature = unb64u(signature_segment)
        expected_signature = hmac.new(
            SECRET.encode("utf-8"),
            f"{header_segment}.{payload_segment}".encode("ascii"),
            hashlib.sha256,
        ).digest()
        return hmac.compare_digest(supplied_signature, expected_signature)
    except (ValueError, TypeError, UnicodeError, OverflowError):
        return False


@app.get("/")
def health():
    return jsonify(service="BringGo Server", status="ok")


@app.post("/v1/activate")
def activate():
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or body.get("app_id") != APP_ID:
        return jsonify(authorized=False, error="invalid_request"), 400
    device_id = str(body.get("device_id") or "").strip()
    if not device_id:
        return jsonify(authorized=False, error="invalid_request"), 400
    if not SECRET:
        return jsonify(authorized=False, error="server_not_configured"), 503
    dh = device_hash(device_id)
    if dh not in APPROVED:
        return jsonify(authorized=False, error="device_not_authorized", activation_required=True, request_code=request_code(dh)), 403
    return jsonify(authorized=True, token=token(dh), expires_in=TOKEN_TTL)


@app.post("/v1/check")
def check():
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or body.get("app_id") != APP_ID:
        return jsonify(authorized=False, error="invalid_request"), 400
    device_id = str(body.get("device_id") or "").strip()
    if not device_id:
        return jsonify(authorized=False, error="invalid_request"), 400
    supplied_token = body.get("token")
    if not isinstance(supplied_token, str) or not supplied_token.strip():
        return jsonify(authorized=False, error="missing_token"), 401
    if not SECRET:
        return jsonify(authorized=False, error="server_not_configured"), 503
    dh = device_hash(device_id)
    if dh not in APPROVED:
        return jsonify(authorized=False, error="device_not_authorized", activation_required=True, request_code=request_code(dh)), 403
    if not verify_token(supplied_token.strip(), dh):
        return jsonify(authorized=False, error="invalid_token"), 401
    return jsonify(authorized=True, expires_in=TOKEN_TTL)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
