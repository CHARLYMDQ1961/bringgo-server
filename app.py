import os
import json
import base64
import hashlib
import hmac
import time
import secrets
import string
import urllib.request
import urllib.parse
import urllib.error

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


app = Flask(__name__)


APP_ID = "CHARLY_MDQ"


SUPABASE_URL = os.getenv(
    "SUPABASE_URL",
    ""
).rstrip("/")


SUPABASE_SECRET_KEY = os.getenv(
    "SUPABASE_SECRET_KEY",
    ""
)


ACTIVATION_SECRET = os.getenv(
    "ACTIVATION_SECRET",
    ""
)


PRIVATE_PEM = os.getenv(
    "ACTIVATION_PRIVATE_KEY_PEM",
    ""
)


TOKEN_TTL = int(
    os.getenv(
        "TOKEN_TTL_SECONDS",
        "31536000",
    )
)


def device_hash(device_id):
    return hashlib.sha256(
        device_id.encode("utf-8")
    ).hexdigest().upper()


def generate_activation_code():
    alphabet = (
        string.ascii_uppercase
        + string.digits
    )

    part1 = "".join(
        secrets.choice(alphabet)
        for _ in range(4)
    )

    part2 = "".join(
        secrets.choice(alphabet)
        for _ in range(2)
    )

    return (
        part1
        + "-"
        + part2
    )


def supabase_request(
    method,
    table,
    params=None,
    body=None,
):
    if not SUPABASE_URL:
        raise RuntimeError(
            "SUPABASE_URL missing"
        )

    if not SUPABASE_SECRET_KEY:
        raise RuntimeError(
            "SUPABASE_SECRET_KEY missing"
        )

    url = (
        SUPABASE_URL
        + "/rest/v1/"
        + table
    )

    if params:
        encoded_params = []

        for key, value in params.items():
            encoded_params.append(
                urllib.parse.quote(
                    str(key),
                    safe="",
                )
                + "="
                + urllib.parse.quote(
                    str(value),
                    safe=".,=()*",
                )
            )

        url += (
            "?"
            + "&".join(
                encoded_params
            )
        )

    data = None

    if body is not None:
        data = json.dumps(
            body
        ).encode("utf-8")

    headers = {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": (
            "Bearer "
            + SUPABASE_SECRET_KEY
        ),
        "Content-Type": (
            "application/json"
        ),
        "Accept": (
            "application/json"
        ),
        "Prefer": (
            "return=representation"
        ),
    }

    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers=headers,
    )

    try:
        with urllib.request.urlopen(
            req,
            timeout=15,
        ) as response:

            raw = (
                response
                .read()
                .decode("utf-8")
            )

            if not raw:
                return []

            return json.loads(raw)

    except urllib.error.HTTPError as exc:
        error_body = (
            exc.read()
            .decode(
                "utf-8",
                errors="replace",
            )
        )

        raise RuntimeError(
            "Supabase HTTP "
            + str(exc.code)
            + ": "
            + error_body
        )

    except urllib.error.URLError as exc:
        raise RuntimeError(
            "Supabase connection error: "
            + str(exc)
        )

    except Exception as exc:
        raise RuntimeError(
            "Supabase request error: "
            + str(exc)
        )


def create_token(
    device_hash_value,
):
    if not PRIVATE_PEM:
        raise RuntimeError(
            "ACTIVATION_PRIVATE_KEY_PEM missing"
        )

    now = int(
        time.time()
    )

    payload = {
        "app_id": APP_ID,
        "device_hash": device_hash_value,
        "iat": now,
        "exp": now + TOKEN_TTL,
        "nonce": secrets.token_hex(16),
    }

    raw = json.dumps(
        payload,
        separators=(
            ",",
            ":",
        ),
    ).encode("utf-8")

    private_key = (
        serialization
        .load_pem_private_key(
            PRIVATE_PEM.encode(
                "utf-8"
            ),
            password=None,
        )
    )

    signature = private_key.sign(
        raw,
        padding.PSS(
            mgf=padding.MGF1(
                hashes.SHA256()
            ),
            salt_length=(
                padding.PSS.MAX_LENGTH
            ),
        ),
        hashes.SHA256(),
    )

    def encode(value):
        return (
            base64
            .urlsafe_b64encode(
                value
            )
            .rstrip(b"=")
            .decode("ascii")
        )

    return (
        encode(raw)
        + "."
        + encode(signature),
        payload["exp"],
    )


def verify_token(token):
    if not PRIVATE_PEM:
        return None

    try:
        part_a, part_b = (
            token.split(
                ".",
                1,
            )
        )

        def decode(value):
            value += (
                "="
                * (
                    -len(value)
                    % 4
                )
            )

            return (
                base64
                .urlsafe_b64decode(
                    value
                )
            )

        raw = decode(
            part_a
        )

        signature = decode(
            part_b
        )

        private_key = (
            serialization
            .load_pem_private_key(
                PRIVATE_PEM.encode(
                    "utf-8"
                ),
                password=None,
            )
        )

        public_key = (
            private_key.public_key()
        )

        public_key.verify(
            signature,
            raw,
            padding.PSS(
                mgf=padding.MGF1(
                    hashes.SHA256()
                ),
                salt_length=(
                    padding.PSS.MAX_LENGTH
                ),
            ),
            hashes.SHA256(),
        )

        payload = json.loads(
            raw.decode(
                "utf-8"
            )
        )

        if payload.get(
            "app_id"
        ) != APP_ID:
            return None

        if int(
            payload.get(
                "exp",
                0,
            )
        ) < int(
            time.time()
        ):
            return None

        return payload

    except Exception:
        return None


def find_device(
    device_hash_value,
):
    rows = supabase_request(
        "GET",
        "devices",
        {
            "select": (
                "id,"
                "app_id,"
                "device_id,"
                "device_hash,"
                "installation_id,"
                "public_key,"
                "status,"
                "created_at,"
                "activated_at,"
                "revoked_at,"
                "last_seen_at"
            ),
            "app_id": (
                "eq."
                + APP_ID
            ),
            "device_hash": (
                "eq."
                + device_hash_value
            ),
            "limit": "1",
        },
    )

    if not rows:
        return None

    return rows[0]


def create_pending_device(
    device_id,
    device_hash_value,
    installation_id="",
    public_key="",
):
    body = {
        "app_id": APP_ID,
        "device_id": device_id,
        "device_hash": device_hash_value,
        "installation_id": (
            installation_id
            or None
        ),
        "public_key": (
            public_key
            or None
        ),
        "status": "pending",
    }

    rows = supabase_request(
        "POST",
        "devices",
        body=body,
    )

    if not rows:
        raise RuntimeError(
            "Supabase did not return "
            "created device"
        )

    return rows[0]


def find_pending_activation(
    device_uuid,
):
    rows = supabase_request(
        "GET",
        "activations",
        {
            "select": (
                "id,"
                "device_id,"
                "activation_code,"
                "status,"
                "requested_at,"
                "approved_at"
            ),
            "device_id": (
                "eq."
                + str(device_uuid)
            ),
            "status": (
                "eq.pending"
            ),
            "order": (
                "requested_at.desc"
            ),
            "limit": "1",
        },
    )

    if not rows:
        return None

    return rows[0]


def create_pending_activation(
    device_uuid,
):
    code = (
        generate_activation_code()
    )

    rows = supabase_request(
        "POST",
        "activations",
        body={
            "device_id": (
                str(device_uuid)
            ),
            "activation_code": code,
            "status": "pending",
        },
    )

    if not rows:
        raise RuntimeError(
            "Supabase did not return "
            "activation"
        )

    return rows[0]


def record_validation_event(
    device_uuid,
    event_type,
    result,
):
    if not device_uuid:
        return

    try:
        supabase_request(
            "POST",
            "validation_events",
            body={
                "device_id": (
                    str(device_uuid)
                ),
                "app_id": APP_ID,
                "event_type": event_type,
                "result": result,
                "ip_address": (
                    request.remote_addr
                ),
            },
        )

    except Exception:
        pass


def update_last_seen(
    device_uuid,
):
    if not device_uuid:
        return

    try:
        supabase_request(
            "PATCH",
            "devices",
            {
                "id": (
                    "eq."
                    + str(device_uuid)
                ),
            },
            {
                "last_seen_at": (
                    time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ",
                        time.gmtime(),
                    )
                ),
            },
        )

    except Exception:
        pass


@app.get("/")
def health():
    return jsonify(
        service="BringGo Server",
        status="ok",
    )


@app.post("/")
def legacy_login():
    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    if data.get(
        "service"
    ) != "login_ext_5":
        return jsonify(
            service=data.get(
                "service",
                "unknown",
            ),
            result="error",
            msg=(
                "service_not_supported"
            ),
        ), 400

    device_id = str(
        data.get(
            "passwd",
            "",
        )
    ).strip()

    if not device_id:
        return jsonify(
            service="login_ext_5",
            result="error",
            msg=(
                "device_id_missing"
            ),
        ), 403

    dh = device_hash(
        device_id
    )

    try:
        device = find_device(
            dh
        )

        if device is None:
            device = (
                create_pending_device(
                    device_id,
                    dh,
                )
            )

            activation = (
                create_pending_activation(
                    device["id"]
                )
            )

            code = activation[
                "activation_code"
            ]

            record_validation_event(
                device["id"],
                "login_ext_5",
                "pending",
            )

            return jsonify(
                service="login_ext_5",
                result="error",
                msg=(
                    "ACTIVACION "
                    "PENDIENTE "
                    + code
                ),
            ), 200

        if device.get(
            "status"
        ) != "active":

            activation = (
                find_pending_activation(
                    device["id"]
                )
            )

            if activation is None:
                activation = (
                    create_pending_activation(
                        device["id"]
                    )
                )

            code = activation[
                "activation_code"
            ]

            record_validation_event(
                device["id"],
                "login_ext_5",
                "pending",
            )

            return jsonify(
                service="login_ext_5",
                result="error",
                msg=(
                    "ACTIVACION "
                    "PENDIENTE "
                    + code
                ),
            ), 200

        update_last_seen(
            device["id"]
        )

        record_validation_event(
            device["id"],
            "login_ext_5",
            "authorized",
        )

        return jsonify(
            service="login_ext_5",
            result="ok",
            msg="ACTIVADO",
            expdate="20991231",
        )

    except Exception as exc:
        app.logger.exception(
            "legacy_login error: %s",
            exc,
        )

        return jsonify(
            service="login_ext_5",
            result="error",
            msg=(
                "server_database_error"
            ),
        ), 503


@app.post("/v1/activate")
def activate():
    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    if data.get(
        "app_id"
    ) != APP_ID:
        return jsonify(
            authorized=False,
            error="invalid_app_id",
        ), 400

    device_id = str(
        data.get(
            "device_id",
            "",
        )
    ).strip()

    installation_id = str(
        data.get(
            "installation_id",
            "",
        )
    ).strip()

    public_key = str(
        data.get(
            "public_key",
            "",
        )
    ).strip()

    if not device_id:
        return jsonify(
            authorized=False,
            error="device_id_missing",
        ), 400

    dh = device_hash(
        device_id
    )

    try:
        device = find_device(
            dh
        )

        if device is None:
            device = (
                create_pending_device(
                    device_id,
                    dh,
                    installation_id,
                    public_key,
                )
            )

            activation = (
                create_pending_activation(
                    device["id"]
                )
            )

            record_validation_event(
                device["id"],
                "activate",
                "pending",
            )

            return jsonify(
                authorized=False,
                error=(
                    "device_not_authorized"
                ),
                code=activation[
                    "activation_code"
                ],
            ), 403

        if device.get(
            "status"
        ) != "active":

            activation = (
                find_pending_activation(
                    device["id"]
                )
            )

            if activation is None:
                activation = (
                    create_pending_activation(
                        device["id"]
                    )
                )

            record_validation_event(
                device["id"],
                "activate",
                "pending",
            )

            return jsonify(
                authorized=False,
                error=(
                    "device_not_authorized"
                ),
                code=activation[
                    "activation_code"
                ],
            ), 403

        token, exp = (
            create_token(dh)
        )

        update_last_seen(
            device["id"]
        )

        record_validation_event(
            device["id"],
            "activate",
            "authorized",
        )

        return jsonify(
            authorized=True,
            token=token,
            exp=exp,
        )

    except Exception as exc:
        app.logger.exception(
            "activate error: %s",
            exc,
        )

        return jsonify(
            authorized=False,
            error=(
                "server_database_error"
            ),
        ), 503


@app.post("/v1/check")
def check():
    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    if data.get(
        "app_id"
    ) != APP_ID:
        return jsonify(
            authorized=False,
            error="invalid_app_id",
        ), 400

    device_id = str(
        data.get(
            "device_id",
            "",
        )
    ).strip()

    token = str(
        data.get(
            "token",
            "",
        )
    ).strip()

    if (
        not device_id
        or not token
    ):
        return jsonify(
            authorized=False,
            error="missing_data",
        ), 400

    payload = verify_token(
        token
    )

    if not payload:
        return jsonify(
            authorized=False,
            error="invalid_token",
        ), 403

    dh = device_hash(
        device_id
    )

    if payload.get(
        "device_hash"
    ) != dh:
        return jsonify(
            authorized=False,
            error="device_mismatch",
        ), 403

    try:
        device = find_device(
            dh
        )

        if device is None:
            return jsonify(
                authorized=False,
                error=(
                    "device_not_registered"
                ),
            ), 403

        if device.get(
            "status"
        ) != "active":

            record_validation_event(
                device["id"],
                "check",
                "revoked",
            )

            return jsonify(
                authorized=False,
                error="device_revoked",
            ), 403

        update_last_seen(
            device["id"]
        )

        record_validation_event(
            device["id"],
            "check",
            "authorized",
        )

        return jsonify(
            authorized=True,
            exp=payload[
                "exp"
            ],
        )

    except Exception as exc:
        app.logger.exception(
            "check error: %s",
            exc,
        )

        return jsonify(
            authorized=False,
            error=(
                "server_database_error"
            ),
        ), 503


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(
            os.getenv(
                "PORT",
                "10000",
            )
        ),
    )
