"""Opt-in, fail-closed device-key licensing API for CHARLY MDQ.

Does not alter the existing /v1 API. Requires persistent PostgreSQL DATABASE_URL.
Never use the Render ephemeral filesystem for the licensing database.
"""
import base64
import hashlib
import hmac
import os
import secrets
import time
import uuid
from functools import wraps
from flask import Blueprint, jsonify, request

bp = Blueprint('security_v2', __name__, url_prefix='/v2')
APP = 'CHARLY_MDQ'


def b64d(s):
    if not isinstance(s, str) or len(s) > 256:
        raise ValueError('invalid encoding')
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')


def db():
    url = os.environ.get('DATABASE_URL', '')
    if not url.startswith(('postgresql://', 'postgres://')):
        raise RuntimeError('persistent_database_not_configured')
    import psycopg2
    return psycopg2.connect(url, connect_timeout=5, sslmode='require')


def error(msg, status):
    return jsonify(ok=False, error=msg), status


def body():
    b = request.get_json(silent=True)
    return b if isinstance(b, dict) else {}


def admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        key = os.environ.get('LICENSE_ADMIN_KEY', '')
        supplied = request.headers.get('Authorization', '')
        if len(key) < 32 or not hmac.compare_digest(supplied, 'Bearer ' + key):
            return error('unauthorized', 401)
        return fn(*args, **kwargs)
    return wrapper


def pubkey(raw):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    key_bytes = b64d(raw)
    if len(key_bytes) != 32:
        raise ValueError('invalid key')
    return Ed25519PublicKey.from_public_bytes(key_bytes), key_bytes


def verify(key_bytes, signature, message):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(key_bytes).verify(b64d(signature), message.encode('ascii'))
        return True
    except (ValueError, TypeError):
        return False
    except Exception as ex:
        from cryptography.exceptions import InvalidSignature
        if isinstance(ex, InvalidSignature):
            return False
        raise


def init(conn):
    with conn.cursor() as cur:
        cur.execute('''CREATE TABLE IF NOT EXISTS license_devices (
            id UUID PRIMARY KEY, public_key BYTEA NOT NULL UNIQUE,
            request_code VARCHAR(20) NOT NULL UNIQUE,
            status VARCHAR(12) NOT NULL CHECK(status IN ('pending','active','revoked','replaced')),
            created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL,
            note VARCHAR(120) NOT NULL DEFAULT ''
        )''')
        cur.execute('''CREATE TABLE IF NOT EXISTS license_challenges (
            id UUID PRIMARY KEY, device_id UUID NOT NULL REFERENCES license_devices(id),
            nonce VARCHAR(80) NOT NULL, expires_at BIGINT NOT NULL, consumed BOOLEAN NOT NULL DEFAULT FALSE
        )''')
    conn.commit()


@bp.post('/admin/init')
@admin
def initialize():
    try:
        with db() as conn:
            init(conn)
        return jsonify(ok=True)
    except Exception:
        return error('database_unavailable', 503)


@bp.post('/enroll')
def enroll():
    b = body()
    try:
        _, key = pubkey(b.get('public_key'))
        if not verify(key, b.get('signature'), APP + '|enroll|' + b['public_key']):
            return error('invalid_proof', 401)
    except (ValueError, TypeError, KeyError):
        return error('invalid_request', 400)
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT id,request_code,status FROM license_devices WHERE public_key=%s', (key,))
                old = cur.fetchone()
                if old:
                    return jsonify(ok=True, device_id=str(old[0]), request_code=old[1], status=old[2])
                now = int(time.time())
                device_id = uuid.uuid4()
                code = '-'.join((secrets.token_hex(3).upper(), secrets.token_hex(3).upper()))
                cur.execute('INSERT INTO license_devices (id,public_key,request_code,status,created_at,updated_at) VALUES (%s,%s,%s,%s,%s,%s)', (str(device_id), key, code, 'pending', now, now))
        return jsonify(ok=True, device_id=str(device_id), request_code=code, status='pending'), 201
    except Exception:
        return error('database_unavailable', 503)


@bp.post('/challenge')
def challenge():
    b = body()
    try:
        device_id = str(uuid.UUID(str(b.get('device_id'))))
    except (ValueError, AttributeError):
        return error('invalid_request', 400)
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT status FROM license_devices WHERE id=%s', (device_id,))
                found = cur.fetchone()
                if not found or found[0] != 'active':
                    return error('not_authorized', 403)
                challenge_id, nonce = uuid.uuid4(), b64e(secrets.token_bytes(32))
                cur.execute('INSERT INTO license_challenges (id,device_id,nonce,expires_at) VALUES (%s,%s,%s,%s)', (str(challenge_id),device_id,nonce,int(time.time())+120))
        return jsonify(ok=True, challenge_id=str(challenge_id), nonce=nonce, expires_in=120)
    except Exception:
        return error('database_unavailable', 503)


@bp.post('/verify')
def validate():
    b = body()
    try:
        device_id = str(uuid.UUID(str(b.get('device_id'))))
        challenge_id = str(uuid.UUID(str(b.get('challenge_id'))))
    except (ValueError, AttributeError):
        return error('invalid_request', 400)
    try:
        with db() as conn:
            with conn.cursor() as cur:
                # Lock the challenge so that two simultaneous requests cannot replay it.
                cur.execute('SELECT nonce,expires_at,consumed FROM license_challenges WHERE id=%s AND device_id=%s FOR UPDATE', (challenge_id, device_id))
                ch = cur.fetchone()
                if not ch or ch[2] or ch[1] < int(time.time()):
                    return error('invalid_challenge', 401)
                cur.execute('SELECT public_key,status FROM license_devices WHERE id=%s', (device_id,))
                row = cur.fetchone()
                if not row or row[1] != 'active':
                    return error('not_authorized', 403)
                message = APP + '|challenge|' + challenge_id + '|' + ch[0]
                if not verify(bytes(row[0]), b.get('signature'), message):
                    return error('invalid_proof', 401)
                cur.execute('UPDATE license_challenges SET consumed=TRUE WHERE id=%s', (challenge_id,))
        return jsonify(ok=True, authorized=True, checked_at=int(time.time()))
    except Exception:
        return error('database_unavailable', 503)


@bp.get('/admin/devices')
@admin
def devices():
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT id,request_code,status,created_at,updated_at,note FROM license_devices ORDER BY created_at DESC LIMIT 500')
                rows = cur.fetchall()
        return jsonify(ok=True, devices=[dict(device_id=str(r[0]), request_code=r[1], status=r[2], created_at=r[3], updated_at=r[4], note=r[5]) for r in rows])
    except Exception:
        return error('database_unavailable', 503)


@bp.post('/admin/decision')
@admin
def decision():
    b = body()
    if b.get('status') not in ('active','revoked'):
        return error('invalid_request', 400)
    code = str(b.get('request_code', '')).strip().upper()
    if len(code) > 20 or not code:
        return error('invalid_request', 400)
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute('UPDATE license_devices SET status=%s,updated_at=%s WHERE request_code=%s AND status IN (\'pending\',\'active\',\'revoked\') RETURNING id', (b['status'],int(time.time()),code))
                row = cur.fetchone()
                if not row:
                    return error('not_found', 404)
        return jsonify(ok=True, status=b['status'])
    except Exception:
        return error('database_unavailable', 503)


@bp.post('/admin/replace')
@admin
def replace():
    """Manual recovery after reinstall: move a license from old key to newly enrolled key."""
    b = body()
    old_code = str(b.get('old_request_code','')).strip().upper()
    new_code = str(b.get('new_request_code','')).strip().upper()
    if not old_code or not new_code or old_code == new_code:
        return error('invalid_request', 400)
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT id,status FROM license_devices WHERE request_code=%s FOR UPDATE', (old_code,))
                old = cur.fetchone()
                cur.execute('SELECT id,status FROM license_devices WHERE request_code=%s FOR UPDATE', (new_code,))
                new = cur.fetchone()
                if not old or not new or old[1] != 'active' or new[1] != 'pending':
                    return error('invalid_transfer', 409)
                now = int(time.time())
                cur.execute('UPDATE license_devices SET status=\'replaced\',updated_at=%s WHERE id=%s', (now,str(old[0])))
                cur.execute('UPDATE license_devices SET status=\'active\',updated_at=%s WHERE id=%s', (now,str(new[0])))
        return jsonify(ok=True, status='transferred')
    except Exception:
        return error('database_unavailable', 503)
