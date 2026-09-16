# BringGo secure-app-validation

Build: `pip install -r requirements.txt`
Start: `gunicorn app:app`

Render private environment variables:
- `ACTIVATION_SECRET`
- `APPROVED_DEVICE_HASHES`
- `TOKEN_TTL_SECONDS` (optional, default 86400)

No DNI, VIN or PostgreSQL.

NOTE: this is the server skeleton. Before putting the activation token into PK51, the token must be changed to an asymmetric signature (server private key only; APK gets public key only).
