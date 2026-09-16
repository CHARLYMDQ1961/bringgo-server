# BringGo Server – CHARLYMDQ

CHARLYMDQ.APK posts its existing login JSON to the Render root endpoint.
The server maps:
- `id` -> application id
- `passwd` -> Android device id
- `service=login_ext_5`

Authorization is controlled only by `APPROVED_DEVICE_HASHES` on Render.
No DNI/VIN is stored in the APK.

The APK uses Android `Settings.Secure.ANDROID_ID` as the device identifier.
A copied APK on another device therefore produces a different hash and is rejected
unless that device is explicitly approved on Render.

Environment variables:
- `ACTIVATION_SECRET`
- `APPROVED_DEVICE_HASHES`
- `TOKEN_TTL_SECONDS`

For an unapproved device, the server returns HTTP 200 with `result=error`,
`msg=device_not_authorized`, and the SHA-256 device hash so the administrator
can approve that exact device hash.
