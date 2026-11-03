# CHARLY MDQ — Seguridad V2 (preparación, no desplegado)

## Estado
Implementación de servidor preparada para pruebas. **No se ha desplegado a Render ni integrado en la APK.** No sustituye un pentest ni garantiza resistencia absoluta a ingeniería inversa.

## Qué añade
- Identidad por instalación mediante clave pública **Ed25519**. La clave privada se debe crear y conservar en Android Keystore cuando el dispositivo lo soporte.
- Solicitud con código aleatorio de 12 dígitos hexadecimales, no una contraseña de activación.
- Aprobación y revocación manuales mediante API de administrador autenticada.
- Comprobación por desafío firmado, con nonce aleatorio de 120 segundos, uso único y estado activo en base de datos.
- Recuperación manual de licencia tras reinstalar (`/v2/admin/replace`): revoca clave anterior y activa la nueva, sin generar una segunda licencia.
- Registro persistente en PostgreSQL. Si falla la base, la verificación falla de manera cerrada.
- Compatibilidad con `/v1/activate` y `/v1/check` existentes: no cambia el comportamiento de la APK actual.

## Dependencias y despliegue futuro
El `requirements.txt` de Render debe incluir `Flask`, `gunicorn`, `psycopg2-binary`, `cryptography`. El servidor debe disponer de una base **PostgreSQL persistente** (variable `DATABASE_URL`, TLS obligatorio) y una variable **nueva y secreta** `LICENSE_ADMIN_KEY` con al menos 32 caracteres aleatorios. No reutilizar `ACTIVATION_SECRET`. No enviar estas claves a clientes ni incorporarlas a la APK. Configurar restricciones de red y monitoreo de la base.

Antes de activar V2: crear PostgreSQL, configurar variables, desplegar en staging, hacer `POST /v2/admin/init` con cabecera `Authorization: Bearer <LICENSE_ADMIN_KEY>` y probar todos los casos. **No desplegar en producción hasta integrar y probar el cliente**.

## API V2
- `POST /v2/enroll` JSON `{ "public_key": "base64url_32_bytes", "signature": "base64url_ed25519_signature" }`. Firma del texto ASCII `CHARLY_MDQ|enroll|<public_key>`; responde `device_id`, `request_code`, `status`.
- `GET /v2/admin/devices` — lista pendientes/activos/revocados (autenticación de administrador).
- `POST /v2/admin/decision` JSON `{ "request_code": "ABCDEF-123456", "status": "active" }` o `"revoked"`.
- `POST /v2/challenge` JSON `{ "device_id": "uuid" }` — devuelve `challenge_id` y `nonce` para dispositivos activos.
- `POST /v2/verify` JSON `{ "device_id": "uuid", "challenge_id": "uuid", "signature": "base64url" }`. Firma del texto ASCII `CHARLY_MDQ|challenge|<challenge_id>|<nonce>`.
- `POST /v2/admin/replace` JSON `{ "old_request_code": "...", "new_request_code": "..." }` — recuperación aprobada manualmente.

## Limitaciones y tareas pendientes
1. El código V2 requiere **pruebas integradas con PostgreSQL real**, controles de concurrencia, migraciones, tests adversariales y revisión independiente.
2. Agregar rate limiting en proxy/servidor para enrolamiento, desafíos y panel; protección del administrador con MFA y auditoría de decisiones.
3. Diseñar cliente Android: Android Keystore, reintentos, almacenamiento seguro, comprobaciones de firma de APK, integridad y control de errores. El código APK funcional NO ha sido modificado.
4. Si se requiere uso offline, implementar **licencia firmada asimétricamente por servidor** con caducidad y verificación local; no incluir secreto HMAC en APK. La V2 actual requiere conexión para verificar.
5. Android Keystore y claves de instalación no sobreviven necesariamente a una desinstalación. La recuperación requiere autorización manual. No se puede garantizar que `ANDROID_ID` identifique inequívocamente un teléfono.
6. La API V1 sigue siendo vulnerable a suplantación de `device_id` si un atacante lo conoce. Planificar migración y posterior deshabilitación de V1 cuando los clientes V2 estén listos.
7. Protección absoluta contra modificación de APK no existe: los chequeos locales pueden parchearse. Evaluar Play Integrity cuando proceda, detección de manipulación y distribución firmada, sin romper compatibilidad con MyLink.
