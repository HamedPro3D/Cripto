# Merkle PoR - Proyecto de demostración

Pequeño proyecto de prueba de retrievability/verificabilidad basado en Merkle trees. Incluye:
- servidor (FastAPI) que expone endpoints para subir archivos, crear retos y entregar pruebas.
- cliente CLI (`client_cli.py`) para subir archivos, lanzar retos (`challenge`) y verificar pruebas (`verify`).
- utilidades para construir/verificar Merkle proofs (`merkle.py`).

## Estructura
- `server.py` — API (endpoints: `/upload`, `/challenge`, `/prove`).
- `client_cli.py` — cliente CLI para interactuar con el servidor.
- `merkle.py` — funciones para calcular Merkle root y verificar pruebas.
- `requirements.txt` — dependencias.

## Requisitos
- Python 3.8+
- Instalar dependencias:
  pip install -r requirements.txt

## Arrancar el servidor
Desde la carpeta del proyecto (`c:....\Cripto`):
uvicorn server:app --reload --host 127.0.0.1 --port 8000

(Reemplaza host/port según necesites.)

## Uso del cliente CLI
Ejecutar desde la carpeta del proyecto.

1) Subir un archivo
python client_cli.py upload ruta/al/archivo --file-id *idDelArchivo* --block-size 4096 --manifest-out manifest.json

2) Crear un reto (challenge)
python client_cli.py challenge --file-id test1 --k 3
- `--k` número de bloques aleatorios a desafiar (por defecto 10).
- `--indices` puedes pasar índices concretos en vez de `k`.
- El cliente genera un `nonce` por defecto si no lo proporcionas.

3) Solicitar pruebas (prove) y verificar
- El servidor devuelve un `challenge_id` en la respuesta a `/challenge`.
- Para obtener las pruebas:
python client_cli.py verify --manifest manifest.json --challenge-id <challenge_id>

## Endpoints (rápido)
- POST /upload — payload: `{ manifest, blocks }` (blocks en base64).
- POST /challenge — payload: `{ file_id, nonce, k }` o `{ file_id, nonce, indices }`.
- POST /prove — payload: `{ file_id, challenge_id }`.

## Pruebas y diagnóstico
- Si el cliente "se queda" sin respuesta:
  - Asegura que el servidor está corriendo y que el host/puerto en `client_cli.py` (`API_BASE`) coinciden con uvicorn.
  - Prueba con curl para aislar cliente/servidor:
    curl -v -X POST "http://127.0.0.1:8000/challenge" -H "Content-Type: application/json" -d '{"file_id":"idDelArchivo","nonce":"n","k":1}'
  - Revisa la salida/logs del servidor (terminal donde corre uvicorn) para ver si las peticiones llegan o si hay errores/excepciones.
  - El cliente incluye un timeout por defecto; si necesitas ajustarlo modifica `TIMEOUT` en `client_cli.py`.

## Notas de desarrollo
- El manifest contiene metadatos (file_id, root, tamaño, block_size, num_blocks, hash_alg, created_at).
- Las pruebas que entrega `/prove` contienen:
  - `block_b64` — bloque en base64
  - `index`, `leaf_hash`, `path` (hex) y `dirs` (direcciones para la prueba)
- `merkle.py` implementa creación y verificación de pruebas; la verificación local se hace con `verify_merkle_proof`.

## Problemas comunes
- 404 en `/challenge`: el `file_id` no está registrado (no subiste el archivo con `/upload`).
- 422 en `/challenge` o `/prove`: falta un campo obligatorio (por ejemplo `nonce` o `k`).
- Sin respuesta/timeout: servidor no accesible (host/puerto incorrectos) o bloqueos en red.

## Siguientes pasos sugeridos
- Persistencia real para bloques/manifest (actualmente memoria/estructura simple).
- Logging más detallado en `server.py`.

## Licencia
Proyecto de ejemplo — adapta y usa según necesites.
