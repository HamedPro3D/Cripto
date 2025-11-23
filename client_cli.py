# client_cli.py
import argparse
import base64
import json
import secrets
from pathlib import Path
from datetime import datetime, timezone
from typing import List

import requests

from merkle import get_merkle_root, verify_merkle_proof, MerkleProof


API_BASE = "http://localhost:8000"
TIMEOUT = 10


def read_blocks(path: Path, block_size: int) -> List[bytes]:
    blocks = []
    with path.open("rb") as f:
        while True:
            chunk = f.read(block_size)
            if not chunk:
                break
            blocks.append(chunk)
    return blocks


def cmd_upload(args):
    file_path = Path(args.file)
    block_size = args.block_size

    blocks = read_blocks(file_path, block_size)
    root = get_merkle_root(blocks)

    manifest = {
        "file_id": args.file_id,
        "filename": file_path.name,
        "file_size": file_path.stat().st_size,
        "block_size": block_size,
        "num_blocks": len(blocks),
        "hash_alg": "SHA-256",
        "root": root.hex(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    payload = {
        "manifest": manifest,
        "blocks": [base64.b64encode(b).decode("ascii") for b in blocks],
    }

    resp = requests.post(f"{API_BASE}/upload", json=payload)
    resp.raise_for_status()
    print("Upload OK:", resp.json())

    # guardamos manifest en disco
    if args.manifest_out:
        Path(args.manifest_out).write_text(json.dumps(manifest, indent=2))
        print("Manifest saved to", args.manifest_out)


def send_challenge(server_url, file_id, k=None, indices=None, nonce=None):
    if nonce is None:
        nonce = secrets.token_hex(8)  # genera un nonce si falta

    payload = {"file_id": file_id, "nonce": nonce}
    if indices is not None:
        payload["indices"] = indices
    else:
        payload["k"] = k

    try:
        # usa la constante TIMEOUT para evitar bloqueo indefinido
        resp = requests.post(f"{server_url}/challenge", json=payload, timeout=TIMEOUT)
        resp.raise_for_status()
    except requests.exceptions.Timeout:
        print("Error: timeout al conectar con el servidor")
        return None
    except requests.exceptions.RequestException as e:
        print("Error en la petición:", e)
        return None

    return resp.json()


def cmd_challenge(args):
    # use send_challenge so timeout and nonce handling are applied
    resp_data = send_challenge(
        API_BASE,
        args.file_id,
        k=(args.k if args.indices is None else None),
        indices=args.indices,
        nonce=args.nonce,
    )
    if resp_data is None:
        print("No se recibió respuesta válida del servidor.")
        return
    print(json.dumps(resp_data, indent=2))


def cmd_verify(args):
    # leemos manifest local
    manifest = json.loads(Path(args.manifest).read_text())

    # pedimos pruebas al servidor
    payload = {"file_id": manifest["file_id"], "challenge_id": args.challenge_id}
    resp = requests.post(f"{API_BASE}/prove", json=payload)
    resp.raise_for_status()
    data = resp.json()

    root = bytes.fromhex(data["root"])
    all_ok = True

    for p in data["proofs"]:
        block = base64.b64decode(p["block_b64"])
        mp = MerkleProof(
            index=p["index"],
            leaf_hash=bytes.fromhex(p["leaf_hash"]),
            path=[bytes.fromhex(h) for h in p["path"]],
            dirs=p["dirs"],
        )
        ok = verify_merkle_proof(mp, root, block)
        print(f"Index {p['index']} -> {'OK' if ok else 'FAIL'}")
        if not ok:
            all_ok = False

    print("Resultado global:", "OK" if all_ok else "FAIL")


def main():
    parser = argparse.ArgumentParser(prog="merkle-por-cli")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # upload
    p_up = sub.add_parser("upload", help="Subir archivo y manifest")
    p_up.add_argument("file")
    p_up.add_argument("--file-id", required=True)
    p_up.add_argument("--block-size", type=int, default=4096)
    p_up.add_argument("--manifest-out", default="manifest.json")
    p_up.set_defaults(func=cmd_upload)

    # challenge
    p_ch = sub.add_parser("challenge", help="Crear reto remoto")
    p_ch.add_argument("--file-id", required=True)
    p_ch.add_argument("--k", type=int, default=10)
    p_ch.add_argument("--indices", type=int, nargs="*")
    p_ch.add_argument("--nonce")
    p_ch.set_defaults(func=cmd_challenge)

    # verify
    p_v = sub.add_parser("verify", help="Verificar pruebas de /prove")
    p_v.add_argument("--manifest", default="manifest.json")
    p_v.add_argument("--challenge-id", required=True)
    p_v.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
