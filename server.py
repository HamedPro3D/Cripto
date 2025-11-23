# server.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict
import base64
import secrets
from datetime import datetime, timedelta, timezone

from merkle import get_merkle_root, build_merkle_proof, MerkleProof

from fastapi.openapi.utils import get_openapi


app = FastAPI(
    title="Merkle PoR API Demo",
    servers=[
        {"url": "https://studious-space-pancake-gj7ggqv9wv42vp9q-8000.app.github.dev", "description": "Codespaces"}
    ]
)


# ---- Modelos de datos ----

class Manifest(BaseModel):
    file_id: str
    filename: str
    file_size: int
    block_size: int
    num_blocks: int
    hash_alg: str
    root: str        # hex-encoded
    created_at: str  # ISO8601


class UploadRequest(BaseModel):
    manifest: Manifest
    blocks: List[str]  # lista de bloques en base64


class ChallengeRequest(BaseModel):
    file_id: str
    nonce: str
    k: Optional[int] = None
    indices: Optional[List[int]] = None


class ChallengeResponse(BaseModel):
    status: str
    challenge_id: str
    indices: List[int]
    issued_at: str


class ProveRequest(BaseModel):
    file_id: str
    challenge_id: str


class ProofItem(BaseModel):
    index: int
    leaf_hash: str
    path: List[str]
    dirs: List[str]
    block_b64: str
    block_present: bool = True


class ProveResponse(BaseModel):
    file_id: str
    challenge_id: str
    root: str
    proofs: List[ProofItem]
    issued_at: str


# ---- "Base de datos" en memoria (demo) ----

DB_BLOCKS: Dict[str, List[bytes]] = {}
DB_MANIFEST: Dict[str, Manifest] = {}
DB_CHALLENGES: Dict[str, Dict] = {}


CHALLENGE_TTL_MINUTES = 5


# ---- Endpoints ----

@app.post("/upload")
def upload(req: UploadRequest):
    manifest = req.manifest

    if len(req.blocks) != manifest.num_blocks:
        raise HTTPException(
            status_code=400,
            detail="num_blocks does not match length of blocks"
        )

    blocks: List[bytes] = [base64.b64decode(b) for b in req.blocks]

    # calculamos la raíz localmente para comprobar consistencia
    root = get_merkle_root(blocks).hex()
    if root != manifest.root:
        raise HTTPException(
            status_code=400,
            detail="Merkle root mismatch between manifest and uploaded blocks"
        )

    DB_BLOCKS[manifest.file_id] = blocks
    DB_MANIFEST[manifest.file_id] = manifest

    return {
        "status": "ok",
        "file_id": manifest.file_id,
        "stored_blocks": len(blocks),
    }


@app.post("/challenge", response_model=ChallengeResponse)
def challenge(req: ChallengeRequest):
    if req.file_id not in DB_BLOCKS:
        raise HTTPException(status_code=404, detail="file_id not found")

    num_blocks = len(DB_BLOCKS[req.file_id])

    if req.indices is not None and req.k is not None:
        raise HTTPException(
            status_code=400,
            detail="Provide either k or indices, not both"
        )

    if req.indices is None:
        # generamos índices pseudo-aleatorios
        k = req.k or 10
        indices = set()
        while len(indices) < k:
            indices.add(secrets.randbelow(num_blocks))
        indices = sorted(indices)
    else:
        # validamos índices
        for i in req.indices:
            if i < 0 or i >= num_blocks:
                raise HTTPException(
                    status_code=400,
                    detail=f"Index out of range: {i}"
                )
        indices = sorted(set(req.indices))

    challenge_id = "ch_" + secrets.token_hex(8)
    now = datetime.now(timezone.utc)

    DB_CHALLENGES[challenge_id] = {
        "file_id": req.file_id,
        "indices": indices,
        "nonce": req.nonce,
        "created_at": now,
    }

    return ChallengeResponse(
        status="challenge_issued",
        challenge_id=challenge_id,
        indices=indices,
        issued_at=now.isoformat(),
    )


@app.post("/prove", response_model=ProveResponse)
def prove(req: ProveRequest):
    ch = DB_CHALLENGES.get(req.challenge_id)
    if not ch or ch["file_id"] != req.file_id:
        raise HTTPException(status_code=404, detail="challenge_id not found")

    now = datetime.now(timezone.utc)
    if now - ch["created_at"] > timedelta(minutes=CHALLENGE_TTL_MINUTES):
        raise HTTPException(status_code=400, detail="challenge expired")

    blocks = DB_BLOCKS[req.file_id]
    manifest = DB_MANIFEST[req.file_id]

    proofs: List[ProofItem] = []

    for idx in ch["indices"]:
        # construimos prueba Merkle para ese índice
        mp: MerkleProof = build_merkle_proof(blocks, idx)
        block = blocks[idx]

        proofs.append(
            ProofItem(
                index=idx,
                leaf_hash=mp.leaf_hash.hex(),
                path=[h.hex() for h in mp.path],
                dirs=mp.dirs,
                block_b64=base64.b64encode(block).decode("ascii"),
                block_present=True,
            )
        )

    return ProveResponse(
        file_id=req.file_id,
        challenge_id=req.challenge_id,
        root=manifest.root,
        proofs=proofs,
        issued_at=now.isoformat(),
    )
