# merkle.py
import hashlib
import struct
from dataclasses import dataclass
from typing import List, Tuple


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(index: int, block: bytes) -> bytes:
    """
    leaf_hash(i, block) = H(0x00 || LE64(i) || block)
    """
    return _sha256(b"\x00" + struct.pack("<Q", index) + block)


def node_hash(left: bytes, right: bytes) -> bytes:
    """
    node_hash(left, right) = H(0x01 || left || right)
    """
    return _sha256(b"\x01" + left + right)


def build_merkle_tree(blocks: List[bytes]) -> List[List[bytes]]:
    """
    Devuelve todos los niveles del árbol.
    level[0] = hojas, level[-1][0] = root.
    """
    if not blocks:
        raise ValueError("Blocks list is empty")

    # nivel de hojas
    current_level = [leaf_hash(i, b) for i, b in enumerate(blocks)]
    tree = [current_level]

    # subir hasta la raíz
    while len(current_level) > 1:
        next_level = []
        # si hay número impar de nodos, duplicamos el último
        if len(current_level) % 2 == 1:
            current_level.append(current_level[-1])

        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1]
            next_level.append(node_hash(left, right))

        tree.append(next_level)
        current_level = next_level

    return tree


def get_merkle_root(blocks: List[bytes]) -> bytes:
    return build_merkle_tree(blocks)[-1][0]


@dataclass
class MerkleProof:
    index: int
    leaf_hash: bytes
    path: List[bytes]    # hashes de los nodos hermanos
    dirs: List[str]      # "L" o "R" indicando dónde va el hermano


def build_merkle_proof(blocks: List[bytes], index: int) -> MerkleProof:
    """
    Construye la prueba de inclusión para el bloque en 'index'.
    """
    if index < 0 or index >= len(blocks):
        raise IndexError("Index out of range")

    tree = build_merkle_tree(blocks)
    path: List[bytes] = []
    dirs: List[str] = []

    idx = index
    for level in range(0, len(tree) - 1):  # desde hojas hasta antes de la raíz
        level_nodes = tree[level]

        # si longitud impar, el último se duplica lógicamente
        if len(level_nodes) % 2 == 1:
            level_nodes = level_nodes + [level_nodes[-1]]

        if idx % 2 == 0:
            # soy hijo izquierdo, hermano derecho
            sibling = level_nodes[idx + 1]
            path.append(sibling)
            dirs.append("R")
        else:
            # soy hijo derecho, hermano izquierdo
            sibling = level_nodes[idx - 1]
            path.append(sibling)
            dirs.append("L")

        idx = idx // 2

    return MerkleProof(
        index=index,
        leaf_hash=leaf_hash(index, blocks[index]),
        path=path,
        dirs=dirs,
    )


def verify_merkle_proof(proof: MerkleProof, root: bytes, block: bytes) -> bool:
    """
    Reconstruye la raíz a partir del bloque, el índice y el camino.
    """
    current = leaf_hash(proof.index, block)

    if current != proof.leaf_hash:
        return False

    for sibling, direction in zip(proof.path, proof.dirs):
        if direction == "R":
            current = node_hash(current, sibling)
        elif direction == "L":
            current = node_hash(sibling, current)
        else:
            raise ValueError(f"Invalid dir: {direction}")

    return current == root
