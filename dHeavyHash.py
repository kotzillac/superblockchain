import numpy as np
from blake3 import blake3


def BLAKE3(data: bytes):
    return blake3(data).digest(32)


def BLAKE3e(data: bytes):
    for _ in range(8):
        data = BLAKE3(data)
    return data


def is_full_rank(A, tol=1e-9):
    R = np.linalg.qr(A.astype(np.float64), mode="r")
    return np.all(np.abs(np.diag(R)) > tol)


def dHeavyHash(data: bytes):
    data = BLAKE3e(data)
    rng = np.random.default_rng(
        seed=int.from_bytes(BLAKE3(data + b"dHeavyHash"), byteorder="big")
    )

    while True:
        mat1 = rng.integers(low=-128, high=128, size=(64, 64), dtype=np.int8)

        for _ in range(3):
            mat2 = rng.integers(low=-128, high=128, size=(64, 64), dtype=np.int8)
            mat1 = mat1 @ mat2

        if is_full_rank(mat1):
            return BLAKE3e(mat1.tobytes(order="C"))