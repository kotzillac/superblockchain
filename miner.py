import timeit

from argon2 import low_level
from blake3 import blake3


def BLAKE3(data):
    return blake3(data).digest()

def BLAKE3e(data):
    return BLAKE3(BLAKE3(BLAKE3(BLAKE3(BLAKE3(BLAKE3(BLAKE3(BLAKE3(data))))))))

def dHash(data):
    for _ in range(4):
        data = BLAKE3e(data)
        data = low_level.hash_secret_raw(data, b'dochaisbestcat', 4, 32768, 1, 64, low_level.Type.ID)
    return data

execution_time = timeit.timeit(lambda: dHash(b"hello world"), number=100)
print(execution_time)