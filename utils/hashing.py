from blake3 import blake3

def blake3_hash(data: bytes) -> str:
    return blake3(data).hexdigest()

def compute_file_hash(file_path: str, chunk_size: int) -> str:
    h = blake3()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()
