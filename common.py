"""Shared helpers (identical copy on every machine)."""
import hashlib
import json
import struct


def pack(header, blobs=()):
    """Wire format: 4-byte header length | JSON header | blob_1 | blob_2 | ..."""
    blobs = list(blobs)
    head = json.dumps(dict(header, sizes=[len(b) for b in blobs])).encode()
    return struct.pack(">I", len(head)) + head + b"".join(blobs)


def unpack(body):
    view = memoryview(body)
    hlen = struct.unpack(">I", view[:4])[0]
    header = json.loads(bytes(view[4:4 + hlen]))
    off, blobs = 4 + hlen, []
    for n in header.pop("sizes"):
        blobs.append(bytes(view[off:off + n]))
        off += n
    return header, blobs


def sha_list(blobs):
    return [hashlib.sha256(b).digest() for b in blobs]


def build_kary_merkle(leaves, k):
    """All levels, bottom (leaves) -> top (root). k=2 is a binary Merkle tree."""
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        levels.append([hashlib.sha256(b"".join(cur[i:i + k])).digest()
                       for i in range(0, len(cur), k)])
    return levels


def root_of(leaves, k):
    return build_kary_merkle(leaves, k)[-1][0]
