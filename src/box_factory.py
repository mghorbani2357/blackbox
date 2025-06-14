import hashlib
import lzma
import pickle
import random
import struct
import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from key_factory import RSAKey


class BlackBox:

    def __init__(
            self, key: RSAKey,
            slots_count_limit: int = float('inf'),
            slots_size_limit: int = float('inf'),
            compression: bool = False,
    ):
        self.id = secrets.token_hex(32)

        self.key = key
        self.slots_count_limit = slots_count_limit
        self.slots_size_limit = slots_size_limit
        self.compression = compression
        self.slots = list()

    def __getitem__(self, slot_index):
        return self.slots[slot_index]

    def __len__(self):
        return len(self.slots)

    def put(self, data: bytes):
        self.slots.append(self.key.encrypt(data))
        while (len(self.slots) > self.slots_count_limit or
               sum([len(slot) for slot in self.slots]) > self.slots_size_limit):
            self.slots.pop(0)

    def get(self, slot_index: int):
        return self[slot_index]


def encapsulate(black_box: BlackBox) -> bytes:
    body = b''.join(black_box.slots)

    header = lzma.compress(pickle.dumps({
        'id': black_box.id,
        'public_key': black_box.key.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        'slots_count_limit': black_box.slots_count_limit,
        'slots_size_limit': black_box.slots_size_limit,
        'compression': black_box.compression,
        'slot_count': len(black_box.slots),
        'slots_size': [len(slot) for slot in black_box.slots],
        'body_size': len(body),
    }))

    header_size = struct.pack('I', len(header))

    if black_box.compression:
        body = lzma.compress(body)

    return header_size + header + body


def decapsulate(capsule: bytes) -> BlackBox:
    header_size = struct.unpack('I', capsule[:4])[0]

    header = pickle.loads(lzma.decompress(capsule[4:header_size + 4]))
    key = RSAKey()
    key.public_key = serialization.load_pem_public_key(header['public_key'], backend=default_backend())

    black_box = BlackBox(
        key=key,
        slots_count_limit=header['slots_count_limit'],
        slots_size_limit=header['slots_size_limit'],
        compression=header['compression']
    )

    black_box.id = header['id']
    header_offset = header_size + 4

    body = lzma.decompress(capsule[header_offset:]) if header['compression'] else capsule[header_offset:]
    body_offset = 0

    for i in range(len(header['slots_size'])):
        black_box.slots.append(body[body_offset:body_offset + header['slots_size'][i]])
        body_offset += header['slots_size'][i]

    return black_box
