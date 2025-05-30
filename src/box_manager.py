import lzma
import pickle
import struct

from cryptography.hazmat.primitives import serialization

from src.box_factory import BlackBox, encapsulate, decapsulate
from src.key_factory import RSAKey


class BoxManager:
    boxes = list()
    ledger = None

    def __init__(self):
        pass

    def load_ledger_from_file(self, file_path):
        pass

    def save_ledger_to_file(self, file_path):
        pass



key = RSAKey(public_key_path='rsa.key.pub')

bb = BlackBox(
    key,
    slots_count_limit=30,
    compression=True
)

bb.put(b"Private data.")


capsule = encapsulate(bb)
recover = decapsulate(capsule)

print('')
