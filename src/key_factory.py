import warnings

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def get_max_message_size(public_key):
    key_size_bytes = public_key.key_size // 8
    hash_size = hashes.SHA256().digest_size
    return key_size_bytes - 2 * hash_size - 2

class RSAKey:
    public_key = None
    private_key = None

    def __init__(self, public_key_path: str = None, private_key_path: str = None, password: bytes = None):
        if public_key_path:
            self.public_key = self.load_public_key(public_key_path)

        if private_key_path:
            self.private_key = self.load_private_key(private_key_path, password=password)

    @staticmethod
    def generate_rsa_keys(file_path: str, key_size: int = 3072, pass_phrase: bytes = None):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        with open(file_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(pass_phrase) if  pass_phrase not in (b'', '', None) else serialization.NoEncryption()
            ))

        with open(f'{file_path}.pub', 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    @staticmethod
    def load_private_key(filepath, password: bytes = None):
        with open(filepath, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=password, backend=default_backend())

    @staticmethod
    def load_public_key(filepath):
        with open(filepath, 'rb') as f:
            return serialization.load_pem_public_key(f.read(), backend=default_backend())

    def encrypt(self, data: bytes):
        if self.public_key is None:
            raise Exception('Public key is not defined')

        max_chunk_size = get_max_message_size(self.public_key)
        encrypted_chunks = []

        for i in range(0, len(data), max_chunk_size):
            chunk = data[i:i + max_chunk_size]
            encrypted_chunk = self.public_key.encrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            length_bytes = len(encrypted_chunk).to_bytes(2, byteorder='big')
            encrypted_chunks.append(length_bytes + encrypted_chunk)

        return b''.join(encrypted_chunks)

    def decrypt(self, ciphertext: bytes):
        if self.private_key is None:
            raise Exception('Private key is not defined')
        decrypted_chunks = []
        i = 0
        data_len = len(ciphertext)

        while i < data_len:
            # Read the length prefix (2 bytes)
            chunk_len = int.from_bytes(ciphertext[i:i + 2], byteorder='big')
            i += 2
            encrypted_chunk = ciphertext[i:i + chunk_len]
            i += chunk_len

            decrypted_chunk = self.private_key.decrypt(
                encrypted_chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            decrypted_chunks.append(decrypted_chunk)

        return b''.join(decrypted_chunks)

# Todo:
#   - implement make_file.py
#   - get output file to store the output or print the data