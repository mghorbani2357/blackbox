import warnings

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


class RSAKey:
    public_key = None
    private_key = None

    def __init__(self, public_key_path: str = None, private_key_path: str = None, password: bytes = None):
        if public_key_path:
            self.public_key = self.load_public_key(public_key_path)

        if private_key_path:
            self.private_key = self.load_private_key(private_key_path, password=password)

    @staticmethod
    def generate_rsa_keys(file_path: str, key_size: int = 3072, pass_phrase: bytes = b''):
        if key_size < 3072:
            warnings.warn("Generating key with size lower than 3072 may cause vulnerability to quantum attacks")
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
                encryption_algorithm=serialization.BestAvailableEncryption(pass_phrase)
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
        return self.public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt(self, ciphertext: bytes):
        if self.private_key is None:
            raise Exception('Private key is not defined')
        return self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )


# === 🔐 Demo Usage ===
# if __name__ == "__main__":
#     passphrase = b'secure-password'

# Step 1: Generate and save keys
RSAKey.generate_rsa_keys('rsa.key', key_size=4096, pass_phrase=b'test')

# Step 2: Load keys
# pub_key = load_public_key('rsa.key.pub')
# priv_key = load_private_key('rsa.key',pass_phrase=passphrase)
# #
# # # Step 3: Encrypt data
# message = b"Top secret message."
# ciphertext = rsa_encrypt(message, pub_key)
# print(len(ciphertext))
# print(f"Encrypted: {ciphertext.hex()}")
# #
# # # Step 4: Decrypt data
# plaintext = rsa_decrypt(ciphertext, priv_key)
# print(f"Decrypted: {plaintext.decode()}")
