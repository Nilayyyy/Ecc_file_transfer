from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os

class ECC:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.public_key = self.private_key.public_key()

    def get_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def load_public_key(self, public_bytes):
        return serialization.load_pem_public_key(public_bytes, backend=default_backend())

    def generate_shared_key(self, peer_public_key):
        shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key)
        # Derive a key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'file-transfer',
            backend=default_backend()
        ).derive(shared_key)
        return derived_key

    def encrypt(self, data, key):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return iv + ciphertext

    def decrypt(self, encrypted_data, key):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
