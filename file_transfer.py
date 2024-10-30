import os
from ecc import ECC

class FileTransfer:
    def __init__(self, ecc_instance, peer_public_key):
        self.ecc = ecc_instance
        self.shared_key = self.ecc.generate_shared_key(peer_public_key)

    def encrypt_file(self, file_path):
        with open(file_path, 'rb') as file:
            file_data = file.read()
            encrypted_data = self.ecc.encrypt(file_data, self.shared_key)
        encrypted_file_path = file_path + '.enc'
        with open(encrypted_file_path, 'wb') as enc_file:
            enc_file.write(encrypted_data)
        return encrypted_file_path

    def decrypt_file(self, encrypted_file_path):
        with open(encrypted_file_path, 'rb') as enc_file:
            encrypted_data = enc_file.read()
            decrypted_data = self.ecc.decrypt(encrypted_data, self.shared_key)
        decrypted_file_path = encrypted_file_path.replace('.enc', '.dec')
        with open(decrypted_file_path, 'wb') as dec_file:
            dec_file.write(decrypted_data)
        return decrypted_file_path
