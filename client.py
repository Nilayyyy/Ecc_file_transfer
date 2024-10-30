import socket
from ecc import ECC
from file_transfer import FileTransfer

# Client-side code
def client_send_file(file_path, server_host='localhost', server_port=12345):
    # Initialize ECC instance and get public key
    ecc = ECC()
    client_public_key = ecc.get_public_key()

    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_host, server_port))

        # Send client's public key to server
        s.sendall(client_public_key)

        # Receive server's public key
        server_public_key_pem = s.recv(4096)

        # Load server's public key from PEM format
        server_public_key = ecc.load_public_key(server_public_key_pem)

        # Set up file transfer with ECC
        file_transfer = FileTransfer(ecc, server_public_key)

        # Encrypt and send file
        encrypted_file = file_transfer.encrypt_file(file_path)
        with open(encrypted_file, 'rb') as f:
            data = f.read()
            s.sendall(data)

        print(f"Encrypted file {encrypted_file} sent successfully.")

if __name__ == "__main__":
    client_send_file('test.txt')
