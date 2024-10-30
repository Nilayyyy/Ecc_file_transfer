import socket
from ecc import ECC
from file_transfer import FileTransfer

# Server-side code
def server_receive_file(save_path, host='localhost', port=12345):
    # Initialize ECC instance and get public key
    ecc = ECC()
    server_public_key = ecc.get_public_key()

    # Set up server socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)
        print(f"Server listening on {host}:{port}")

        # Accept connection from client
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")

            # Receive client's public key in PEM format
            client_public_key_pem = conn.recv(4096)

            # Load client's public key from PEM format
            client_public_key = ecc.load_public_key(client_public_key_pem)

            # Send server's public key to client in PEM format
            conn.sendall(server_public_key)

            # Set up file transfer with ECC
            file_transfer = FileTransfer(ecc, client_public_key)

            # Receive encrypted file data
            encrypted_data = conn.recv(4096)
            with open(save_path + '.enc', 'wb') as f:
                f.write(encrypted_data)

            # Decrypt the file
            decrypted_file = file_transfer.decrypt_file(save_path + '.enc')
            print(f"File decrypted and saved as {decrypted_file}")

if __name__ == "__main__":
    server_receive_file('received_file.txt')
