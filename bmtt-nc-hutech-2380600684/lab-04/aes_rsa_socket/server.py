from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import socket
import threading

# Create server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen()

# List to keep track of clients (optional, for broadcasting)
clients = []

# AES/RSA helper functions
def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ciphertext

def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:AES.block_size]
    ciphertext = encrypted_message[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode()

# Thread to handle each client
def handle_client(client_socket, addr):
    print(f"Client connected: {addr}")
    
    # Generate server RSA key for this client
    server_key = RSA.generate(2048)
    cipher_rsa_server = PKCS1_OAEP.new(server_key)
    
    # Send server public key
    client_socket.send(server_key.publickey().export_key(format='PEM'))
    
    # Receive client public key
    client_pub_key_data = client_socket.recv(4096)
    client_public_key = RSA.import_key(client_pub_key_data)
    cipher_rsa_client = PKCS1_OAEP.new(client_public_key)
    
    # Create AES key for this client
    aes_key = get_random_bytes(16)
    encrypted_aes_key = cipher_rsa_client.encrypt(aes_key)
    client_socket.send(encrypted_aes_key)
    
    # Thread to receive messages from this client
    def receive_messages():
        while True:
            try:
                encrypted_message = client_socket.recv(4096)
                if not encrypted_message:
                    break
                decrypted_message = decrypt_message(aes_key, encrypted_message)
                print(f"{addr}: {decrypted_message}")
            except:
                break
    
    receive_thread = threading.Thread(target=receive_messages)
    receive_thread.start()
    
    # Send messages to client
    while True:
        try:
            message = input(f"Enter message to {addr} ('exit' to quit): ")
            encrypted_message = encrypt_message(aes_key, message)
            client_socket.send(encrypted_message)
            if message.lower() == "exit":
                break
        except:
            break
    
    client_socket.close()
    print(f"Connection with {addr} closed.")

# Main loop to accept clients
while True:
    client_socket, addr = server_socket.accept()
    clients.append(client_socket)
    thread = threading.Thread(target=handle_client, args=(client_socket, addr))
    thread.start()