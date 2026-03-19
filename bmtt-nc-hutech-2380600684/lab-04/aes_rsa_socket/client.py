from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import socket
import threading

# Connect to server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))

# Generate client RSA key
client_key = RSA.generate(2048)
cipher_rsa_client = PKCS1_OAEP.new(client_key)

# Receive server public key
server_pub_key_data = client_socket.recv(4096)
server_public_key = RSA.import_key(server_pub_key_data)
cipher_rsa_server = PKCS1_OAEP.new(server_public_key)

# Send client public key to server
client_socket.send(client_key.publickey().export_key(format='PEM'))

# Receive AES key and decrypt
encrypted_aes_key = client_socket.recv(4096)
aes_key = cipher_rsa_client.decrypt(encrypted_aes_key)

# AES encrypt/decrypt helpers
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

# Thread to receive messages from server
def receive_messages():
    while True:
        try:
            encrypted_message = client_socket.recv(4096)
            if not encrypted_message:
                break
            decrypted_message = decrypt_message(aes_key, encrypted_message)
            print("Server:", decrypted_message)
        except:
            break

receive_thread = threading.Thread(target=receive_messages)
receive_thread.start()

# Send messages to server
while True:
    message = input("Enter message ('exit' to quit): ")
    encrypted_message = encrypt_message(aes_key, message)
    client_socket.send(encrypted_message)
    if message.lower() == "exit":
        break

client_socket.close()