import socket
import time
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from tkinter import messagebox

IP = '127.0.0.1'

class SecureTCPClient:
    def __init__(self, server_ip = IP, port = 53217):
        self.server_ip = server_ip
        self.port = port
        self.server_public_key = None
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        if not self.connect_to_server():  # authenticates and opens connection
            # Create an error gui message
            messagebox.showerror("Connection Error", "Failed to connect to the server. Please try again later or contact support.")
            raise ConnectionError("Couldn't connect to server, try again later!")

    def verify_server(self, server_public_key, challenge, signature):
        """Verify server identity by checking signed challenge"""
        try:
            key = RSA.import_key(server_public_key)
            hash_obj = SHA256.new(challenge)
            pkcs1_15.new(key).verify(hash_obj, signature)
            print("Server authentication successful!")
            return True
        
        except (ValueError, TypeError):
            print("Server authentication failed!")
            return False

    def connect_to_server(self):
        """Connects to server and verifies authentication"""
        try:    
            self.client_socket.connect((self.server_ip, self.port))

            # Generate random challenge (nonce)
            challenge = get_random_bytes(16)
            self.client_socket.send(challenge)
            response = self.client_socket.recv(4096)
            
            # Ensure we got a valid response
            if b":::" not in response:
                print("Invalid response from server.")
                self.client_socket.close()
                return False
            
            else:
                # Receive server's public key and signed challenge
                public_key, signature = response.split(b":::") 

            # Verify Server
            if self.verify_server(public_key, challenge, signature):
                print("Server Verified!")
                self.server_public_key = RSA.import_key(public_key)
                return True
            
            else:
                print("Exiting due to failed authentication.")
                return False
            
        except Exception as e:
            print(f'Connection Error: {e}')
            self.client_socket.close()
            return False

    def encryptedSend(self, message:str):
        """Encrypts a message securely using RSA."""
        if self.server_public_key is None:
            print("No verified server public key. Aborting...")
            return
        
        try:
            # Encrypt the message
            cipher_rsa = PKCS1_OAEP.new(self.server_public_key)
            encrypted_message = cipher_rsa.encrypt(message.encode())

            self.client_socket.sendall(encrypted_message)
            
        except Exception as e:
            print(f'Error sending message: {e}')

    def encryptedRecieve(self):
        """Waits for a response from server (1min timeout)"""
        count = 0
        while True:
            response = self.client_socket.recv(1024)
            if response:
                    print(f'Server Response: {response.decode()}')
                    return response.decode()
            else:
                if count < 60:
                    time.sleep(1)
                else:
                    break
                
    def endSession(self):
        """Closes the connection and notifies the server."""
        self.encryptedSend('EXIT')
        self.client_socket.close()
        
        
if __name__ == "__main__":
    client = SecureTCPClient()
    message = ["test", 'test2', 'test3', 'password', 'email', 'godnsouihnguh83284u098rewufdhsjoHGYBIU(*&^FOVGHBUH*(&GFCTVG))']
    [client.encryptedSend(i) for i in message]
    client.endSession()
    #client.send(message)