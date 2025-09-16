import socket
import time
import threading
from queue import Queue
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import RSA_keyGeneration as keyGen



class SecureTCPServer:
    """RSA Encrypted session for sending and recieving data securely"""
    def __init__(self, host="0.0.0.0", port=53217, max_connections=5, data_queue:Queue=None):
        self.kg = keyGen.RSAKeyManager()
        self.host = host
        self.port = port
        self.max_connections = max_connections
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        self.data_queue = data_queue

        # Try-Except catch in case keys do not exist
        while True:
            try:
                # Load the RSA keys
                self.private_key = self.kg.load_private_key()
                self.public_key = self.kg.load_public_key()
                break

            except FileNotFoundError:
                # Generate Keys if not existant already
                self.kg.save_keys()

            except Exception as e:
                print(f"Error loading keys: {e}")
                break
        
        print("Initilization done.")


    def start_server(self):
        """Starts the TCP server and listens for incoming connections."""
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(self.max_connections)
        print(f"Secure Server listening on {self.host}:{self.port}")
    
        while True:
            time.sleep(0.01)
            self.client_socket, addr = self.server_socket.accept()
            self.auth = self.authenticateClient()
            print(f"Connection received from {addr}")

            # Start a new thread for each client
            client_thread = threading.Thread(target=self.handle_client)
            client_thread.start()


    def authenticateClient(self):
        """Authenticate client by signing a challenge (sends public key)"""
        try:
            # Receive challenge (nonce) from client
            challenge = self.client_socket.recv(1024)

            if not challenge:
                print("No challenge recieved.")
                return False

            # Sign the challenge with the private key
            hash_obj = SHA256.new(challenge)
            signature = pkcs1_15.new(self.private_key).sign(hash_obj)

            # Send public key and signature back to client
            self.client_socket.send(self.public_key.export_key() + b":::" + signature)
            print("Sent public key and signed challenge.")
            return True
                
        except Exception as e:
            print(f"Error: {e}")
            return False
        

    def handle_client(self, messageSend=None):
        """Handles the secure key exchange and communication."""
        if not self.auth:
            print("Client authentication failed.")
            self.client_socket.close()
            return
        
        try:
            cipher_rsa = PKCS1_OAEP.new(self.private_key)

            if messageSend:
                # Only send a message, don't wait for incoming message
                print(f"Sending message: {messageSend}")
                self.client_socket.sendall(messageSend)
            
            else:
                # Listen loop
                while True:
                    # Receive the encrypted message from the client
                    encrypted_message = self.client_socket.recv(512)
                    
                    if not encrypted_message:
                        self.client_socket.close()
                        break

                    # Decrypt AES key using server's private key
                    message = cipher_rsa.decrypt(encrypted_message)
                    print(f"Message Recieved: {message.decode()}")

                    # Checking Queue
                    if self.data_queue:
                        self.data_queue.put(message.decode())

                    # Close session from client
                    if message == b'EXIT':
                        print("Session Closed: Client Disconnected")
                        self.client_socket.close()
                        break

        except Exception as e:
            print(f"Error during key exchange: {e}")
            self.client_socket.close()

    def stop_server(self):
        """Stops the server and closes the socket."""
        self.server_socket.close()
        print("Server stopped.")

if __name__ == "__main__":
    server = SecureTCPServer()
    try:
        server.start_server()
    except KeyboardInterrupt:
        server.stop_server()
