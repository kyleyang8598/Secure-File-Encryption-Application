"""Encryption methods for main.py"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import file_manager as fm
import os

# DO NOT USE
class XOR:
    """Handles XOR encryption for low level security"""
    def __init__(self, key:str):
        self.key = ...

    def encrypt(self, file:str) -> int:
        """Encrypts file content using XOR."""
        self.file = fm.FileManager(file)
        self.content = self.file.read_file()
        self.encrypted_content = []
        print(self.content)
        for i in self.content:
            print(i)
            for j in i:
                self.encrypted_content.append(j ^ self.key)
        print(self.encrypted_content) #WIP still need to make a file function
        ...

# Main Class
class AESCipher:
    """Handles AES encryption and decryption"""
    """Key must be 32 bytes"""
    def __init__(self, file:str|None, key:bytes, email:str):
        self.key = key
        self.email = email
        self.file_location = file
        self.file = fm.FileManager(file)
        self.path = self.file.storage(self.email)

    def encrypt(self):
        """Encrypts file content using AES."""
        if self.file.is_already_encrypted():
            return
        else:
            # Get the absolute paths of the source and destination files
            source_file = self.file_location
            destination_file = os.path.join(self.path, os.path.basename(self.file_location))

             # Check if the source and destination files are the same
            if os.path.abspath(source_file) == os.path.abspath(destination_file):
                new_file_location = source_file
            else:
                self.file.move_file(self.file_location, self.path)
                new_file_location = os.path.join(self.path, os.path.basename(self.file_location))
            
            # Reinit with new file location
            self.file = fm.FileManager(new_file_location)

            content = self.file.read_file()
            cipher = AES.new(self.key, AES.MODE_CBC)
            ciphertext = cipher.encrypt(pad(content, AES.block_size))
            self.file.write_file(cipher.iv + ciphertext, add_header=True)
            return new_file_location

    def decrypt(self):
        """Decrypts AES encrypted file content."""
        if self.file.is_already_encrypted():
            self.file.strip_header()
            ciphertext = self.file.read_file()
            iv = ciphertext[:AES.block_size] # change later include SHA256 for Key generation and IV
            ciphertext = ciphertext[AES.block_size:]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            try:
                self.file.write_file(unpad(cipher.decrypt(ciphertext), AES.block_size))
                print("Decryption successful.")
            except:
                print("Decryption unsuccessful.")

    def encrypt_all(self):
        all_files = []
        directory = self.path

        # Get all files
        for root, dirs, files in os.walk(directory):
            for file in files:
                full_path = os.path.join(root, file)
                all_files.append(full_path)
        
        for file in all_files:
            self.file_location = file
            self.file = fm.FileManager(file)
            self.encrypt()

    def decrypt_all(self):
        all_files = []
        directory = self.path

        # Get all files
        for root, dirs, files in os.walk(directory):
            for file in files:
                full_path = os.path.join(root, file)
                all_files.append(full_path)
        
        for file in all_files:
            self.file_location = file
            self.file = fm.FileManager(file)
            self.decrypt()

if __name__ == "__main__":
    # aes_cipher = AESCipher(r'shoppingList.txt')  # Initialize with a random key
    # plaintext = "Hello, AES encryption!"

    # encrypted_text = aes_cipher.encrypt()
    # print(f"Encrypted: {encrypted_text}")

    # decrypted_text = aes_cipher.decrypt()
    # print(f"Decrypted: {decrypted_text}")

    aes = AESCipher(file=None, key=bytes('a'*32, encoding='utf8'), email='1')
    #aes.encrypt_all()

    aes.decrypt_all()
