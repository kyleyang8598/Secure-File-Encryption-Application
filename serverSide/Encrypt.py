from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

class AESEncrypt:
    def __init__(self, key:bytes):
        self.key = key

    def encrypt(self, content):
        """Encrypts file content using AES."""
        cipher = AES.new(self.key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(content, AES.block_size))
        return base64.b64encode(cipher.iv + ciphertext).decode()

if __name__ == "__main__":
    file = AESEncrypt()
    