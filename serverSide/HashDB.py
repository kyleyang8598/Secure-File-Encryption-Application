from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

class Hash:
    def __init__(self, key_len = 32, N = 2**17, r = 8, p = 1):
        """Parameters for scrypt according to OWASP Guidelines"""
        self.key_len = key_len
        self.N = N
        self.r = r
        self.p = p

    def deriveHashDB(self, password:str, salt=None)->tuple[bytes, bytes]:
        """Returns key, salt"""
        salt = get_random_bytes(16) if not salt else salt
        key = scrypt(password, salt, self.key_len, self.N, self.r, self.p)
        return (key, salt)

if __name__ == "__main__":
    password = b'ttttttttttttttttttttttttttttttttttttest'
    salt = 'test'#get_random_bytes(16)
    key = scrypt(password, salt, 16, N=2**17, r=8, p=1)
    print(key)
    print(salt)
# with open("test.txt", 'wb') as file:
#     file.write(salt)

# with open("test.txt", 'rb') as file:
#     print(file.read())