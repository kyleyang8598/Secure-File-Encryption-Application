from Crypto.PublicKey import RSA

class RSAKeyManager:
    """Handles RSA key generation, saving, and loading."""
    
    def __init__(self, key_size=2048):
        """Initialize with a key size and generate an RSA key pair."""
        self.key_size = key_size
        self.key = RSA.generate(self.key_size)  # Generate RSA key pair

    def save_keys(self, private_key_file="private.pem", public_key_file="public.pem"):
        """Saves the RSA private and public keys to files."""
        # Save private key
        private_key = self.key.export_key()
        with open(private_key_file, "wb") as f:
            f.write(private_key)

        # Save public key
        public_key = self.key.publickey().export_key()
        with open(public_key_file, "wb") as f:
            f.write(public_key)

        print(f"Keys saved: {private_key_file}, {public_key_file}")

    def load_private_key(self, filename="private.pem"):
        """Loads an existing private key from a file."""
        with open(filename, "rb") as f:
            return RSA.import_key(f.read())

    def load_public_key(self, filename="public.pem"):
        """Loads an existing public key from a file."""
        with open(filename, "rb") as f:
            return RSA.import_key(f.read())

# Usage Example
if __name__ == "__main__":
    rsa_manager = RSAKeyManager()
    rsa_manager.save_keys()  # Generate and save keys
