import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from Crypto import Random

class AESEncryptor:
    def __init__(self, key=b'strom-32-byte-aes-key-1234'):
        """
        Enhanced AES Encryptor combining both versions
        Features:
        - Auto IV generation (version 1)
        - Fixed IV option (version 2)
        - Key length validation
        - Type safety
        """
        self.key = key[:32]  # Ensure 256-bit key (version 2 improvement)
        self.default_iv = b'strom-16-byte-iv'  # Fixed IV (version 2)
        
    def encrypt(self, plaintext, use_random_iv=True):
        """
        Encrypt data with optional random IV (version 1) or fixed IV (version 2)
        
        Args:
            plaintext: String to encrypt
            use_random_iv: Bool - True for random IV (more secure), False for fixed IV
            
        Returns:
            base64 encoded string of (IV + ciphertext) if random IV,
            or just ciphertext if fixed IV
        """
        if use_random_iv:
            iv = Random.new().read(AES.block_size)  # version 1 approach
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            ct_bytes = cipher.encrypt(pad(self._ensure_bytes(plaintext), AES.block_size))
            return base64.b64encode(iv + ct_bytes).decode()  # version 1 style
        else:
            cipher = AES.new(self.key, AES.MODE_CBC, self.default_iv)  # version 2 approach
            ct_bytes = cipher.encrypt(pad(self._ensure_bytes(plaintext), AES.block_size))
            return base64.b64encode(ct_bytes).decode()  # version 2 style
    
    def decrypt(self, ciphertext, used_random_iv=True):
        """
        Decrypt data based on IV mode used during encryption
        
        Args:
            ciphertext: base64 encoded ciphertext
            used_random_iv: Bool - must match encryption setting
            
        Returns:
            Decrypted string
        """
        ct = base64.b64decode(ciphertext)
        
        if used_random_iv:
            iv = ct[:AES.block_size]  # version 1 approach
            ct_bytes = ct[AES.block_size:]
        else:
            iv = self.default_iv  # version 2 approach
            ct_bytes = ct
            
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct_bytes), AES.block_size).decode()
    
    def _ensure_bytes(self, data):
        """Helper to ensure data is in bytes format"""
        if isinstance(data, str):
            return data.encode('utf-8')
        return data

    @staticmethod
    def generate_key(length=32):
        """Generate random cryptographic key"""
        return Random.get_random_bytes(length)

# Example usage
if __name__ == "__main__":
    # Initialize with custom key or generate one
    key = AESEncryptor.generate_key()
    encryptor = AESEncryptor(key)
    
    # Encrypt with random IV (more secure)
    msg = "Secret message for Strom"
    encrypted = encryptor.encrypt(msg)
    print(f"Encrypted (random IV): {encrypted}")
    
    # Decrypt (auto-detects IV)
    decrypted = encryptor.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")
    
    # Encrypt with fixed IV (for deterministic output)
    encrypted_fixed = encryptor.encrypt(msg, use_random_iv=False)
    print(f"Encrypted (fixed IV): {encrypted_fixed}")
    print(f"Decrypted: {encryptor.decrypt(encrypted_fixed, used_random_iv=False)}")
