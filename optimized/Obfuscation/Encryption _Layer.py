class HybridEncoder:
    """Hybrid AES/ChaCha20 Payload Encoder with Fallback"""
    def __init__(self, master_key):
        self.aes_key = hashlib.sha256(master_key + b'AES').digest()[:32]
        self.chacha_key = hashlib.sha256(master_key + b'CHACHA').digest()[:32]

    def encrypt(self, payload):
        # Randomly choose between AES and ChaCha20
        if random.choice([True, False]):
            # AES-256-CBC
            iv = get_random_bytes(16)
            cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(payload, AES.block_size))
            return b'AES' + iv + ciphertext
        else:
            # ChaCha20
            nonce = get_random_bytes(12)
            cipher = ChaCha20.new(key=self.chacha_key, nonce=nonce)
            ciphertext = cipher.encrypt(payload)
            return b'CHAC' + nonce + ciphertext

    def decrypt(self, data):
        if data.startswith(b'AES'):
            iv = data[3:19]
            ciphertext = data[19:]
            cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ciphertext), AES.block_size)
        elif data.startswith(b'CHAC'):
            nonce = data[4:16]
            ciphertext = data[16:]
            cipher = ChaCha20.new(key=self.chacha_key, nonce=nonce)
            return cipher.decrypt(ciphertext)
        else:
            raise ValueError("Unknown encryption method")
