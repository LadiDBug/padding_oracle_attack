from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import base64

def xor(b1, b2):
    """XOR operation tra due byte_arrays"""
    return bytearray([b1[i] ^ b2[i] for i in range(len(b1))])

class AES_MODE_CBC(object):
    def __init__(self, key=None, iv=None):
        if key is None:
            key = get_random_bytes(32)
        self.key = key
        if iv is None:
            iv = get_random_bytes(16)
        self.iv = iv

    def _add_padding(self, data):
        padding = 16 - (len(data) % 16)
        return data + bytes([padding] * padding)



    def split_blocks(self, data):
        blocks = []
        for i in range(0, len(data), 16):
            blocks.append(data[i:i+16])
        return blocks

    def encrypt(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        plaintext = self._add_padding(plaintext)
        blocks = self.split_blocks(plaintext)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        ciphertext = self.iv
        previous_block = self.iv
        for block in blocks:
            encrypted_block = cipher.encrypt(xor(previous_block, block))
            ciphertext += encrypted_block
            previous_block = encrypted_block
        return base64.b64encode(ciphertext)
    
if __name__ == "__main__":
    cipher = AES_MODE_CBC()
    plaintext = "Questa è una stringa segreta"
    ciphertext = cipher.encrypt(plaintext)
    print("Stringa cifrata: ", ciphertext)
    