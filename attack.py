from aes_encryption import AES_MODE_CBC
import base64
from Crypto.Cipher import AES

cipher = AES_MODE_CBC()

def check_and_strip_padding(data):
    padding_len = data[-1]

    if padding_len < 1 or padding_len > 16:
        raise ValueError("Incorrect padding")
    
    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Incorrect padding")
    
    return data[:-padding_len]

def attack(ciphertext):
    ciphertext = base64.b64decode(ciphertext)
    blocks = cipher.split_blocks(ciphertext)
    iv = blocks[0]
    blocks = blocks[1:]

    plaintext = b''
    for i, block in enumerate(blocks):
        # Perform padding oracle attack on each block
        decrypted_block = decifra_blocco(iv, block)
        plaintext += decrypted_block
        iv = blocks[i]  # Update iv for the next block decryption

    return check_and_strip_padding(plaintext)   

def decifra_blocco(iv, block):
    BLOCK_SIZE = 16
    zeroing_iv = [0] * BLOCK_SIZE

    for pad_val in range(1, BLOCK_SIZE + 1):
        padding_iv = [pad_val ^ b for b in zeroing_iv]

        for candidate in range(256):
            padding_iv[-pad_val] = candidate
            iv_guess = bytes(padding_iv)
            if oracolo(iv_guess, block):
                if pad_val == 1:
                    padding_iv[-2] ^= 1
                    iv_guess = bytes(padding_iv)
                    if not oracolo(iv_guess, block):
                        continue  # false positive; keep searching
                break
        else:
            raise Exception("Nessun padding valido trovato")

        zeroing_iv[-pad_val] = candidate ^ pad_val    

    return bytes(zeroing_iv)


def oracolo(iv, ciphertext):
    try:
        oracle = AES.new(cipher.key, AES.MODE_CBC, iv)
        plaintext = oracle.decrypt(ciphertext)
        check_and_strip_padding(plaintext)
        return True  # Valid padding
    except ValueError:
        return False  # Invalid padding



if __name__ == "__main__":
    plaintext = "Stringa segretissima"
    ciphertext = cipher.encrypt(plaintext)
    print("Testo Ciff: ", ciphertext)

    msg = attack(ciphertext)
    
    print("Msg segreto: ", msg.decode('utf-8'))