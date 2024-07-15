from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import base64

def xor(b1, b2):
    """XOR operation tra due byte_arrays"""
    return bytearray([b1[i] ^ b2[i] for i in range(len(b1))])

class AES_MODE_CBC(object):
    def __init__(self, key=None, iv=None):

        #se la chiave non è fornita, genera una chiave casuale
        if key is None:
            key = get_random_bytes(32)
        self.key = key

        #se IV non è fornito, genera un IV casuale
        if iv is None:
            iv = get_random_bytes(16)
        self.iv = iv

    #funzione che aggiunge padding
    def _add_padding(self, data):
        #calcolo quanto padding aggiungere, in modulo 16
        padding = 16 - (len(data) % 16)
        return data + bytes([padding] * padding)

    #funzione per dividere i dati in 16 byte ciascuno
    def split_blocks(self, data):
        blocks = []
        for i in range(0, len(data), 16):
            blocks.append(data[i:i+16])
        return blocks

    #Funzione che cripta il plaintext
    def encrypt(self, plaintext):

        # se il testo è una stringa, la converto in byte
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # aggiungo padding
        plaintext = self._add_padding(plaintext)
        
        #divido in blocchi da 16 byte
        blocks = self.split_blocks(plaintext)
        
        # istanza di un cifrario AES con chiave e iv passati 
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        
        #inizializzo il testo cifrato con iv
        ciphertext = self.iv
        
        #assegno al blocco precedente IV, per poter eseguire la prima cifratura
        blocco_precedente = self.iv

        for block in blocks:

            #eseguo lo xor tra il blocco precedente e il blocco attuale, e cifro
            encrypted_block = cipher.encrypt(xor(blocco_precedente, block))
            #lo aggiungo a ciphertext
            ciphertext += encrypted_block
            # assegno a blocco_precedente il blocco attuale cifrato
            blocco_precedente = encrypted_block
        
        #codifico il testo in base64 e decodifico in UTF-8
        return base64.b64encode(ciphertext).decode('utf-8')
    
if __name__ == "__main__":
    cipher = AES_MODE_CBC()
    plaintext = "Questa è una stringa segreta"
    ciphertext = cipher.encrypt(plaintext)
    print("Stringa cifrata:", ciphertext)
    