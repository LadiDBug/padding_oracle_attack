from aes_encryption import AES_MODE_CBC
import base64
from Crypto.Cipher import AES

#inizializzo un'istanza di AES_MODE_CBC
cipher = AES_MODE_CBC()

def check_and_strip_padding(data):

    # lunghezza del padding ottenuta dall'ultimo byte dei dati
    padding_len = data[-1]

    #controllo se la lunghezza del padding è valida
    if padding_len < 1 or padding_len > 16:
        raise ValueError("Lunghezza padding non valida!")
    
    #verifico ch eil padding sia corretto
    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Padding non corretto!")
    
    #rimuvo il padding dai dati
    return data[:-padding_len]


# Funzione che esegue l'attacco
def attack(ciphertext):
    #preparo i dati
    ciphertext = base64.b64decode(ciphertext)
    blocks = cipher.split_blocks(ciphertext)
    
    #vettore di inizializzazione
    iv = blocks[0]

    # i blocchi cifrati sono dall'1 in poi
    blocks = blocks[1:]

    plaintext = b''

    #eseguo l'attacco per ogni blocco
    for i, block in enumerate(blocks):
        
        #passo il blocco alla funzione decifra blocco
        blocco_decifrato = decifra_blocco(block)

        #metto il blocco decifrato nel plaintext
        plaintext += blocco_decifrato

        #aggiorno iv
        iv = blocks[i]  

    #ritorno il plaintext senza padding
    return check_and_strip_padding(plaintext)   

# Funzione che si occupa di decifrare un singolo blocco
def decifra_blocco(block):

    # inizializzo un IV con tutti zero
    iv_prova = [0] * 16

    for pad_val in range(1, 16 + 1):

        # creo un IV con il padding corrente 
        padding_iv = [pad_val ^ b for b in iv_prova]

        for candidate in range(256):

            #modifico il byte dell'IV che corrisponde al padding corrente
            padding_iv[-pad_val] = candidate
            iv_guess = bytes(padding_iv)

            # verifico se IV ipotizzato produce un padding valido
            if oracolo(iv_guess, block):
                if pad_val == 1:
                    #devo verificare anche se è un falso positivo
                    padding_iv[-2] ^= 1
                    iv_guess = bytes(padding_iv)
                    if not oracolo(iv_guess, block):
                        continue  # se falso positivo, continua
                break
        else:
            #se non si riesce a trovare un padding valido, c'è eccezzione
            raise Exception("Nessun padding valido trovato")

        #memorizzo il valore che sono riuscita a decifrare nell'IV di prova 
        iv_prova[-pad_val] = candidate ^ pad_val    

    # alla fine ritorno il blocco decifrato
    return bytes(iv_prova)


def oracolo(iv, ciphertext):
    try:
        #oracle = una istanza del cifrario AES, con IV ipotizzato
        oracle = AES.new(cipher.key, AES.MODE_CBC, iv)

        # provo a decifrare
        plaintext = oracle.decrypt(ciphertext)

        #controllo se padding corretto
        check_and_strip_padding(plaintext)

        #True se padding valido
        return True  
    
    #altrimenti padding non valido
    except ValueError:
        return False  



if __name__ == "__main__":
    plaintext = "Questa è una stringa super segreta"
    ciphertext = cipher.encrypt(plaintext)
    print("Testo Cifrato:", ciphertext)

    msg = attack(ciphertext)
    
    print("Msg segreto:", msg.decode('utf-8'))