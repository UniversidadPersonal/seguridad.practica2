from Crypto.Random import get_random_bytes
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Util import Counter

class AES_CIPHER_ECB:

    BLOCK_SIZE_AES = 16 # AES: Bloque de 128 bits

    def __init__(self, key):
        self.key = key


    def cifrar(self, cadena):
        data = cadena.encode("utf-8")
        cipherAES = AES.new(self.key, AES.MODE_ECB)
        cyphertext = cipherAES.encrypt(pad(data,self.BLOCK_SIZE_AES))
        return cyphertext

    def descifrar(self, cifrado):
        decipherAES = AES.new(key, AES.MODE_ECB)
        decyphertext = unpad(decipherAES.decrypt(cifrado), self.BLOCK_SIZE_AES).decode("utf-8", "ignore")
        return decyphertext

key = get_random_bytes(16)  # Clave aleatoria de 128 bits
datos = "Hola amigas de la seguridad"
d = AES_CIPHER_ECB(key)
print('---- AES-CYPHER-ECB ----')
print(f' - Texto claro          - {datos}')
cifrado = d.cifrar(datos)
print(f' - Texto cifrado        - {cifrado}')
descifrado = d.descifrar(cifrado)
print(f' - Texto descifrado     - {descifrado}')
print('------------------------')


########################################################################################################################
########################################################################################################################
########################################################################################################################

class AES_CIPHER_CTR:

    BLOCK_SIZE_AES = 16  # AES: Bloque de 128 bits
    non = get_random_bytes(8)
    def __init__(self, key):
        self.key = key

    def cifrar(self, cadena):

        data = cadena.encode("utf-8")
        cipherAES = AES.new(self.key, AES.MODE_CTR, nonce=self.non)
        cyphertext = cipherAES.encrypt(pad(data, self.BLOCK_SIZE_AES))
        return cyphertext

    def descifrar(self, cifrado):

        decipherAES = AES.new(key, AES.MODE_CTR, nonce=self.non)
        decyphertext = unpad(decipherAES.decrypt(cifrado), self.BLOCK_SIZE_AES).decode("utf-8", "ignore")
        return decyphertext


key = get_random_bytes(16)  # Clave aleatoria de 128 bits
datos = "Hola amigas de la seguridad"
d = AES_CIPHER_CTR(key)
print('---- AES-CYPHER-CTR ----')
print(f' - Texto claro          - {datos}')
cifrado = d.cifrar(datos)
print(f' - Texto cifrado        - {cifrado}')
descifrado = d.descifrar(cifrado)
print(f' - Texto descifrado     - {descifrado}')
print('------------------------')

########################################################################################################################
########################################################################################################################
########################################################################################################################

class AES_CIPHER_OFB:

    BLOCK_SIZE_AES = 16  # AES: Bloque de 128 bits
    IV = get_random_bytes(16)

    def __init__(self, key):
        self.key = key

    def cifrar(self, cadena):

        #Si no indicamos el mismo IV al encrypt y al decrypt, nos dará soluciones distintas,
        # en cambio si usamos el mismo, nos dará la misma frase.
        data = cadena.encode("utf-8")
        cipherAES = AES.new(self.key, AES.MODE_OFB, self.IV)
        cyphertext = cipherAES.encrypt(pad(data, self.BLOCK_SIZE_AES))
        return cyphertext

    def descifrar(self, cifrado):

        decipherAES = AES.new(key, AES.MODE_OFB, self.IV)
        decyphertext = decipherAES.decrypt(cifrado).decode("utf-8", "ignore")
        return decyphertext


key = get_random_bytes(16)  # Clave aleatoria de 128 bits
datos = "Hola amigas de la seguridad"
d = AES_CIPHER_OFB(key)
print('---- AES-CYPHER-OFB ----')
print(f' - Texto claro          - {datos}')
cifrado = d.cifrar(datos)
print(f' - Texto cifrado        - {cifrado}')
descifrado = d.descifrar(cifrado)
print(f' - Texto descifrado     - {descifrado}')
print('------------------------')


########################################################################################################################
########################################################################################################################
########################################################################################################################

class AES_CIPHER_CFB:
    BLOCK_SIZE_AES = 16  # AES: Bloque de 128 bits
    IV = get_random_bytes(16)

    def __init__(self, key):
        self.key = key

    def cifrar(self, cadena):
        # Si no indicamos el mismo IV al encrypt y al decrypt, nos dará soluciones distintas,
        # en cambio si usamos el mismo, nos dará la misma frase.
        data = cadena.encode("utf-8")
        cipherAES = AES.new(self.key, AES.MODE_CFB)
        cyphertext = cipherAES.encrypt(pad(data, self.BLOCK_SIZE_AES))
        return cyphertext

    def descifrar(self, cifrado):
        decipherAES = AES.new(key, AES.MODE_CFB)
        decyphertext = decipherAES.decrypt(cifrado).decode("utf-8", "ignore")
        return decyphertext


key = get_random_bytes(16)  # Clave aleatoria de 128 bits
datos = "Hola amigas de la seguridad"
d = AES_CIPHER_OFB(key)
print('---- AES-CYPHER-CFB ----')
print(f' - Texto claro          - {datos}')
cifrado = d.cifrar(datos)
print(f' - Texto cifrado        - {cifrado}')
descifrado = d.descifrar(cifrado)
print(f' - Texto descifrado     - {descifrado}')
print('------------------------')

########################################################################################################################
########################################################################################################################
########################################################################################################################

class AES_CIPHER_GCM:
    BLOCK_SIZE_AES = 16  # AES: Bloque de 128 bits
    IV = get_random_bytes(16)

    def __init__(self, key):
        self.key = key

    def cifrar(self, cadena):
        # Si no indicamos el mismo IV al encrypt y al decrypt, nos dará soluciones distintas,
        # en cambio si usamos el mismo, nos dará la misma frase.
        data = cadena.encode("utf-8")
        cipherAES = AES.new(self.key, AES.MODE_GCM, self.IV, mac_len=16)
        cyphertext = cipherAES.encrypt(pad(data, self.BLOCK_SIZE_AES))
        return cyphertext

    def descifrar(self, cifrado):
        decipherAES = AES.new(key, AES.MODE_GCM, self.IV, mac_len=16)
        decyphertext = decipherAES.decrypt(cifrado).decode("utf-8", "ignore")
        return decyphertext


key = get_random_bytes(16)  # Clave aleatoria de 128 bits
datos = "Hola amigas de la seguridad"
d = AES_CIPHER_OFB(key)
print('---- AES-CYPHER-GCM ----')
print(f' - Texto claro          - {datos}')
cifrado = d.cifrar(datos)
print(f' - Texto cifrado        - {cifrado}')
descifrado = d.descifrar(cifrado)
print(f' - Texto descifrado     - {descifrado}')
print('------------------------')