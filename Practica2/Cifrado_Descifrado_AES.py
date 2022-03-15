from Crypto.Random import get_random_bytes
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Util import Counter


key = get_random_bytes(16)
IV = get_random_bytes(16)
datos = "Hola amigas de la seguridad".encode("utf-8")
BLOCK_SIZE_AES = 16

print(f' - Texto plano      - {datos}')

#Cifrado
cipher_AES = AES.new(key, AES.MODE_CBC, IV)
ciphertext = cipher_AES.encrypt(pad(datos,BLOCK_SIZE_AES))

print(f' - Texto cifrado    - {ciphertext}')

#Descifrado
decipher_AES = AES.new(key, AES.MODE_CBC, IV)
deciphertext = unpad(decipher_AES.decrypt(ciphertext), BLOCK_SIZE_AES).decode("utf-8", "ignore")

print(f' - Texto descifrado - {deciphertext}')
print(deciphertext)

