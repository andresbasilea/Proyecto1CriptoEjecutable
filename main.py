# pip install xlwings
# pip install cffi
# pip install cryptography==3.3.2
# pip install scrypt
# pip install time
# pip install pycryptodome
# pip install pycryptodomex

# Proyecto 1: Criptografía


# Each algorithm is used for some goal; therefore, you need to compare only the ones that
# share such a goal. For example, if you want to compare hashing algorithms you compare
# the efficiency of SHA-2 and SHA-3 by using the same input testing vector.

# Following this idea, you need to create a table or a graph comparing the efficiency of these
# algorithms for the following operations:
#    Encryption
#    Decryption
#    Hashing
#    Signing
#    Verifying

# After the execution of your program, you should show the results for each operation. These
# should be presented using a visual component (i.e., a table, a graph). Coming back to the
# hashing example, after the execution of all hashing algorithms with all the hashing vectors,
# you could show a table similar to the following or a graph that can show your results.


# Chacha20 Key Size 256 bits
# AES-EBC Key Size 256 bits
# AES-GCM Key size 256 bits
# SHA-2 Hash size 512 bits
# SHA-3 Hash size 512 bits
# Scrypt Output size 32 bits
# RSA-OAEP 2048 bits
# RSA-PSS 2048 bits
# ECDSA ECDSA, 521 Bits (P-521)
# EdDSA ECDSA, 32 Bits (Curve25519)

# import os # Para llaves
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import timeit # time

import xlwings as xw
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# from Cryptodome.Protocol.KDF import scrypt

from Crypto.Hash import SHA3_512 


# SHA-2 y 3
import hashlib




# x = input("Presione enter para ejecutar el código...")

df_cifrado = pd.DataFrame(columns=['Chacha20', 'AES-EBC', 'AES-GCM', 'RSA-OAEP'])
df_descifrado = pd.DataFrame(columns=['Chacha20', 'AES-EBC', 'AES-GCM', 'RSA-OAEP'])

df_hash = pd.DataFrame(columns=['SHA-2', 'SHA-3', 'Scrypt'])

df_firma = pd.DataFrame(columns=['RSA-PSS', 'ECDSA', 'EdDSA'])
df_verifica = pd.DataFrame(columns=['RSA-PSS', 'ECDSA', 'EdDSA'])




# HASHING


ws = xw.Book("CriptoTestVectors.xlsx").sheets['VECTORES']
plaintext = ws.range("B22:B26").value

salt = 'NaCl'

# SHA-2 Hash size 512 bits
def sha512_hash(plaintext):
	# SHA - 2   512
	sha512 = hashlib.sha512()
	# Update the hash object with your message
	sha512.update(plaintext)
	# Get the digest of the hash object (i.e. the hash value)
	hash_value = sha512.digest()
	# Print the hash value as a hexadecimal string
	hex_hash_value = hash_value.hex()
	#print(hex_hash_value)

# SHA-3 Hash size 512 bits
def sha3_512_hash(plaintext):
	# SHA - 3   512
	sha3_512 = SHA3_512.new()
	# Update the hash object with your message
	sha3_512.update(plaintext)
	# Get the digest of the hash object (i.e. the hash value)
	hash_value = sha3_512.digest()

	# Print the hash value as a hexadecimal string
	hex_hash_value = hash_value.hex()
	#print(hex_hash_value)

	
# Scrypt Output size 32 bits
def scrypt_key(plaintext, salt):
	N = 16384
	r = 8
	p = 1
	dk_len = 32
	salt = b'NaCl'
	# Generate the derived key using Scrypt
	dk = Scrypt(salt=salt, n=N, r=r, p=p, length=dk_len)
	dk = dk.derive(plaintext)
	#key = scrypt(plaintext, salt, key_len=32, N=2**14, r=8, p=1)
	#return key


print(".")
for i in range(1000):
	df_hash.loc[i] = [None, None, None]   #Inicializar dataframe
	
for j in range(5):
	for i in range(200):
		t = timeit.timeit(lambda: sha512_hash(bytes(plaintext[j],'utf-8')), number=1)
		df_hash.loc[i+(j*200),'SHA-2'] = '{:.10f}'.format(t)
	
for j in range(5):
	for i in range(200):
		t = timeit.timeit(lambda: sha3_512_hash(bytes(plaintext[j],'utf-8')), number=1)
		df_hash.loc[i+(j*200),'SHA-3'] = '{:.10f}'.format(t)
	
for j in range(5):
	for i in range(200):
		t = timeit.timeit(lambda: scrypt_key(bytes(plaintext[j],'utf-8'), salt), number=1)
		df_hash.loc[i+(j*200),'Scrypt'] = '{:.10f}'.format(t)


		

print(df_hash)
		
df_hash2 = df_hash.astype(float)
df_mean_hash2 = df_hash2.mean()
print('Media: \n',df_hash2.mean(), '\n\n')
print('Desviación estándar: \n', df_hash2.std())

df_mean_hash2.plot.bar()
plt.show()


df_hash2.plot()
plt.show()


df_mean_sha2sha3 = df_mean_hash2[['SHA-2', 'SHA-3']].copy()
df_mean_sha2sha3.plot.bar()
plt.show()

df_mean_sha2sha3 = df_hash2[['SHA-2', 'SHA-3']].copy()
df_mean_sha2sha3.plot()
plt.show()






# CIFRADO Y DESCIFRADO


###################################################################

ciphertexts = {'chacha':[], 'aesecb':[], 'aesgcm':[], 'rsa':[]}
chacha = None

# Chacha20 Key Size 256 bits
def chacha20_encrypt(key, nonce, plaintext):
	global chacha
	# Create a ChaCha20 cipher object
	chacha = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
	# Create a ChaCha20 encryptor object
	encryptor = chacha.encryptor()
	# Encrypt plaintext
	ciphertext = encryptor.update(plaintext)
	# print(ciphertext.hex())
	ciphertexts['chacha'].append(ciphertext.hex())
	return ciphertext

def chacha20_decrypt(key, ciphertext):
	global chacha
	# Create a ChaCha20 decryptor object
	#chacha = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
	decryptor = chacha.decryptor()
	# Decrypt ciphertext
	decrypted_text = decryptor.update(ciphertext)
	return plaintext


# AES-EBC Key Size 256 bits
def aes_ecb_encrypt(key, nonce, plaintext):
	aes_cipher = Cipher(algorithms.AES(key), mode=modes.ECB(), backend=default_backend())
	encryptor = aes_cipher.encryptor()
	ciphertext = encryptor.update(plaintext)
	#print(ciphertext.hex())
	ciphertexts['aesecb'].append(ciphertext.hex())
	return ciphertext

def aes_ecb_decrypt(key, ciphertext):
	aes_cipher = Cipher(algorithms.AES(key), mode=modes.ECB(), backend=default_backend())
	decryptor = aes_cipher.decryptor()
	plaintext = decryptor.update(ciphertext)
	#print(plaintext.hex())
	return plaintext

# AES-GCM Key size 256 bits
def aes_gcm_encrypt(key, nonce, plaintext):
	aesgcm_cipher = AESGCM(key)
	# Encrypt plaintext
	ciphertext = aesgcm_cipher.encrypt(nonce, plaintext, associated_data=None)
	#print(ciphertext.hex())
	ciphertexts['aesgcm'].append(ciphertext.hex())
	return ciphertext

def aes_gcm_decrypt(key,ciphertext, nonce):
	aesgcm_cipher = AESGCM(key)
	plaintext = aesgcm_cipher.decrypt(nonce, ciphertext, associated_data=None)
	#print(ciphertext.hex())
	return plaintext



# RSA - OAEP 2048 bits

# Generate a new RSA key pair with a key size of 2048 bits
private_key = rsa.generate_private_key(
	public_exponent=65537,
	key_size=2048,
	backend=default_backend()
)
public_key = private_key.public_key()
private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)


def rsa_oaep_encrypt(public_key,plaintext):
	ciphertext = public_key.encrypt(
		plaintext,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)
	return ciphertext


def rsa_oaep_decrypt(private_key, ciphertext):
	# Decrypt the ciphertext using the private key
	plaintext = private_key.decrypt(
		ciphertext,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)
	return plaintext

#################################################################




for i in range(1000):
	df_cifrado.loc[i] = [None, None, None, None]   #Inicializar dataframe
	df_descifrado.loc[i] = [None, None, None, None]


# Cifrado
	
# AES_EBC
# # Specifying a sheet
ws = xw.Book("CriptoTestVectors.xlsx").sheets['VECTORES']
AES_ECBkeys = ws.range("B6:B15").value
#print(AES_ECBkeys)
AES_plaintext = ws.range("C6:C15").value
#print(AES_plaintext)
#print(bytes.fromhex(AES_plaintext))

#para vectores de AES_EBC:
for j in range(10):
	for i in range(100):
		t = timeit.timeit(lambda: aes_ecb_encrypt(bytes.fromhex(AES_ECBkeys[j]),0,bytes.fromhex(AES_plaintext[j])), number=1)
		df_cifrado.loc[i+(j*100),'AES-EBC'] = '{:.10f}'.format(t)
		

		
		
		
# AES_GCM
# # Specifying a sheet
ws = xw.Book("CriptoTestVectors.xlsx").sheets['VECTORES']
AES_GCMkeys = ws.range("B6:B15").value
AES_GCMplaintext = ws.range("C6:C15").value
AES_GCMnonce = ws.range("D6:D15").value

#para vectores de AES_EBC:
for j in range(10):
	for i in range(100):
		t = timeit.timeit(lambda: aes_gcm_encrypt(bytes.fromhex(AES_GCMkeys[j]),bytes.fromhex(AES_GCMnonce[j]),bytes.fromhex(AES_GCMplaintext[j])), number=1)
		df_cifrado.loc[i+(j*100),'AES-GCM'] = '{:.10f}'.format(t)
		



# CHACHA20
# # Specifying a sheet
ws = xw.Book("CriptoTestVectors.xlsx").sheets['VECTORES']
CHACHA_keys = ws.range("B6:B15").value
CHACHA_plaintext = ws.range("C6:C15").value
CHACHA_nonce = ws.range("D6:D15").value

#para vectores de CHACHA20:
for j in range(10):
	for i in range(100):
		t = timeit.timeit(lambda: chacha20_encrypt(bytes.fromhex(CHACHA_keys[j]),bytes.fromhex(CHACHA_nonce[j]),bytes.fromhex(CHACHA_plaintext[j])), number=1)
		df_cifrado.loc[i+(j*100),'Chacha20'] = '{:.10f}'.format(t)

		
		
# RSA_OAEP
# # Specifying a sheet
ws = xw.Book("CriptoTestVectors.xlsx").sheets['VECTORES']
RSA_OAEP_plaintext = ws.range("C6:C15").value

#para vectores de RSA_OAEP:
for j in range(10):
	for i in range(100):
#         ciphertext = rsa_oaep_encrypt(public_key, bytes.fromhex(RSA_OAEP_plaintext[j]))
#         print(ciphertext)
		t = timeit.timeit(lambda: rsa_oaep_encrypt(public_key, bytes.fromhex(RSA_OAEP_plaintext[j])), number=1)
		df_cifrado.loc[i+(j*100),'RSA-OAEP'] = '{:.10f}'.format(t)
	
		
		
		
print(df_cifrado)
		
df_cifrado2 = df_cifrado.astype(float)
df_mean_cifrado2 = df_cifrado2.mean()
print('Media: \n',df_cifrado2.mean(), '\n\n')
print('Desviación estándar: \n', df_cifrado2.std())

df_mean_cifrado2.plot.bar()
plt.show()


df_cifrado2.plot()
plt.show()




# Descifrado


# AES_EBC
# # Specifying a sheet
ws = xw.Book("CriptoTestVectors.xlsx").sheets['VECTORES']
AES_ECBkey = ws.range("B6:B15").value
AES_ECBcipher = ws.range("J6:J15").value
#print(AES_ECBcipher)

#para vectores de AES_EBC:
for j in range(10):
	for i in range(100):
		t = timeit.timeit(lambda: aes_ecb_decrypt(bytes.fromhex(AES_ECBkey[j]),bytes.fromhex(AES_ECBcipher[j])), number=1)
		df_descifrado.loc[i+(j*100),'AES-EBC'] = '{:.10f}'.format(t)
		

		
# AES_GCM
# # Specifying a sheet
ws = xw.Book("CriptoTestVectors.xlsx").sheets['VECTORES']
AES_GCMkey = ws.range("B6:B15").value
AES_GCMnonce = ws.range("D6:D15").value
AES_GCMcipher = ws.range("K6:K15").value

#para vectores de AES_gcm:
for j in range(10):
	for i in range(100):
		t = timeit.timeit(lambda: aes_gcm_decrypt(bytes.fromhex(AES_GCMkey[j]),bytes.fromhex(AES_GCMcipher[j]), bytes.fromhex(AES_GCMnonce[j])), number=1)
		df_descifrado.loc[i+(j*100),'AES-GCM'] = '{:.10f}'.format(t)
		
		
		
# CHACHA
# # Specifying a sheet
ws = xw.Book("CriptoTestVectors.xlsx").sheets['VECTORES']
CHACHA_key = ws.range("B6:B15").value
CHACHA_cipher = ws.range("I6:I15").value


#para vectores de chacha:
for j in range(10):
	for i in range(100):
		t = timeit.timeit(lambda: chacha20_decrypt(bytes.fromhex(CHACHA_key[j]),bytes.fromhex(CHACHA_cipher[j])), number=1)
		df_descifrado.loc[i+(j*100),'Chacha20'] = '{:.10f}'.format(t)
		   

#para vectores de RSA_OAEP:
for j in range(10):
	for i in range(100):
		ciphertext = rsa_oaep_encrypt(public_key, bytes.fromhex(RSA_OAEP_plaintext[j]))
		t = timeit.timeit(lambda: rsa_oaep_decrypt(private_key, ciphertext), number=1)
		#t = timeit.timeit(lambda: rsa_oaep_decrypt(private_key, bytes.fromhex(RSA_OAEP_cipher[j])), number=1)
		#t = timeit.timeit(lambda: rsa_oaep_decrypt(private_key, RSA_OAEP_cipher[j]), number=1)
		df_descifrado.loc[i+(j*100),'RSA-OAEP'] = '{:.10f}'.format(t)        
		
		
		
		
			  
		
print(df_descifrado)
		
df_descifrado2 = df_descifrado.astype(float)
df_mean_descifrado2 = df_descifrado2.mean()
print('Media: \n',df_descifrado2.mean(), '\n\n')
print('Desviación estándar: \n', df_descifrado2.std())

df_mean_descifrado2.plot.bar()
plt.show()


df_descifrado2.plot()
plt.show()

	




# FIRMA DIGITAL

# RSA - PSS 2048


# message =  b'To see a World in a Grain of Sand'

ws = xw.Book("CriptoTestVectors.xlsx").sheets['VECTORES']
message = ws.range("B22:B26").value

##### RSA PSS
# Generate a new RSA key pair with a key size of 2048 bits
private_key = rsa.generate_private_key(
		public_exponent=65537,
		key_size=2048,
		backend=default_backend()
	)
public_key = private_key.public_key()

# Firmar un mensaje con RSA-PSS
def rsa_pss_sign(message):
	# Sign a message using the private key and RSA-PSS signature padding
	signature = private_key.sign(
		message,
		#PADDING DE PSS
		padding.PSS(
			mgf=padding.MGF1(hashes.SHA256()),
			salt_length=padding.PSS.MAX_LENGTH
		),
		hashes.SHA256()
	)
	return signature

def rsa_pss_verify_sign(message, signature, public_key):
	# Verify the signature using the public key and RSA-PSS signature padding
	try:
		public_key.verify(
			signature,
			message,
			padding.PSS(
				mgf=padding.MGF1(hashes.SHA256()),
				salt_length=padding.PSS.MAX_LENGTH
			),
			hashes.SHA256()
		)
		#print("Signature is valid")
	except:
		return
		#print("Signature is invalid")






##### ECDSA

# Generate a new EC key pair with a curve size of 521 bits (P-521)
private_key_ecdsa = ec.generate_private_key(
	ec.SECP521R1(),
	backend=default_backend()
)
public_key_ecdsa = private_key_ecdsa.public_key()


# Firmar un mensaje con ECDSA
def ecdsa_sign(message, private_key_ecdsa):
	signature_ecdsa = private_key_ecdsa.sign(
	message,
	ec.ECDSA(hashes.SHA256())
	)
	return signature_ecdsa

# Verificar la firma con ECDSA
def ecdsa_verify_sign(message, signature_ecdsa, public_key_ecdsa):
	# Verify the signature using the public key and ECDSA signature algorithm
	try:
		public_key_ecdsa.verify(
			signature_ecdsa,
			message,
			ec.ECDSA(hashes.SHA256())
		)
		#print("Signature is valid")
	except:
		return
		#print("Signature is invalid")
		
		
		
		
		
##### EdDSA

# Generate a new Ed25519 key pair
private_key_eddsa = Ed25519PrivateKey.generate()
public_key_eddsa = private_key_eddsa.public_key()


# Firmar un mensaje con EdDSA
def eddsa_sign(message, private_key_eddsa):
	signature_eddsa = private_key_eddsa.sign(message)
	return signature_eddsa

# Verificar la firma con EdDSA
def eddsa_verify_sign(message, signature_eddsa, public_key_eddsa):
	# Verify the signature using the public key and Ed25519 signature algorithm
	try:
		public_key_eddsa.verify(
			signature_eddsa,
			message
		)
		#print("Signature is valid")
	except:
		return
		#print("Signature is invalid")






		
		
		
for i in range(1000):
	df_firma.loc[i] = [None, None, None]   #Inicializar dataframe
	df_verifica.loc[i] = [None,None,None]

	
	
# RSA PSS
for j in range(5):
	for i in range(200):
		t = timeit.timeit(lambda: rsa_pss_sign(bytes(message[j],'utf-8')), number=1)
		df_firma.loc[i+(j*200),'RSA-PSS'] = '{:.10f}'.format(t)

for j in range(5):
	for i in range(200):
		signature = rsa_pss_sign(bytes(message[j],'utf-8'))
		t = timeit.timeit(lambda: rsa_pss_verify_sign(bytes(message[j],'utf-8'),signature,public_key ), number=1)
		df_verifica.loc[i+(j*200),'RSA-PSS'] = '{:.10f}'.format(t)


	
# ECDSA

for j in range(5):
	for i in range(200):
		t = timeit.timeit(lambda: ecdsa_sign(bytes(message[j],'utf-8'), private_key_ecdsa), number=1)
		df_firma.loc[i+(j*200),'ECDSA'] = '{:.10f}'.format(t)

for j in range(5):
	for i in range(200):
		signature = ecdsa_sign(bytes(message[j],'utf-8'), private_key_ecdsa)
		t = timeit.timeit(lambda: ecdsa_verify_sign(bytes(message[j],'utf-8'),signature,public_key_ecdsa ), number=1)
		df_verifica.loc[i+(j*200),'ECDSA'] = '{:.10f}'.format(t)

	
	
# EdDSA

for j in range(5):
	for i in range(200):
		t = timeit.timeit(lambda: eddsa_sign(bytes(message[j],'utf-8'), private_key_eddsa), number=1)
		df_firma.loc[i+(j*200),'EdDSA'] = '{:.10f}'.format(t)

for j in range(5):
	for i in range(200):
		signature_eddsa = eddsa_sign(bytes(message[j],'utf-8'), private_key_eddsa)
		t = timeit.timeit(lambda: eddsa_verify_sign(bytes(message[j],'utf-8'),signature_eddsa,public_key_eddsa ), number=1)
		df_verifica.loc[i+(j*200),'EdDSA'] = '{:.10f}'.format(t)
	
	
	
	

print(df_firma)
		
df_firma2 = df_firma.astype(float)
df_mean_firma2 = df_firma2.mean()
print('Media: \n',df_firma2.mean(), '\n\n')
print('Desviación estándar: \n', df_firma2.std())

df_mean_firma2.plot.bar()
plt.show()


df_firma2.plot()
plt.show()




print(df_verifica)
		
df_verifica2 = df_verifica.astype(float)
df_mean_verifica2 = df_verifica2.mean()
print('Media: \n',df_verifica2.mean(), '\n\n')
print('Desviación estándar: \n', df_verifica2.std())

df_mean_verifica2.plot.bar()
plt.show()


df_verifica2 = df_verifica2.drop(df_verifica2["ECDSA"].idxmax())
df_verifica2.plot()
plt.show()




# x = input("presione enter para salir...")

