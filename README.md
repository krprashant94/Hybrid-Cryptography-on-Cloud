# Hybrid Cryptography on Cloud

A python package for hybrid file encryption and decryption. securefile is for n-layer file encryption. This package provides a basic two-way encryption algorithm for a file. It supports approximately all kind of file encoding. The package provides RSA, DES, AES and Shift Cipher and base64 algorithm for file encoding and decoding.

[Full Documantaion](https://www.sixpetal.com/securefile)


## Installation
type `pip install securefile` to install this package in native python

##### Dependency
 - pyserial (use `pip install pyserial` for native python or `conda install -c anaconda pyserial` for anaconda python)




## Uses

```python
import time
from securefile import Encrypt
from securefile.keyset import RSA_KEY, DES_KEY, AES_KEY
from securefile.secureserial import SerialPort

ser = SerialPort()
ser.scan()
ser.open('COM3')
arduino_key = ser.read_key(console_log=True)
ser.close()

des_key = DES_KEY.genrate(arduino_key.des_key)
aes_key = AES_KEY.genrate(arduino_key.aes_key)
rsa_public_key = RSA_KEY.public_key_genrate(int(arduino_key.rsa_tuple[0]),
                                            int(arduino_key.rsa_tuple[1]))
rsa_private_key = RSA_KEY.private_key_genrate(6861, 57067)
chiper_shift = int(arduino_key.shift)

enc = Encrypt('test.md', delimiter=':')
enc.open()

start_time = time.time()

enc.base64_encrypt()
enc.aes_encrypt(aes_key, commit=True)
enc.des_encrypt(des_key, commit=True)
enc.rsa_encrypt(rsa_private_key, commit=True)
enc.caesar_cipher(key_shift=chiper_shift, commit=True)

encode_time = time.time() - start_time
print("--- %s seconds ---" % str(encode_time))

enc.caesar_decipher(key_shift=chiper_shift, commit=True)
enc.rsa_decrypt(rsa_public_key, commit=True)
enc.des_decrypt(des_key, commit=True)
enc.aes_decrypt(aes_key, commit=True)
enc.base64_decrypt(commit=True)

decode_time = time.time() - start_time
print("--- %s seconds ---" % (decode_time))

with open("cipher.csv", "a", encoding="utf8") as file:
    file.write(str(len(enc.get_text())) + ','+ str(encode_time) + ','+ str(decode_time) + ",\n")
    file.close()

enc.close()
```
Output
```
TODO: todo
```

## Wiki

#### Data Encryption Standard (DES) Algorithm

The Data Encryption Standard (DES) is a symmetric-key block cipher published by the National Institute of Standards and Technology (NIST). DES is an implementation of a Feistel Cipher. It uses 16 round Feistel structure. The block size is 64-bit. Though, key length is 64-bit, DES has an effective key length of 56 bits, since 8 of the 64 bits of the key are not used by the encryption algorithm.

#### RSA Algorithm

RSA algorithm is a public key encryption technique and is considered as the most secure way of encryption.
RSA algorithm is asymmetric cryptography algorithm. Asymmetric actually means that it works on two different keys i.e. Public Key and Private Key. As the name describes that the Public Key is given to everyone and Private key is kept private.

#### Advanced Encryption Standard (AES) Algorithm

The more popular and widely adopted symmetric encrypt algorithm likely to be encountered nowadays is the Advanced Encryption Standard (AES). It is found at least six time faster than triple DES.
A replacement for DES was needed as its key size was too small. With increasing computing power, it was considered vulnerable against exhaustive key search attack. Triple DES was designed to overcome this drawback but it was found slow.

#### Base64

Base64 encoding schemes are commonly used when there is a need to encode binary data that needs be stored and transferred over media that are designed to deal with textual data. This is to ensure that the data remains intact without modification during transport.

## Cite

##### A Survey on Performance Analysis of DES, AES and RSA Algorithm along with LSB Substitution Technique:

    Padmavathi, B. and S. Ranjitha Kumari. 
    "A Survey on Performance Analysis of DES , AES and RSA Algorithm along with LSB Substitution Technique."
    2013.

###### pydes Project
    [Pydes by RobinDavid](https://github.com/RobinDavid/pydes)

    
##### Secure File storage in Cloud Computing using Hybrid Cryptography Algorithm
    P. V. Maitri and A. Verma, "Secure file storage in cloud computing using hybrid cryptography algorithm," 2016 International Conference on Wireless Communications, Signal Processing and Networking (WiSPNET), Chennai, 2016, pp. 1635-1638.
    doi: 10.1109/WiSPNET.2016.7566416
    URL: http://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=7566416&isnumber=7566075
