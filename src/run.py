# -*- coding: utf-8 -*-
"""
Created on Sun Oct 21 22:30:25 2018

Author: Prashant Kumar and Pamela Banerjee

"""

# In[]
import time
from securefile import Encrypt
from securefile.keyset import RSA_KEY, DES_KEY, AES_KEY
from securefile.secureserial import SerialPort
# In[]
def main():
    """
    Entry point of program
    """
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
    
    # enc.base64_encrypt()
    # enc.aes_encrypt(aes_key, commit=False)
    # enc.des_encrypt(des_key, commit=False)
    # enc.rsa_encrypt(rsa_private_key, commit=False)
    # enc.caesar_cipher(key_shift=chiper_shift, commit=False)
    
    encode_time = time.time() - start_time
    print("--- %s seconds ---" % str(encode_time))

    enc.caesar_decipher(key_shift=chiper_shift, commit=False)
    enc.rsa_decrypt(rsa_public_key, commit=False)
    enc.des_decrypt(des_key, commit=False)
    enc.aes_decrypt(aes_key, commit=False)
    enc.base64_decrypt(commit=True)
    
    decode_time = time.time() - start_time
    print("--- %s seconds ---" % (decode_time))
    
    with open("cipher.csv", "a", encoding="utf8") as file:
        file.write(str(len(enc.get_text())) + ','+ str(encode_time) + ','+ str(decode_time) + "\n")
        file.close()

    enc.close()

# In[]:
if __name__ == '__main__':
    main()
