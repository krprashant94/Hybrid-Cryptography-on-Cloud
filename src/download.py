# -*- coding: utf-8 -*-
"""
Created on Sun Oct 21 22:30:25 2018

Author: Prashant Kumar and Pamela Banerjee

"""

# In[]
from shutil import copyfile
from securefile import Encrypt
from securefile.keyset import RSA_KEY, DES_KEY, AES_KEY
from securefile.secureserial import SerialPort
# In[]
def main():
    """
    Entry point of program
    """
    file_name = 'test.md'

    copyfile( 'cloud/' + file_name, file_name)

    ser = SerialPort()
    ser.scan()
    ser.open('COM3')
    arduino_key = ser.read_key(console_log=True)
    ser.close()

    des_key = DES_KEY.genrate(arduino_key.des_key)
    aes_key = AES_KEY.genrate(arduino_key.aes_key)
    rsa_public_key = RSA_KEY.public_key_genrate(int(arduino_key.rsa_tuple[0]),
                                                int(arduino_key.rsa_tuple[1]))
    chiper_shift = int(arduino_key.shift)

    enc = Encrypt(file_name, delimiter=':')
    enc.open()

    enc.caesar_decipher(key_shift=chiper_shift, commit=True)
    enc.rsa_decrypt(rsa_public_key, commit=True)
    enc.des_decrypt(des_key, commit=True)
    enc.aes_decrypt(aes_key, commit=True)
    enc.base64_decrypt(commit=True)

    enc.close()

# In[]:
if __name__ == '__main__':
    main()
