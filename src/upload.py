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
    copyfile(file_name, 'cloud/' + file_name)

    ser = SerialPort()
    ser.scan()
    ser.open('COM3')
    arduino_key = ser.read_key(console_log=True)
    ser.close()

    des_key = DES_KEY.genrate(arduino_key.des_key)
    aes_key = AES_KEY.genrate(arduino_key.aes_key)
    rsa_private_key = RSA_KEY.private_key_genrate(6861, 57067)
    chiper_shift = int(arduino_key.shift)

    enc = Encrypt('cloud/' + file_name, delimiter=':')
    enc.open()

    enc.base64_encrypt()
    enc.aes_encrypt(aes_key, commit=True)
    enc.des_encrypt(des_key, commit=True)
    enc.rsa_encrypt(rsa_private_key, commit=True)
    enc.caesar_cipher(key_shift=chiper_shift, commit=True)

    enc.close()

# In[]:
if __name__ == '__main__':
    main()
