# -*- coding: utf-8 -*-
"""
Created on Sun May 6 17:47:25 2020

Author: Prashant Kumar

"""

# In[]
import time
from securefile import Encrypt
from securefile.keyset import AES_KEY

def main():
    aes_key = AES_KEY.genrate("000102030405060708090a0b0c0d0e0f")
    enc = Encrypt('test_file.txt', delimiter=':')
    enc.open()
    enc.aes_encrypt(aes_key, commit=True)
    enc.close()

if __name__ == '__main__':
    main()
