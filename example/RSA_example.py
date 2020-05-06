# -*- coding: utf-8 -*-
"""
Created on Sun May 6 17:47:25 2020

Author: Prashant Kumar

"""

# In[]
import time
from securefile import Encrypt
from securefile.keyset import RSA_KEY

def main():
    rsa_key = RSA_KEY.genrate(11, 13)
    enc = Encrypt('test_file.txt', delimiter=':')
    enc.open()
    enc.rsa_encrypt(rsa_key, commit=False)
    enc.close()

if __name__ == '__main__':
    main()
