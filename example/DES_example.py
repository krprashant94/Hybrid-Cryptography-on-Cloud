# -*- coding: utf-8 -*-
"""
Created on Sun May 6 17:47:25 2020

Author: Prashant Kumar

"""

# In[]
import time
from securefile import Encrypt
from securefile.keyset import DES_KEY

def main():
    des_key = DES_KEY.genrate("123456789")
    enc = Encrypt('test_file.txt', delimiter=':')
    enc.open()
    enc.des_encrypt(des_key, commit=True)
    enc.close()

if __name__ == '__main__':
    main()
