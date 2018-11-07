# -*- coding: utf-8 -*-
# pylint: disable=R0201
# pylint: disable=E1133
# pylint: disable=R1705
# pylint: disable=C0200
# coding: utf-8
#Created on Sun Oct 21 22:30:25 2018
#Author Prashant

"""
Data Encryption Standard (DES) Algorithm
-----------------------------------------
The Data Encryption Standard (DES) is a symmetric-key block cipher published by
the National Institute of Standards and Technology (NIST).
DES is an implementation of a Feistel Cipher.
It uses 16 round Feistel structure.
The block size is 64-bit. Though, key length is 64-bit,
DES has an effective key length of 56 bits, since 8 of the 64 bits
of the key are not used by the encryption algorithm
(function as check bits only).

`Pydes <https://github.com/RobinDavid/pydes>`_

Example Code ::

    key = "12345678"
    text = "Hello wo11"
    print("Ciphered: ", encrypt(key, text))
    print("Deciphered: ", decrypt(key, encrypt(key, text)))

Output ::

    Ciphered:  #####
    Deciphered:  Hello wo11
"""
### Matrix and dataset

# In[1]:


#-*- coding: utf8 -*-

#Initial permut matrix for the datas
PI = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

#Initial permut made on the key
CP_1 = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]

#Permut applied on shifted key to get Ki+1
CP_2 = [14, 17, 11, 24, 1, 5, 3, 28,
        15, 6, 21, 10, 23, 19,
        12, 4,
        26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32]

#Expand matrix to get a 48bits matrix of datas to apply the xor with Ki
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

#SBOX
S_BOX = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
          [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
          [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
          [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],],
         [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
          [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
          [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
          [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],],
         [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
          [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
          [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
          [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],],
         [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
          [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
          [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
          [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],],
         [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
          [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
          [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
          [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],],
         [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
          [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
          [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
          [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],],
         [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
          [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
          [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
          [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],],
         [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
          [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
          [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
          [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],]]

#Permut made after each SBox substitution for each round
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

#Final permut for datas after the 16 rounds
PI_1 = [40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25]

#Matrix that determine the shift for each round of keys
SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


# ### Constant

# In[2]:


ENCRYPT = 1
DECRYPT = 0


# ### Function

# In[3]:


def string_to_bit_array(text):
    """
    Convert a string into a list of bits
    """
    array = list()
    for char in text:
        binval = binvalue(char, 8)#Get the char value on one byte
        array.extend([int(x) for x in list(binval)]) #Add the bits to the final list
    return array

def bit_array_to_string(array):
    """
    Recreate the string from the bit array
    """
    res = ''.join(
        [chr(int(y, 2)) for y in [''.join([str(x) for x in bytes]) for bytes in  nsplit(array, 8)]])
    return res

def binvalue(val, bitsize):
    """
    Return the binary value as a string of the given size
    """
    binval = bin(val)[2:] if isinstance(val, int) else bin(ord(val))[2:]
    if len(binval) > bitsize:
        raise ValueError("binary value larger than the expected size")
    while len(binval) < bitsize:
        binval = "0"+binval #Add as many 0 as needed to get the wanted size
    return binval

def nsplit(s_s, n_s):
    """
    Split a list into sublists of size "n_s"
    """
    return [s_s[k:k+n_s] for k in range(0, len(s_s), n_s)]


# ### DES class

# In[4]:


class DES():
    """
    Data Encryption Standard Object
    -----------------------------------
    The Data Encryption Standard (DES) is a symmetric-key block cipher published
    by the National Institute of Standards and Technology (NIST).

    :Method:
        - __init__()
        - run()
        - substitute()
        - permut()
        - expand()
        - xor()
        - generatekeys()
        - shift()
        - add_padding()
        - remove_padding()
        - encrypt()
        - decrypt()
    :Attributes:
        - password = None
        - text = None
        - keys = list()
    """
    def __init__(self):
        """
        __init__()
        --------------
        :return: None
        :raises: None
        """
        self.password = None
        self.text = None
        self.keys = list()

    def run(self, key, text, action=ENCRYPT, padding=False):
        """
        Core function for encryption and dedcryption

        :param str key: Encryption/Decryption key.
        :param str text: Message or plain/cipher Text.
        :param ENCRYPT|DECRYPT action=ENCRYPT: Encryption or Decryption action.   
        :param bool padding=False: True|False
        :return: Encrypted/Decrypted Message
        :raises ValueError: Key Should be 8 bytes long
        :raises ValueError: Data size should be multiple of 8
        """
        if len(key) < 8:
            raise ValueError("Key Should be 8 bytes long")
        elif len(key) > 8:
            key = key[:8] #If key size is above 8bytes, cut to be 8bytes long

        self.password = key
        self.text = text

        if padding and action == ENCRYPT:
            self.add_padding()
        elif len(self.text) % 8 != 0:#If not padding specified data size must be multiple of 8 bytes
            raise ValueError("Data size should be multiple of 8")

        self.generatekeys() #Generate all the keys
        text_blocks = nsplit(self.text, 8) #Split the text in blocks of 8 bytes so 64 bits
        result = list()
        for block in text_blocks:#Loop over all the blocks of data
            block = string_to_bit_array(block)#Convert the block in bit array
            block = self.permut(block, PI)#Apply the initial permutation
            g_split, d_split = nsplit(block, 32) #g(LEFT), d(RIGHT)
            tmp = None
            for i in range(16): #Do the 16 rounds
                d_e = self.expand(d_split, E) #Expand d to match Ki size (48bits)
                if action == ENCRYPT:
                    tmp = self.xor(self.keys[i], d_e)#If encrypt use Ki
                else:
                    tmp = self.xor(self.keys[15-i], d_e)#If decrypt start by the last key
                tmp = self.substitute(tmp) #Method that will apply the SBOXes
                tmp = self.permut(tmp, P)
                tmp = self.xor(g_split, tmp)
                g_split = d_split
                d_split = tmp
            result += self.permut(d_split + g_split, PI_1)
            #Do the last permut and append the result to result
        final_res = bit_array_to_string(result)
        if padding and action == DECRYPT:
            return self.remove_padding(final_res)
            #Remove the padding if decrypt and padding is true
        else:
            return final_res
            #Return the final string of data ciphered/deciphered

    def substitute(self, d_e):
        """
        Substitute bytes using SBOX.

        :param list d_e: n bit array.
        :returns: subtitute array.
        """
        subblocks = nsplit(d_e, 6)#Split bit array into sublist of 6 bits
        result = list()
        for i in range(len(subblocks)): #For all the sublists
            block = subblocks[i]
            row = int(str(block[0])+str(block[5]), 2)
            #Get the row with the first and last bit
            column = int(''.join([str(x) for x in block[1:][:-1]]), 2)
            #Column is the 2,3,4,5th bits
            val = S_BOX[i][row][column]
            #Take the value in the SBOX appropriated for the round (i)
            bin_val = binvalue(val, 4)
            #Convert the value to binary
            result += [int(x) for x in bin_val]
            #And append it to the resulting list
        return result

    def permut(self, block, table):
        """
        Permut the given block using the given table (so generic method).

        :param int block: Blocks
        :param list table: table
        :returns: permuted list.
        """
        return [block[x-1] for x in table]

    def expand(self, block, table):
        """
        Do the exact same thing than permut but for more clarity has been renamed

        :param int block: Blocks
        :param list table: table
        :returns: permuted list.

        """
        return [block[x-1] for x in table]

    def xor(self, logic_t1, logic_t2):
        """
        Apply a xor and return the resulting list
        """
        return [x^y for x, y in zip(logic_t1, logic_t2)]

    def generatekeys(self):
        """
        Algorithm that generates all the keys
        """
        self.keys = []
        key = string_to_bit_array(self.password)
        key = self.permut(key, CP_1) #Apply the initial permut on the key
        g_split, d_split = nsplit(key, 28)
        #Split it in to (g_split->LEFT), (d_split->RIGHT)
        for i in range(16):#Apply the 16 rounds
            g_split, d_split = self.shift(g_split, d_split, SHIFT[i])
            #Apply the shift associated with the round (not always 1)
            tmp = g_split + d_split #Merge them
            self.keys.append(self.permut(tmp, CP_2)) #Apply the permut to get the Ki

    def shift(self, g_s, d_s, n_s):
        """
        Shift a list of the given value
        """
        return g_s[n_s:] + g_s[:n_s], d_s[n_s:] + d_s[:n_s]

    def add_padding(self):
        """
        Add padding to the datas using PKCS5 spec.
        """
        pad_len = 8 - (len(self.text) % 8)
        self.text += pad_len * chr(pad_len)

    def remove_padding(self, data):
        """
        Remove the padding of the plain text (it assume there is padding)
        """
        pad_len = ord(data[-1])
        return data[:-pad_len]

    def encrypt(self, key, text):
        """
        Encrypt a text with DES algorithm

        Example:
            Example use may depends upon ```package import```
            ::

                import securefile.des_algorithm as des_algo
                cipher_text = des_algo.encrypt(key.key, plain_text)

        :param str key: Encryption key.
        :param str text: Plain Text.
        
        :returns: Encrypted Message or Cipher Text.
        :raises ValueError: Key Should be 8 bytes long
        :raises ValueError: Data size should be multiple of 8
        """
        fill = 0
        if len(text) % 8 != 0:
            fill = 8 - len(text) % 8
            for _ in range(fill):
                text += '0'
        text += '0000000' + str(fill)
        chiper = self.run(key, text, ENCRYPT, False)
        return chiper

    def decrypt(self, key, text):
        """
        Decrypt a cipher text into plain text.

        Example:
            Example use may depends upon ```package import```
            ::

                import securefile.des_algorithm as des_algo
                plain_text = des_algo.decrypt(key, plain_text)

        :Parameters str key: Encryption key.
        :Parameters str text: Cipher Text.
        :returns: Decrypted Message or Plain Text.
        :raises ValueError: Key Should be 8 bytes long
        :raises ValueError: Data size should be multiple of 8
        """
        plain_text = self.run(key, text, DECRYPT, False)
        trim = int(plain_text[-8:]) + 8
        plain_text = plain_text[:-trim]
        return plain_text

# In[6]:
if __name__ == '__main__':
    KEY = "12345678123456781234567812345678"
    TEXT = "T"
    dec = DES()
    print("Ciphered: ", dec.encrypt(KEY, TEXT))
    print("Deciphered: ", dec.decrypt(KEY, dec.encrypt(KEY, TEXT)))
