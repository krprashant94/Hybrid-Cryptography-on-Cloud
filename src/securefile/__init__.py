# -*- coding: utf-8 -*-
#Created on Sun Oct 14 15:40:05 2018
#Author Prashant Kumar and Pamela Banerjee
"""
SecureFile
-----------
A python package for hybrid file encryption and decryption. **securefile** is
for n-layer file encryption. This package provides a basic two-way encryption
algorithm for a file. It supports approximately all kind of file encoding.
The package provides RSA, DES, AES and Shift Cipher and base64
algorithm for file encoding and decoding.

transmitting sensitive data over a public channel is quite insecure. to secure
the data over public channel we need to encrypt the data. So that no third
party can access that information. It may be possible that encrypting with one
algorithm can be decoded by reverse engineering. But, using n-layer of the
different algorithm, makes it more secure and decoding such kind of ciphertext
with reverse engineering will take approximately unpractical time for a
supercomputer also.

**Dependency**:
    - pyserial
        >>> python -m pip install pyserial
    
    Native :
        - base64
        - random
        - binascii
        - re

**Installation**:
    To install this package with pip command type
        >>> pip install securefile

**Module Structure**:
    .. graphviz::
    
        digraph foo {
            "Securefile Module" -> "DES Algorithm"
            "Securefile Module" -> "RSA Algorithm"
            "Securefile Module" -> "AES Algorithm"
            "Securefile Module" -> "    Keyset   "
            "Securefile Module" -> "Secure Serial"

            "Securefile Module"[shape=ractangle]
            "AES Algorithm"[shape=ractangle]
            "DES Algorithm"[shape=ractangle]
            "RSA Algorithm"[shape=ractangle]
            "    Keyset   "[shape=ractangle]
            "Secure Serial"[shape=ractangle]
        }

**Uses**::

    from securefile import Encrypt
    from securefile.keyset import RSA_KEY, DES_KEY, AES_KEY
    
    des_key = DES_KEY.genrate('12345678123456781234567812345678')
    aes_key = AES_KEY.genrate('700102030405060708090a0b0c0d0e0f')
    rsa_public_key = RSA_KEY.public_key_genrate(18285, 57067)
    rsa_private_key = RSA_KEY.private_key_genrate(6861, 57067)
    chiper_shift = 3

    enc = Encrypt('test.txt', delimiter=':')
    enc.open()
    
    enc.base64_encrypt()
    enc.aes_encrypt(aes_key, commit=True)
    enc.des_encrypt(des_key, commit=True)
    enc.rsa_encrypt(rsa_private_key, commit=True)
    enc.caesar_cipher(key_shift=chiper_shift, commit=True)

    enc.caesar_decipher(key_shift=chiper_shift, commit=True)
    enc.rsa_decrypt(rsa_public_key, commit=True)
    enc.des_decrypt(des_key, commit=True)
    enc.aes_decrypt(aes_key, commit=True)
    enc.base64_decrypt(commit=True)
"""
# In[]:
__author__ = "Prashant Kumar and Pamela Banerjee"
__copyright__ = "Copyright 2018, Secure File Storage on Cloud Using Hybrid Cryptography Project"
__credits__ = ["Prashant Kumar", "Pamela Banerjee"]
__license__ = "GPL"
__version__ = "1.0.1"
__maintainer__ = ["Prashant Kumar", "Pamela Banerjee"]
__email__ = ["kr.prashant94@gmail.com", "pamelabanerjee11@gmail.com"]
__status__ = "Development"

# In[]:
from base64 import b64decode, b64encode
import securefile.des_algorithm as des_algo
import securefile.rsa_algorithm as rsa_algo
import securefile.aes_algorithm as aes_algo

# In[]:
class Encrypt:
    """
    Encrypt
    ---------
    Encrypt is the center class for all the module it is a wrapper class for
    all encryption and decryption algorithm.

    Example ::

        from securefile import Encrypt
        enc = Encrypt('test.md', delimiter=':')
    
    :Special Method:
        - :class:`~securefile.Encrypt.__init__()`
        - :class:`~securefile.Encrypt.__open_check()`

    :Method:
        - :class:`~securefile.Encrypt.open()`
        - :class:`~securefile.Encrypt.close()`
        - :class:`~securefile.Encrypt.create()`
        - :class:`~securefile.Encrypt.commit()`
        - :class:`~securefile.Encrypt.des_encrypt()`
        - :class:`~securefile.Encrypt.des_decrypt()`
        - :class:`~securefile.Encrypt.caesar_cipher()`
        - :class:`~securefile.Encrypt.caesar_decipher()`
        - :class:`~securefile.Encrypt.rsa_encrypt()`
        - :class:`~securefile.Encrypt.rsa_decrypt()`
        - :class:`~securefile.Encrypt.aes_encrypt()`
        - :class:`~securefile.Encrypt.aes_decrypt()`
        - :class:`~securefile.Encrypt.base64_encrypt()`
        - :class:`~securefile.Encrypt.base64_decrypt()`
        - :class:`~securefile.Encrypt.get_text()`

    :Attributes:
        - __file_name
        - __plain_text
        - __open_flag
    """
    def __init__(self, file_name, delimiter=':'):
        """
        Encrypt class object takes two argument

        :param str file_name: file name with path that is going to encrypted or decrypted.
        :param chr delimiter='\:': delimiter used to pack/split the bytes of file.
        :returns: None
        :raises: None
        """
        self.__file_name = file_name
        self.__plain_text = []
        self.__open_flag = False
        self.__delimiter = delimiter

    def get_text(self):
        """
        get_text()
        ------------
        Get the char-byte array of current opened file

        :returns list: byte array of opened file or Null if no woring file exist.
        :raises: None
        """
        return self.__plain_text

    @staticmethod
    def create(file_name, delimiter=':'):
        """
        Create a Encrypt object form file

        ::

            a = Encrypt.create('test.md', delimiter=':')
            a.open()
            print(a.get_text())

        :param str file_name: file name with path that is going to encrypted or decrypted.
        :param chr delimiter='\:': delimiter used to pack/split the bytes of file.
        :returns: None
        :raises: None
        """
        return Encrypt('test.md', delimiter=':')

    def open(self):
        """
        open()
        --------
        Open current file and read the data contains. Binary file reading
        using basic python file open()
        
        Uses:
            >>> enc.open()

        :returns: True|False
        :raises UnicodeDecodeError: On File Encoding error
        :raises FileNotFoundError: On file not found
        :raises FileExistsError: On file no more exist
        """
        if not self.__open_flag:
            try:
                self.__open_flag = True
                file = open(self.__file_name, 'r', encoding='utf-8')
                self.__plain_text = file.read()
                file.close()
                self.__plain_text = [char for char in self.__plain_text]
                return True
            except UnicodeDecodeError as exp:
                self.close()
                print(exp)
                raise UnicodeDecodeError('Encrypt.open()',
                                         b'0',
                                         47,
                                         1,
                                         "Invalid file format for UTF-8 charecterset. Open Failed.")
        else:
            return False
    def close(self):
        """
        close()
        ----------
        close current file and flush the memory

        Uses:
            >>> enc.open()
            >>> enc.close()

        :returns bool: True|False
        :raises FileExistsError: On no file open()
        """
        if self.__open_flag:
            self.__plain_text = []
            self.__open_flag = False
            return True
        else:
            return FileExistsError('No file open in current module.')

    def __open_check(self):
        """
        __open_check()
        -----------------
        Check weather the file is open or not.
        :returns: None
        :raises FileExistsError: No working file exists in the current module. try to call Encrypt.open() before encrypting or decrypting the file.
        """
        if not self.__open_flag:
            raise FileExistsError("No working file exists in the current module." +
                                  " try to call Encrypt.open() before encrypting" +
                                  " or decrypting the file.")
        else:
            return

    def commit(self):
        """
        commit()
        -----------
        Save current progress in the woring file. (Commit the changes)

        :returns bool: True if successfully saved otherwise raise exception
        :raises: File exception on error
        """
        self.__open_check()
        buffer = ''
        for char in self.__plain_text:
            buffer += char
        file = open(self.__file_name, 'w', encoding='utf-8')
        file.write(buffer)
        file.close()
        return True

    def des_encrypt(self, key, commit=False):
        """
        des_encrypt()
        ---------------
        Encrypt a plain text with DES algorithm.

        Example::

                from securefile import Encrypt
                from securefile.keyset import DES_KEY
                des_key = DES_KEY.genrate('12345678123456781234567812345678')
                enc = Encrypt('test.md')
                enc.open()
                enc.des_encrypt(des_key, commit=True)
                enc.close()

        :param `~securefile.keyset.DES_KEY` key: Encryption key.
        :param bool commit=False: Save the change or not.
        :returns: Encrypted Message or Cipher Text.
        :raises ValueError: Key Should be 8 bytes long
        :raises ValueError: Data size should be multiple of 8

        .. warning::

            - Emoji not supported in DES encryption it will skip if emoji encounter
            - To overcome this please use base64 encoding
        """
        self.__open_check()
        buffer = ''
        for i in self.__plain_text:
            buffer += i
        try:
            algo = des_algo.DES()
            buffer = algo.encrypt(key.key, buffer)
        except ValueError as exp:
            print(exp)
            print("Emoji may encountered skiping")
        self.__plain_text = [char for char in buffer]
        del buffer
        if commit:
            self.commit()
        return self.__plain_text

    def des_decrypt(self, key, commit=False):
        """
        des_decrypt
        -------------
        Decrypt a cipher text into plain text using DES algorithm.

        Example::

                from securefile import Encrypt
                from securefile.keyset import DES_KEY
                des_key = DES_KEY.genrate('12345678123456781234567812345678')
                enc = Encrypt('test.md')
                enc.open()
                enc.des_decrypt(des_key, commit=True)
                enc.close()

        :param `~securefile.keyset.DES_KEY` key: Encryption key.
        :param bool commit=False: Save the change or not.
        :returns: Decrypted Message or Plain Text.
        :raises ValueError: Text is not valid DES string. Decode failed.
        """
        self.__open_check()
        buffer = ''
        for i in self.__plain_text:
            buffer += i
        try:
            algo = des_algo.DES()
            self.__plain_text = algo.decrypt(key.key, buffer)
            del buffer
            if commit:
                self.commit()
            return self.__plain_text
        except ValueError:
            raise ValueError("Text is not valid DES string. Decode failed.")

    def caesar_cipher(self, key_shift=3, commit=False):
        """
        Caesar Cipher
        ---------------
        The action of a Caesar cipher is to replace each plaintext letter
        with a different one a fixed number of places down the alphabet.
        The cipher illustrated here uses a left shift of three, so that
        (for example) each occurrence of E in the plaintext becomes B in
        the ciphertext.

        caesar_cipher()
        ------------------
        Encrypt a plain text into cipher text.

        Example::

                from securefile import Encrypt
                enc = Encrypt('test.md')
                enc.open()
                enc.caesar_cipher(key_shift=3, commit=True)
                enc.close()

        :param int key_shift=3: Number of place to br shift.
        :param bool commit=False: Save the change or not.
        :returns list: Encrypted Message or Cipher Text.
        :raises: None
        """
        self.__open_check()
        buffer = []
        for i in self.__plain_text:
            buffer.append(chr(ord(i)+key_shift))
        self.__plain_text = buffer
        del buffer
        if commit:
            self.commit()
        return self.__plain_text

    def caesar_decipher(self, key_shift=3, commit=False):
        """
        caesar_decipher()
        -------------------
        Decrypt a cipher text into plain text.
        
        See :class:`~securefile.Encrypt.caesar_cipher`

        Example::

                ...
                enc.caesar_decipher(key_shift=3, commit=True)
                ...

        :param int key_shift=3: Position shift in cipher text.
        :param bool commit=False: Save the change or not.
        :returns: Decrypted Message or Plain Text.
        :raises: None
        """
        self.__open_check()
        buffer = []
        for i in self.__plain_text:
            buffer.append(chr(ord(i)-key_shift))
        self.__plain_text = buffer
        del buffer
        if commit:
            self.commit()
        return self.__plain_text

    def rsa_encrypt(self, key, commit=False):
        """
        rsa_encrypt()
        ----------------
        Encrypt a plain text with RSA algorithm.
        ( :class:`~securefile.rsa_algorithm` )

        Example::

                from securefile import Encrypt
                from securefile.keyset import RSA_KEY
                rsa_private_key = RSA_KEY.private_key_genrate(6861, 57067)
                enc = Encrypt('make.txt')
                enc.open()
                enc.rsa_encrypt(rsa_private_key)
                enc.close()

        :param `~securefile.keyset.RSA_KEY` key: Encryption key.
        :param bool commit=False: Save the change or not.
        :returns: Encrypted Message or Cipher Text.
        :raises: None

        .. warning::

            - Emojy may change in RSA
            - RSA returns big number as encrypted text, It is good to use this at last layer of model in order to make encryption fast.
        """
        self.__open_check()
        buffer = ''
        algo = rsa_algo.RSA()
        self.__plain_text = algo.encrypt(key.private_key, self.__plain_text)
        for word in self.__plain_text:
            buffer += str(word)+self.__delimiter
        self.__plain_text = [word for word in buffer]
        del buffer
        if commit:
            self.commit()
        return self.__plain_text


    def rsa_decrypt(self, key, commit=False):
        """
        rsa_decrypt()
        ----------------
        Decrypt a cipher text into plain text.
        ( :class:`~securefile.Encrypt.rsa_encrypt` )

        Example::

                ...
                enc.open()
                enc.rsa_decrypt(rsa_public_key, commit=True)
                enc.close()

        :param `~securefile.keyset.RSA_KEY` key: Encryption key.
        :param bool commit=False: Save the change or not.
        :returns: Decrypted Message or Plain Text.
        :raises: TypeError - Text is not valid RSA string. Decode failed.
        
        .. note:: Decryption of RSA cipher text may take more time then encryption
        """
        self.__open_check()
        try:
            buffer = ''
            for word in self.__plain_text:
                buffer += word
            self.__plain_text = buffer.split(self.__delimiter)
            algo = rsa_algo.RSA()
            self.__plain_text = algo.decrypt(key.public_key, self.__plain_text)
            if commit:
                self.commit()
            return self.__plain_text
        except ValueError:
            raise TypeError("Text is not valid RSA string. Decode failed.")

    def aes_encrypt(self, key, commit=False):
        """
        aes_encrypt()
        ----------------
        Encrypt a plain text with AES algorithm.
        ( :class:`~securefile.aes_algorithm` )

        Example::

                from securefile import Encrypt
                from securefile.keyset import AES_KEY
                aes_key = AES_KEY.genrate('700102030405060708090a0b0c0d0e0f')
                enc = Encrypt('test.txt')
                enc.open()
                enc.aes_encrypt(aes_key)
                enc.close()

        :param `~securefile.keyset.AES_KEY` key: Encryption key.
        :param bool commit=False: Save the change or not.
        :returns: Encrypted Message or Cipher Text.
        :raises IndexError: Word size too large to encrypt with AES algorithm.
        :raises ValueError: No a formetted text

        .. note:: Most sutable after RSA or DES Algorithm
        """
        self.__open_check()
        try:
            buffer = ''
            for char in self.__plain_text:
                buffer += char
            algo = aes_algo.AES(mode='ecb', input_type='text')
#            Making buffer of 15 charecter to optomize the time of encryption
            buffer = [buffer[i:i+10] for i in range(0, len(buffer), 10)]
            cipher = ""
            for word in buffer:
                if len(word) > 15:
                    raise IndexError("word size(" + str(len(word)) +
                                     ") is too large to encrypt with AES" +
                                     " algorithm. You can check for the following" +
                                     "\n1. Change the delimiter" +
                                     "\n2. Try to encrypt with RSA or DES before using AES.""")
                cipher += algo.encrypt(word, key.key)
            self.__plain_text = [char for char in cipher]
            del cipher
            del buffer
            if commit:
                self.commit()
            return self.__plain_text
        except ValueError:
            raise ValueError("No a formetted text")

    def aes_decrypt(self, key, commit=False):
        """
        aes_decrypt()
        ----------------
        Decrypt a cipher text into plain text.
        ( :class:`~securefile.Encrypt.aes_encrypt` )

        Example::

                ...
                enc.open()
                enc.aes_decrypt(des_key, commit=True)
                enc.close()

        :param `~securefile.keyset.AES_KEY` key: Encryption key.
        :param bool commit=False: Save the change or not.
        :returns: Decrypted Message or Plain Text.
        :raises: ValueError - Not a formetted text.
        """
        self.__open_check()
        try:
            key_len = len(key.key)
            buffer = ''
            for char in self.__plain_text:
                buffer += char
            buffer = [buffer[i:i+key_len] for i in range(0, len(buffer), key_len)]

            algo = aes_algo.AES(mode='ecb', input_type='text')
            text = ''
            for word in buffer:
                text += algo.decrypt(word, key.key)
            del buffer
            self.__plain_text = [x for x in text]

            del text
            if commit:
                self.commit()
            return self.__plain_text

        except ValueError:
            raise ValueError("Not a formetted text")

    def base64_encrypt(self, commit=False):
        """
        Base64
        ----------
        Base64 encoding schemes are commonly used when there is a need to
        encode binary data that needs be stored and transferred over
        media that are designed to deal with textual data.
        This is to ensure that the data remains intact without modification
        during transport.

        Uses:
            Encrypt a plain text into cipher text using b64encode.

        Example::

                from securefile import Encrypt
                enc = Encrypt('list_count.txt', delimiter=',')
                enc.open()
                enc.base64_encrypt()
                enc.close()

        :param bool commit=False: Save the change or not.
        :returns: Encrypted Message or Cipher Text.
        :raises: None
        """
        buffer = ''
        for char in self.__plain_text:
            buffer += char
        buffer = b64encode(buffer.encode('utf-8')).decode('utf-8')
        self.__plain_text = [char for char in buffer]
        if commit:
            self.commit()
        del buffer
        return self.__plain_text
    def base64_decrypt(self, commit=False):
        """
        Base64
        ----------
        See :class:`~securefile.Encrypt.base64_encrypt`
        
        Decrypt a cipher text into plain text using b64decode.

        Example::

                ...
                enc.open()
                enc.base64_decrypt(commit=True)
                enc.close()

        :param bool commit=False: Save the change or not.
        :returns: Decrypted Message or Plain Text.
        :raises: None
        """
        buffer = ''
        for char in self.__plain_text:
            buffer += char
        buffer = b64decode(buffer.encode('utf-8')).decode('utf-8')
        self.__plain_text = [char for char in buffer]
        if commit:
            self.commit()
        del buffer
        return self.__plain_text
