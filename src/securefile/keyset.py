# -*- coding: utf-8 -*-
#Created on Mon Oct 22 18:59:37 2018
#Author Prashant Kumar and Pamela Banerjee

"""
keyset
-------
A module for all key object. it provide following key object at one:
    - DES key
    - AES Key
    - RSA Key

**Uses** ::

    import securefile.keyset

**Module Structure**:
    .. graphviz::
    
        digraph foo {
            "KeySet Module" -> "RSA_KEY"
            "KeySet Module" -> "AES_KEY"
            "KeySet Module" -> "DES_KEY"
    
            "KeySet Module"[shape=ractangle]
            "RSA_KEY"[shape=ractangle]
            "AES_KEY"[shape=ractangle]
            "DES_KEY"[shape=ractangle]
        }

"""

from securefile.rsa_algorithm import RSA

# In[]
class RSA_KEY:
    """
    Key Class
    ----------
    Rivest–Shamir–Adleman (RSA) Algorithm key object.
    
    :Method:
        - :class:`~securefile.keyset.RSA_KEY.genrate()`
        - :class:`~securefile.keyset.RSA_KEY.public_key_genrate()`
        - :class:`~securefile.keyset.RSA_KEY.private_key_genrate()`

    :Attributes:
        - public_key
        - private_key
    """
    def __init__(self, public, private):
        """
        __init__
        ----------
        Initlize the class
        
        :param tuple public: public key tuple, like (a, b)
        :param tuple private: private key tuple, like (a, b)
        :returns: None
        :raises: None
        """
        self.public_key = public
        self.private_key = private

    def __repr__(self):
        return "<RSA Key Object>"

    @staticmethod
    def genrate(prime_one, prime_two):
        """
        *@staticmethod*

        genrate
        --------
        Genrate a public key and private key pair from a given prime numberi

        Example ::

            print(RSA_KEY.genrate(149, 383))

        :param int prime_one: First prime number for RSA key. (Must be a prime number)
        :param int prime_two: Second prime number for RSA key. (Must be a prime number)
        :returns: :class:`~securefile.keyset.RSA_KEY` public and private key pair object
        :raises ValueError: Both numbers must be prime.
        :raises ValueError: p and q cannot be equal in RSA key
        """
        public_key, private_key = RSA.generate_keypair(prime_one, prime_two)
        return RSA_KEY(public_key, private_key)

    @staticmethod
    def public_key_genrate(key1, key2):
        """
        *@staticmethod*

        public_key_genrate
        -------------------
        Genrate a public key pair from a given key tuple

        Example ::

            print(RSA_KEY.public_key_genrate(18285, 57067))

        :param int key1: First tuple of public key.
        :param int key2: Second tuple of public key.
        :returns: :class:`~securefile.keyset.RSA_KEY` Public key object
        :Raises: None
        """
        public_key = (key1, key2)
        return RSA_KEY(public_key, [])

    @staticmethod
    def private_key_genrate(key1, key2):
        """
        *@staticmethod*

        private_key_genrate()
        ----------------------
        Genrate a private key pair from a given key tuple

        Example ::

            print(RSA_KEY.private_key_genrate(6861, 57067))

        :param int key1: First tuple of private key.
        :param int key2: Second tuple of private key.
        :returns: :class:`~securefile.keyset.RSA_KEY` Private key object
        :raises: None
        """
        return RSA_KEY([], (key1, key2))

class DES_KEY:
    """
    Key Class
    ----------
    Data Encryption Standard (DES) Algorithm key object.

    :Method:
        :class:`~securefile.keyset.DES_KEY.genrate()`
    :Attributes:
        key
    """
    def __init__(self, key):
        """
        __init__
        ----------
        :param str key: Key string
        :returns:  None
        :Raises: None
        """
        self.key = key

    def __repr__(self):
        return "<DES Key Object>"

    @staticmethod
    def genrate(key):
        """
        *@staticmethod*

        genrate
        --------
        Genrate the DES Key object.
        
        Example ::
        
            des_key = DES_KEY.genrate('12345678123456781234567812345678')
        
        :param str key: Key string
        :returns: :class:`~securefile.keyset.DES_KEY` Key object
        :raises ValueError: DES key must be 8 charecter long
        """
        if len(key) < 8:
            raise ValueError("DES key must be 8 charecter long")
        return DES_KEY(key)

class AES_KEY:
    """
    Key Class
    ----------
    Advanced Encryption Standard (AES) Algorithm key object.

    :Method:
        :class:`~securefile.keyset.AES_KEY.genrate()`
    :attributes:
        key
    """
    def __init__(self, key):
        """
        __init__()
        -----------
        :param str key: Key string
        :returns: None
        :raises: None
        """
        self.key = key

    def __repr__(self):
        return "<AES Key Object>"

    @staticmethod
    def genrate(key):
        """
        genrate
        --------
        Genrate the AES key object.
        
        Example ::
        
            aes_key = AES_KEY.genrate('700102030405060708090a0b0c0d0e0f')
        
        :param str key: key string
        :returns: :class:`~securefile.keyset.AES_KEY` Key object
        :raises ValueError: AES key must be 128-bit(32 char), 192-bit(48 char) or 256-bit(64 char)
        """
        if len(key) not in [32]:
#            TODO: [32, 48, 64] may work but not now
            raise ValueError(
                    "AES key must be 128-bit(32 char), 192-bit(48 char) or 256-bit(64 char)"
                    +"\nExample : 000102030405060708090a0b0c0d0e0f")
        return AES_KEY(key)
