# -*- coding: utf-8 -*-
#Created on Sun Oct 21 22:30:25 2018
#Author Prashant
"""
RSA Algorithm
--------------
RSA algorithm is a public key encryption technique and is considered as the
most secure way of encryption.

RSA algorithm is asymmetric cryptography algorithm.
Asymmetric actually means that it works on two different keys
i.e. Public Key and Private Key.
As the name describes that the Public Key is given to everyone
and Private key is kept private.

The idea of RSA is based on the fact that it is difficult to
factorize a large integer. The public key consists of two
numbers where one number is multiplication of two large
prime numbers. And private key is also derived from the same
two prime numbers. So if somebody can factorize the large number,
the private key is compromised. Therefore encryption strength
totally lies on the key size and if we double or triple the
key size, the strength of encryption increases exponentially.
RSA keys can be typically 1024 or 2048 bits long,
but experts believe that 1024 bit keys could be broken in the
near future. But till now it seems to be an infeasible task.

It was invented by Rivest, Shamir and Adleman
in year 1978 and hence name RSA algorithm.
"""
# In[]
import random

# In[]
class RSA:
    """
    RSA algorithm is a public key encryption technique and is considered as the
    most secure way of encryption. It was invented by Rivest, Shamir and Adleman
    in year 1978 and hence name RSA algorithm.
    """
    def __init__(self):
        pass

    @staticmethod
    def gcd(a, b):
        '''
        Euclid's algorithm for determining the greatest common divisor
        Use iteration to make it faster for larger integers
        '''
        while b != 0:
            a, b = b, a % b
        return a

    @staticmethod
    def multiplicative_inverse(a, b):
        """
        Euclid's extended algorithm for finding the multiplicative inverse of two numbers
        Returns a tuple (r, i, j) such that

        .. math:: r = gcd(a, b) = ia + jb

        ::

            r = gcd(a,b) i = multiplicitive inverse of a mod b
                 or      j = multiplicitive inverse of b mod a

        Neg return values for i or j are made positive mod b or a respectively
        Iterateive Version is faster and uses much less stack space
        """
        x = 0
        y = 1
        lx = 1
        ly = 0
        oa = a  # Remember original a/b to remove
        ob = b  # negative values from return results
        while b != 0:
            q = a // b
            (a, b) = (b, a % b)
            (x, lx) = ((lx - (q * x)), x)
            (y, ly) = ((ly - (q * y)), y)
        if lx < 0:
            lx += ob  # If neg wrap modulo orignal b
        if ly < 0:
            ly += oa  # If neg wrap modulo orignal a
        # return a , lx, ly  # Return only positive values
        return lx

    @staticmethod
    def is_prime(num):
        """
        Tests to see if a number is prime
        """
        if num == 2:
            return True
        if num < 2 or num % 2 == 0:
            return False
        for n in range(3, int(num**0.5)+2, 2):
            if num % n == 0:
                return False
        return True

    @staticmethod
    def generate_keypair(p, q):
        if not (RSA.is_prime(p) and RSA.is_prime(q)):
            raise ValueError('Both numbers must be prime.')
        elif p == q:
            raise ValueError('p and q cannot be equal in RSA key')
        #n = pq
        n = p * q
    
        #Phi is the totient of n
        phi = (p-1) * (q-1)
    
        #Choose an integer e such that e and phi(n) are coprime
        e = random.randrange(1, phi)
    
        #Use Euclid's Algorithm to verify that e and phi(n) are comprime
        g = RSA.gcd(e, phi)
        while g != 1:
            e = random.randrange(1, phi)
            g = RSA.gcd(e, phi)

        #Use Extended Euclid's Algorithm to generate the private key
        d = RSA.multiplicative_inverse(e, phi)
        
        #Return public and private keypair
        #Public key is (e, n) and private key is (d, n)
        return ((e, n), (d, n))
    
    @staticmethod
    def encrypt(pk, plaintext):
        """
        RSA Encrypt
        -------------
        decrypt() do basic RSA encryption algoritm to make ciphertext

        :param tuple pk: RSA Private Key as tuple
        :param int ciphertext: Plain Text
        :returns: list integer array of encrypted text
        :raises: None
        """
        #Unpack the key into it's components
        key, n = pk
        #Convert each letter in the plaintext to numbers based on the character using a^b mod m
        cipher = [(ord(char) ** key) % n for char in plaintext]
        #Return the array of bytes
        return cipher

    @staticmethod
    def decrypt(pk, ciphertext):
        """
        RSA Decrypt
        -------------
        decrypt() do basic RSA decryption algoritm to decipher the ciphertext

        :param tuple pk: RSA Public Key as tuple
        :param int ciphertext: Cipher s
        :returns: char array of decrypted Text
        :raises ValueError: Throws error when not correnct text is providded
        """
        #Unpack the key into its components
        key, n = pk
        #Generate the plaintext based on the ciphertext and key using a^b mod m
        plain = [chr(pow(int(char), key, n)) for char in ciphertext if char]
        #Return the array of bytes as a string
        return plain

def __example():
    '''
    Detect if the script is being run directly by the user
    '''
    algo = RSA()
    public, private = RSA.generate_keypair(149, 383)
    print("Your public key is ", public ," and your private key is ", private)
    message = input("Enter a message to encrypt with your private key: ")
    encrypted_msg = algo.encrypt(private, message)
    print("Your encrypted message is: ")
    print(' '.join(str(x) for x in encrypted_msg))
    print("Decrypting message with public key ", public ," . . .")
    print("Your message is:")
    print(algo.decrypt(public, encrypted_msg))

if __name__ == '__main__':
    __example()