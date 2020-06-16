# Author: Dustin Ray
# TCSS 581 - Cryptology
# Spring 2020

# A python implementation of the El Gamal signature scheme.
# I would have used Ocaml or Rust but I ran out of time. 
# This implementation utilized the PyCrypto library for generation of 
# securely random primes, and thus if PyCrypto is secure, this implemenation
# could also be considered secure. This implementation has a bottleneck in the 
# modular inverse function. There may be a library that makes this run faster, but any value
# above 25 takes a very long time to run.

# This mostly follows the scheme as outlined here: https://en.wikipedia.org/wiki/ElGamal_signature_scheme

import Crypto
from Crypto import Random
from Crypto.Util.number import *
from random import randint
import hashlib
import time

# PROOF:
# because during generation the assumtion is that the hash of the message
# H(m)  is congruent to xr + sk mod(p), then since g is relatively prime to p, 
# g ^ H(m) is congruent to g ^ xr + sk mod(p), which is also congruent to
# (g^x)^r * (g^k)^s mod(p), which is congruent to 
# (y^r) * (r)^s mod(p)

# global security perameter: size of prime
n = int(input("Please enter a security parameter (Higher than 25 takes longer to process): "))

# arbitrary message
msg = input("Please enter a message to sign: ")

#convert message into bytes and hash with SHA256
byte_msg = int.from_bytes(hashlib.sha256(msg.encode()).digest(), byteorder = 'big')

print("\nMessage to sign: " + msg)

def main():

    # generate key
    p, x, g, y = keyGen()

    # get a securely random prime 
    k = Crypto.Util.number.getPrime(n, randfunc = Crypto.Random.get_random_bytes)

    print("\nGenerating modular inverse of parameter k...")
    #get inverse of k
    k_inv =  modularInverse(k, p - 2)
    

    print("Signing message...")
    # r and s are message signatures
    r, s = signMessage(g, p, k, k_inv, x)

    # verification step: successful if these are congruent
    #v1 = pow(g, byte_msg, p) % p
    #v2 = (pow(y, r) * pow(r, s)) % p

#    if v1 == v2:
#        print("Verification Success!")

    print("Message signature: " + str(r) + ", " + str(s) + "\n")

# generates a keypair for signing/verification.
def keyGen():

    print("\nGenerating Keypair...")
    time0 = time.time()

    # get a securely random prime 
    p = Crypto.Util.number.getPrime(n, randfunc = Crypto.Random.get_random_bytes)
    # g is arbitrary generator from Zp*
    g = 2

    # x is random integer from {1 ... p -2} (does not need to be securely
    # random since it is public anyways)
    x = randint(0, p-1)
    
    # x is public key and y is private key
    y = pow(g, x, p)

    time1 = time.time()
    print("Generated Keypair in " + str(time1 - time0) + " seconds")
    print("\n" + "Secret signing key: " + str(y))
    print("Public key: " + str(x))
    
    # p and g are public algorithm parameters to be shared between 
    # communicating parties
    return p, x, g, y

# returns a message signature
def signMessage(g, p, k, k_inv, x):

    time0 = time.time()
    
    r = pow(g, k, p)
    s = ((byte_msg - x * r) * k_inv) % (p - 1)
    
    time1 = time.time()
    print("Signed in " + str(time1 - time0) + " seconds")

    return r, s

# this function is lame and takes a long time for n parameter
# over a value of 25. There is probably a library that exists
# that makes this run faster. 

def modularInverse(a, m) : 

    result = a % m
    
    for x in range(1, m): 
        if (result * x) % m == 1: 
            result = x 
        else:
            result = 1
    
    return result

main()

