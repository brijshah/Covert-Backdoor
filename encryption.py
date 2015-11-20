#!/usr/bin/python

import triplesec

def encrypt(data, password):
    ciphertext = triplesec.encrypt(data, password)
    return ciphertext

def decrypt(data, password):
    plaintext = triplesec.decrypt(data, password)
    return plaintext