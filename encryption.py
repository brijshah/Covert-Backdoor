#!/usr/bin/python

import triplesec

def encrypt(data, password):
    ciphertext = triplesec.encrypt(bytes(data), bytes(password))
    return ciphertext

def decrypt(data, password):
    plaintext = triplesec.decrypt(bytes(data), bytes(password))
    return plaintext