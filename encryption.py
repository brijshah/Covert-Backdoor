#!/usr/bin/python

from Crypto.Cipher import AES

def encrypt(data, password):
    encryptionKey = AES.new(password)
    tagString = (str(data) +
                  (AES.block_size -
                   len(str(data)) % AES.block_size) * "\0")
    ciphertext = base64.b64encode(encryptionKey.encrypt(tagString))
    return ciphertext

def decrypt(data, password):
    decryptionKey = AES.new(password)
    rawData = decryptionKey.decrypt(base64.b64decode(data))
    plaintext = rawData.rstrip("\0")
    return plaintext