#!/usr/bin/python

from Crypto.Cipher import AES
import base64

masterkey = "12345678901234567890123456789012"

def encrypt(data):
    encryptionKey = AES.new(masterkey)
    tagString = (str(data) +
                  (AES.block_size -
                   len(str(data)) % AES.block_size) * "\0")
    print len(tagString)
    ciphertext = base64.b64encode(encryptionKey.encrypt(tagString))
    return ciphertext

def decrypt(data):
    decryptionKey = AES.new(masterkey)
    rawData = decryptionKey.decrypt(base64.b64decode(data))
    plaintext = rawData.rstrip("\0")
    return plaintext