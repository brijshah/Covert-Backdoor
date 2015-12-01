#!/usr/bin/python

#-----------------------------------------------------------------------------
#-- SOURCE FILE:    encryption.py -   Encryption for Client and Backdoor
#--
#-- FUNCTIONS:      encrypt(data, password)
#--					decrypt(data, password)
#--
#-- DATE:           November 29, 2015
#--
#-- PROGRAMMERS:    Brij Shah & Callum Styan
#--
#-- NOTES:
#-- AES encryption for the client and backdoor.
#-----------------------------------------------------------------------------

from Crypto.Cipher import AES
import base64

masterkey = "12345678901234567890123456789012"

#-----------------------------------------------------------------------------
#-- FUNCTION:       encrypt(data)
#--
#-- VARIABLES(S):   data - the data to be encrypted
#--					password - used to encrypt data
#--
#-- NOTES:
#-- encrypt takes in the data to be encrypted and returns the encoded data.
#-----------------------------------------------------------------------------
def encrypt(data, password):
    encryptionKey = AES.new(password)
    tagString = (str(data) + (AES.block_size - len(str(data)) % AES.block_size) * "\0")
    ciphertext = base64.b64encode(encryptionKey.encrypt(tagString))
    return ciphertext

#-----------------------------------------------------------------------------
#-- FUNCTION:       decrypt(data)
#--
#-- VARIABLES(S):   data - the data to be decrypted
#--					password - used to decrypt data
#--
#-- NOTES:
#-- decrypt takes in encoded data and returns the plain text value.
#-----------------------------------------------------------------------------
def decrypt(data, password):
    decryptionKey = AES.new(password)
    rawData = decryptionKey.decrypt(base64.b64decode(data))
    plaintext = rawData.rstrip("\0")
    return plaintext
