from scapy.all import *
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

maxPort = 65535

# createPacketTwo - takes in two ASCII characters
# Turns both characters into binary strings, concatenates the strings
# and turns the result into an integer value. It then creates a TCP packet
# and sets the source port as the difference between 65535 and the integer.
# Returns a TCP packet created by scapy.
def createPacketTwo(protocol, ip, char1, char2):
    # get the binary values of both chars without the binary string indicator
    binChar1 = bin(ord(char1))[2:].zfill(8)
    binChar2 = bin(ord(char2))[2:].zfill(8)
    print binChar1 + binChar2
    # get the integer value of the concatenated binary values
    intPortVal = int(binChar1 + binChar2, 2)
    print "bin value " + str((bin(intPortVal)))
    # craft the packet
    if protocol == 'tcp':
        packet = IP(dst=ip)/TCP(dport=80, sport=maxPort - intPortVal)
    elif protocol == 'udp':
        packet = IP(dst=ip)/UDP(dport=80, sport=maxPort - intPortVal)
    return packet

# create a packet when we only have 1 character remaining in the file
# works exactly the same as createPacketTwo except we only have one character
# returns a TCP packet created by scapy.
def createPacketOne(protocol, ip, char):
    # get the binary value of the character
    binChar = bin(ord(char))[2:].zfill(8)
    print binChar
    #get the integer value of that binary value
    intPortVal = int(binChar, 2)
    # craft the packet
    if protocol == 'tcp':
        packet = IP(dst=ip)/TCP(dport=8000, sport=maxPort - intPortVal)
    elif protocol == 'udp':
        packet = IP(dst=ip)/UDP(dport=8000, sport=maxPort - intPortVal)
    return packet

# we won't need this after we do encryption
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