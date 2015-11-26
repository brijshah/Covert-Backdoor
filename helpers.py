from scapy.all import *
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

maxPort = 65535

# take string and break it into chunks of length size
def chunkString(size, string):
  chunkedString = [string[i:i+size] for i in range(0, len(string), size)]
  return chunkedString

# create a packet when we only have 1 character remaining in the file
# works exactly the same as createPacketTwo except we only have one character
# returns a TCP packet created by scapy.
def createPacket(protocol, ip, char):
    # get the binary value of the character
    binChar = bin(ord(char))[2:].zfill(8)
    #print binChar
    #get the integer value of that binary value
    intPortVal = int(binChar, 2)
    # craft the packet
    if protocol == 'tcp':
        packet = IP(dst=ip)/TCP(dport=8000, sport=maxPort - intPortVal)
    elif protocol == 'udp':
        packet = IP(dst=ip)/UDP(dport=8000, sport=maxPort - intPortVal)
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
