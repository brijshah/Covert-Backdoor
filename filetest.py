import os

lastPosition = 0
fileSize = 0

# createPacketTwo - takes in two bytes
# Turns both bytes into binary strings, concatenates the strings
# and turns the result into an integer value. It then creates a TCP packet
# and sets the source port as the difference between 65535 and the integer.
# Returns a TCP packet created by scapy.
def createPacketTwo(byte1, byte2):
  # get the binary values of both chars without the binary string indicator
  binByte1 = bin(ord(byte1))[2:].zfill(8)
  binByte2 = bin(ord(byte2))[2:].zfill(8)
  print binByte1 + binByte2
  # get the integer value of the concatenated binary values
  intPortVal = int(binByte1 + binByte2, 2)
  # print "bin value " + str((bin(intPortVal)))
  # craft the packet
  # packet = IP(dst=args.destIp)/TCP(dport=80, sport=maxPort - intPortVal)
  # return packet

# create a packet when we only have 1 byte remaining in the file
# works exactly the same as createPacketTwo except we only have one byte
# returns a TCP packet created by scapy.
def createPacketOne(byte):
  # get the binary value of the character
  binChar = bin(ord(byte))[2:].zfill(8)
  print binByte
  #get the integer value of that binary value
  intPortVal = int(binByte, 2)
  print intPortVal
  # craft the packet
  # packet = IP(dst=args.destIp)/TCP(dport=80, sport=maxPort -intPortVal)
  # return packet

# readOneByte - takes in a file descriptor of an open file
# accesses the global lastPosition variable, and seeks to that byte offset
# within the file.  Then, read one byte from the file and update the lastPosition.
# Returns the byte read from the file.
def readOneByte(fileDescriptor):
  global lastPosition
  fileDescriptor.seek(lastPosition)
  byte = fileDescriptor.read(1)
  lastPosition = fileDescriptor.tell()
  return byte

def readFile(path):
  global lastPosition
  global fileSize
  fileDescriptor = open(path, 'rb')
  while lastPosition < fileSize:
    if lastPosition == fileSize - 1:
      # the next byte we read contains the last character in the file
      char = readOneByte(fileDescriptor)
      # print char
      packet = createPacketOne(char)
    else:
      # there is at least 2 characters left in the file
      char1 = readOneByte(fileDescriptor)
      char2 = readOneByte(fileDescriptor)
      # print char1 + char2
      # print char2
      packet = createPacketTwo(char1, char2)

# path = '/Users/callumstyan/git/Covert-Backdoor/README.md'
path = '/Users/callumstyan/Downloads/yo.wav'
fileSize = os.path.getsize(path)
readFile(path)