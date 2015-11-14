#!/usr/bin/python

import logging
import time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

knocks = [1000,2000,3000]


def portKnock():
    for knock in knocks:
        packet = IP(dst="192.168.0.19")/UDP(sport=knock, dport=7000)
        send(packet)
        time.sleep(1)

def main():
    portKnock()

if __name__ == '__main__':
    main()
