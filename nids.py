from __future__ import print_function
from scapy.all import sniff

def examine_arp(packet):
    print(packet.summary())
    return

if __name__ == "__main__" :
    sniff(filter='arp', prn=examine_arp)

