from __future__ import print_function
from collections import defaultdict
from scapy.all import sniff, Ether


apr_responces = defaultdict(lambda: 0)
tcp_open_ports = 0
tcp_open_port_threshold = 100
my_mac = Ether().src

def set_tcp_open_port_threshold(threshold):
    global tcp_open_port_threshold
    tcp_open_port_threshold = threshold

def check_syn_flood(packet) :
    global tcp_open_ports
    if packet['TCP'].flags.S:
        tcp_open_ports += 1
    if packet['TCP'].flags.A:
        tcp_open_ports -= 1
    if tcp_open_ports > tcp_open_port_threshold :
        #todo alert !!
    
def varify_mac(target_ip):
    request_arp = scapy.ARP(pdst = target_ip)
    br = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_br = br / arp_request
    list_1 = scapy.srp(arp_req_br, timeout=5,verbose=False)[0]
    return list_1[0][1].hwsrc

def check_arp_spoofing(packet):
    who_has = 1;
    is_at = 2;
    if packet['ARP'].op == is_at :
        received_mac = packet['ARP'].hwsrc
        checked_mac = varify_mac(packet['ARP'].psrc)
        if received_mac != checked_mac :
            #todo alert !!

    
def examine(packet):
    if my_mac != packet['Ether'].src :
        if 'TCP' in packet : check_syn_flood(packet)
        if 'ARP' in packet : check_arp_spoofing(packet)

if __name__ == "__main__" :
    sniff(filter='tcp or arp', prn=examine, store = False)
    print(apr_responces)

