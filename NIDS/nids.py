from __future__ import print_function
from collections import defaultdict
from scapy.all import sniff, Ether


class nids_back:

    def __init__(self):
        self.apr_responces = defaultdict(lambda: 0)
        self.tcp_open_ports = 0
        self.tcp_open_port_threshold = 100
        self.my_mac = Ether().src
        self.arp_spoofed = False
        self.syn_flooded = False

    def start(self):
        sniff(filter='tcp or arp', prn=self.examine, store = False)

    def set_tcp_open_port_threshold(self, threshold):
        self.tcp_open_port_threshold = threshold

    def check_syn_flood(self, packet) :
        print(packet.show())
        return
        if packet['TCP'].flags.S:
            self.tcp_open_ports += 1
        elif packet['TCP'].flags.A and not packet['TCP'].flags.SA:
            self.tcp_open_ports -= 1
        if self.tcp_open_ports > self.tcp_open_port_threshold :
            syn_flooded = True
        
    def varify_mac(self, target_ip):
        request_arp = scapy.ARP(pdst = target_ip)
        br = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_req_br = br / request_arp
        list_1 = scapy.srp(arp_req_br, timeout=5,verbose=False)[0]
        return list_1[0][1].hwsrc

    def check_arp_spoofing(self, packet):
        who_has = 1;
        is_at = 2;
        if packet['ARP'].op == is_at :
            received_mac = packet['ARP'].hwsrc
            checked_mac = varify_mac(packet['ARP'].psrc)
            if received_mac != checked_mac :
                arp_spoofed = True

        
    def examine(self, packet):
        if self.my_mac != packet['Ether'].src :
            if 'TCP' in packet : self.check_syn_flood(packet)
            if 'ARP' in packet : self.check_arp_spoofing(packet)
            print(self.tcp_open_ports)

    

if __name__ == "__main__" :
    s = nids_back()
    print(s.my_mac)
    s.start()
