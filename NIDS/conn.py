import eel
import threading
from pynotifier import Notification
from nids import nids

    
eel.init("UI")

def action_upon_detecting_arp_spoof():
    eel.action_upon_detecting_arp_spoof()
    sniffer.finish()
    Notification(
    app_name = 'NIDS',
	title='ARP spoof attack detected',
	description='someone is attacking your pc with arp spoofing attack!!',
	duration=5,                              
	urgency='normal',
    icon_path="/home/atharva/Desktop/semII/MiniProject/NIDS/alert.png",
    ).send()
    


def action_upon_detecting_syn_flood():
    eel.action_upon_detecting_syn_flood()
    sniffer.finish()
    Notification(
    app_name = 'NIDS',
	title='Syn Flood attack detected',
	description='someone is attacking your server with syn flood attack!!',
	duration=5,                              
	urgency='normal',
    icon_path="/home/atharva/Desktop/semII/MiniProject/NIDS/alert.png",
    ).send()
    


sniffer = nids(action_upon_detecting_arp_spoof, action_upon_detecting_syn_flood)

def start_in_background():
    global sniffer
    thread = threading.Thread(target=sniffer.start, args=())
    thread.daemon = True
    thread.start()

@eel.expose
def get_vals(arp_spoof_checked, syn_flood_checked, max_open_conn):
    global sniffer 
    sniffer.detect_arp_spoofing = arp_spoof_checked
    sniffer.detect_syn_flood = syn_flood_checked
    print(sniffer.detect_arp_spoofing, sniffer.detect_syn_flood, max_open_conn)
    if(sniffer.detect_syn_flood) : 
        sniffer.set_tcp_open_port_threshold(int(max_open_conn))
        sniffer.reset_open_ports()
    start_in_background()

@eel.expose    
def stop_sniff():
    global sniffer
    print('stop clicked!')
    
    sniffer.finish()
eel.start("index.html", size=(400, 400), port=8001)

