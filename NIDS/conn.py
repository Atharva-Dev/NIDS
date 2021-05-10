import eel
import threading
from nids import nids

    
eel.init("UI")

sniffer = nids(eel.action_upon_detecting_arp_spoof, eel.action_upon_detecting_syn_flood)

def start_in_background():
    global sniffer
    thread = threading.Thread(target=sniffer.start, args=())
    thread.daemon = True
    thread.start()

@eel.expose
def get_vals(arp_spoof_checked, syn_flood_checked):
    global sniffer
    sniffer.detect_arp_spoofing = arp_spoof_checked
    sniffer.detect_syn_flood = syn_flood_checked
    print(sniffer.detect_arp_spoofing, sniffer.detect_syn_flood)
    start_in_background()

@eel.expose    
def stop_sniff():
    global sniffer
    print('stop clicked!')
    sniffer.done = True
eel.start("index.html", size=(380, 400), port=8000)
