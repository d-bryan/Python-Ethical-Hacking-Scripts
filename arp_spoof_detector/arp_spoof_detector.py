#!/usr/bin/env python

import scapy.all as scapy
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", dest="interface", help="Enter an interface to test for attack")
options = parser.parse_args()

def get_mac(ip):
    #Arp request for specified ip address
    arp_request = scapy.ARP(pdst=ip)
    #broadcast to all other devices
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/ arp_request
    answered_arp_requests = scapy.srp(arp_request_broadcast, timeout=1, verbose = False)[0]
    return answered_arp_requests[0][1].hwsrc

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac = getmac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc

            if real_mac != response_mac:
                print("[+] You are under attack!")
        except IndexError:
            pass

sniff(options.interface)