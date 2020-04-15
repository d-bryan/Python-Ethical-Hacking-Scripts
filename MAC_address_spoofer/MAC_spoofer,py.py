#!/usr/bin/env python

import scapy.all as scapy
import optparse

def scan(ip):
    #Arp request for specified ip address
    arp_request = scapy.ARP(pdst=ip)

    #broadcast to all other devices
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    arp_request_broadcast = broadcast/ arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose = False)[0]

    return answered_list

def print_ip(valid_ip_and_macs):
    print(" [] Ip Addresses" + "\t" +"[] Mac Addresses" + "\n=================================================")
    for ip_and_mac in valid_ip_and_macs:
        print(ip_and_mac[1].psrc + "\t\t" + ip_and_mac[1].hwsrc)
        print("=================================================")

def get_user_args():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--ip_address", dest="ip_address", help="Enter IP address range to scan")
    (options, arguments) = parser.parse_args()

    if options.ip_address:
        return options.ip_address
    else:
        print("Please enter valid IP address range")

ip_address_range = get_user_args()
valid_ip_and_macs = scan(ip_address_range)
print_ip(valid_ip_and_macs)