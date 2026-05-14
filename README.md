# Lab-Local-DNS-Attack

## Full Documentation
You can view the full tchnical report here: [Local DNS Attack Lab (PDF)](./Lab-Local-DNS-Attack.pdf)

## Project Overview
This project demonstrates the vulnerabilities inherent in the Domain Name System (DNS). Using a "Sniff-then-Spoof" approach, I successfully intercepted DNS queries and provided fraudulent responses to redirect traffic from legitimate sites (like Facebook) to an attacker-controlled IP address.

## Technical Skills Demonstrated
* **Network Protocol Analysis:** Deep understanding of DNS Query/Response structure, including Question, Answer, and Additional sections.
* **Traffic Interception:** Used **Scapy** to sniff local network traffic and trigger automated responses.
* **Service Redirection:** Successfully poisoned a target's DNS cache to facilitate a Man-in-the-Middle (MITM) scenario.
* **Tools:** Scapy (Python), Dig, Docker, Linux.
* **Environment:** Seed Labs (Ubuntu VM) https://seedsecuritylabs.org/Labs_20.04/Files/DNS_Local/DNS_Local.pdf

## Lab Breakdown

### 1. DNS Environment Verification
Verified the environment by querying a local DNS server for `ns.attacker32.com` and confirming the response via the `dig` command. 

### 2. The Sniff-and-Spoof Attack
I developed a Python script that listens for DNS queries on the local network. When a query is detected, the script immediately generates a spoofed DNS response.
* **Mechanism:** The script copies the Transaction ID from the original query to ensure the victim's machine accepts the fake response as legitimate.
* **Payload Manipulation:** I modified the **Answer Section** to point a domain to a malicious IP and updated the **Additional Section** to include fraudulent name server records.

### 3. Cache Poisoning
By providing multiple records in the "Additional" and "Authoritative" sections of the DNS packet, I demonstrated how an attacker can stay "persistent" in a victim's cache, redirecting future traffic without needing to sniff every subsequent packet.

## Defensive Strategy (SOC Perspective)
To mitigate these types of attacks, security operations should prioritize:
* **DNSSEC Deployment:** Using digital signatures to ensure DNS data is authentic and has not been tampered with.
* **Monitoring:** Detecting multiple DNS responses for a single query or identifying "unsolicited" DNS replies on the network.
* **Recursive Resolver Hardening:** Limiting the DNS servers that internal hosts are allowed to query.
