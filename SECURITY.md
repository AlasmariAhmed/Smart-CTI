Security & Intended Use
Smart CTI is a DEFENSIVE tool for blue-team / SOC / CTI-analyst workflows only.

What it does
Pulls public IOCs (malicious IPs, domains, URLs, file hashes, CVEs) from OSINT feeds and filters them by your relevance lists (ASNs, keywords, countries) so defenders can prioritize threats.

What it does NOT do
❌ No active scanning, exploitation, or credential testing

❌ No payload generation or C2 code

❌ No offensive libraries (scapy, impacket, etc.)

The relevance lists are filters, not target generators
They answer "should I prioritize this IOC?" — not "what should I attack?" Ships empty by default.

Public feeds = public knowledge
Attackers can already see these blocklists. That's the point: raising their cost to rotate infrastructure benefits defenders more.

Auditable
All claims verifiable from source — connectors call hard-coded public URLs, rate-limited to 1 req/sec, no scanning code.

Authorized users
SOC teams, MSSPs, CTI researchers, academic/defensive use only. Not for offensive operations or surveillance.