# Tools and Scripts

This directory documents the tools used in support of LabCommand log analysis 
and threat intelligence operations. All tools listed are used in active 
analysis workflows.

---

## OSINT and Threat Intelligence Platforms

### [VirusTotal](https://www.virustotal.com)
Multi vendor malware and IP/domain reputation analysis. Used for vendor 
detection counts, passive DNS resolution history, referring file associations, 
and community sourced threat context on identified IPs.

### [AbuseIPDB](https://www.abuseipdb.com)
IP reputation and abuse reporting database. Used for confidence scoring, 
cumulative report counts, distinct source counts, and abuse category 
classification on attacker IPs.

### [AlienVault OTX](https://otx.alienvault.com)
Open threat exchange platform. Used for pulse lookups, indicator correlation, 
and cross-referencing IPs against known threat actor campaigns and infrastructure.

### [urlscan.io](https://urlscan.io)
URL and domain scanning and analysis. Used for inspecting suspicious domains 
associated with attacker infrastructure and passive DNS enrichment.

### [Shodan](https://www.shodan.io)
Internet facing infrastructure search engine. Used for surface exposure 
assessment and verifying what services and banners are visible on attacker IPs.

### [IPinfo](https://ipinfo.io)
GeoIP and ASN lookup service. Used for autonomous system number (ASN) 
identification, organization attribution, and geographic context on 
attacker IPs.

---

## Log Analysis and Data Handling

### Microsoft Excel
Spreadsheet application used for initial log handling, data cleanup, and 
structural preparation of raw CSV exports prior to analysis.

### Google Sheets
Cloud based spreadsheet environment used for log triage, IP classification, 
request pattern analysis, and IOC structuring across analysis sessions.

### Visual Studio Code
Code and text editor used for raw log file inspection, CSV review, and 
editing of repository files and documentation.

---

## Log Sources

### WAF and Web Application Logs
Primary log source. WAF and web application logs exported in CSV format
for analysis. Fields include timestamp, request URL, request method,
source IP, HTTP status code, and user agent.

---

## Notes

Tool selection prioritizes free tier and open source options wherever 
possible, consistent with LabCommand's research-focused operating model. 
All enrichment is performed manually : no automated ingestion pipelines 
are in use at this time.

---

*Part of the [Log-Analysis-Playbook](../README.md) project.*
