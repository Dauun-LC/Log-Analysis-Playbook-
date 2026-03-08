# Incident Report Template

# Threat Intelligence Report: [SITE OR INFRASTRUCTURE NAME] Log Analysis

**Period:** [START DATE] – [END DATE]
**Analyst:** [ANALYST NAME OR HANDLE]
**Status:** [Draft / Final]
**Repository:** [REPOSITORY NAME]

---

## Executive Summary

During the period of [START DATE]–[END DATE], [SITE OR INFRASTRUCTURE NAME] 
experienced [BRIEF DESCRIPTION OF ACTIVITY — e.g. sustained automated attack 
activity / isolated scanning events / targeted exploitation attempts] across 
[NUMBER] distinct threat categories. All activity was [blocked / partially 
blocked / not blocked] by [WAF AND DEFENSIVE LAYER DESCRIPTION — redact as 
appropriate]. Analysis of [TOTAL LOG ENTRIES] log entries identified 
[NUMBER] unique attacker IPs, enriched against AbuseIPDB and VirusTotal.

Notable findings include: [FINDING 1], [FINDING 2], [FINDING 3].

---

## Methodology

[LOG SOURCE DESCRIPTION — redact specifics as appropriate] logs were exported 
and triaged in [ANALYSIS ENVIRONMENT — redact as appropriate]. Own 
infrastructure IPs, legitimate platform IPs, and verified crawlers were 
filtered out, reducing [TOTAL LOG ENTRIES] rows to [NUMBER] unique blocked 
attacker IPs. Each IP was categorized by behavioral pattern and enriched 
using AbuseIPDB (confidence score, report count, source count, categories) 
and VirusTotal (vendor detections, passive DNS, referring files, community 
notes). IOCs were recorded in structured CSV format by category.

---

## Findings by Category

### 1. Scanners ([NUMBER] IPs)

[DESCRIPTION OF SCANNING ACTIVITY — user agents observed, endpoints targeted, 
behavioral patterns noted.]

Most significant finding: [IP ADDRESS] ([ASN, COUNTRY]) — [DESCRIPTION OF 
WHY THIS IP IS NOTABLE]. [ABUSEIPDB CONFIDENCE]% confidence, [NUMBER] reports 
from [NUMBER] sources. VirusTotal: [NUMBER]/94 vendors malicious.

[ADD ADDITIONAL SCANNER ENTRIES AS NEEDED]

---

### 2. Scrapers ([NUMBER] IPs)

[DESCRIPTION OF SCRAPING ACTIVITY — request volume, endpoints targeted, 
behavioral patterns noted.]

**[IP ADDRESS] ([ASN, COUNTRY]):** [DESCRIPTION OF SCRAPING BEHAVIOR — 
number of requests, content targeted, session characteristics]. AbuseIPDB 
confidence [NUMBER]%, [NUMBER] reports from [NUMBER] sources. VirusTotal: 
[NUMBER]/94 vendors malicious. Behavior consistent with [ASSESSMENT — e.g. 
content aggregation / AI training data collection / SEO harvesting].

[ADD ADDITIONAL SCRAPER ENTRIES AS NEEDED]

---

### 3. Shell Hunters ([NUMBER] IPs)

[NUMBER] campaign(s) identified.

**Campaign [NUMBER] — [INFRASTRUCTURE LABEL e.g. Azure Japan] 
([IP ADDRESS(ES)]):** [DESCRIPTION OF SHELL HUNTING ACTIVITY — paths probed, 
toolkit characteristics, session timing, coordination indicators]. AbuseIPDB 
confidence [NUMBER]%, [NUMBER] reports from [NUMBER] sources. VirusTotal: 
[NUMBER]/94 vendors malicious.

[ADD ADDITIONAL SHELL HUNTER CAMPAIGNS AS NEEDED]

---

### 4. Brute Forcers ([NUMBER] IPs)

[NUMBER] IPs targeted [AUTHENTICATION ENDPOINTS — redact specifics as 
appropriate].

**[INFRASTRUCTURE LABEL e.g. Lithuanian Infrastructure] ([IP ADDRESS(ES)], 
[ASN]):** [DESCRIPTION OF BRUTE FORCE ACTIVITY — user agents, endpoints 
targeted, volume, timing]. AbuseIPDB confidence [NUMBER]%, [NUMBER] reports 
from [NUMBER] sources. VirusTotal: [NUMBER]/94 vendors malicious. 
[ADDITIONAL INFRASTRUCTURE CONTEXT IF APPLICABLE — e.g. phishing domains 
in passive DNS, criminal ASN designation].

[ADD ADDITIONAL BRUTE FORCER ENTRIES AS NEEDED]

---

### 5. Additional Categories ([NUMBER] IPs)

*Use this section if new threat behavior types are identified that do not 
fit the four established categories above. Define the category, describe 
the behavior pattern, and document IOCs using the same structure as above. 
Update the IOC CSV directory and README accordingly when adding a new 
category.*

[CATEGORY NAME — e.g. Exploit Delivery / C2 Callbacks / Data Exfiltration]

**[IP ADDRESS] ([ASN, COUNTRY]):** [DESCRIPTION OF BEHAVIOR]. AbuseIPDB 
confidence [NUMBER]%, [NUMBER] reports from [NUMBER] sources. VirusTotal: 
[NUMBER]/94 vendors malicious.

[ADD ADDITIONAL ENTRIES AS NEEDED]

---

## Threat Actor Infrastructure Observations

Several patterns emerged across categories that suggest shared infrastructure 
or coordinated campaigns:

- [OBSERVATION 1 — e.g. shared toolkits, identical wordlists, timing correlation]
- [OBSERVATION 2 — e.g. shared referring files in VirusTotal, passive DNS overlap]
- [OBSERVATION 3 — e.g. ASN serving dual criminal purpose]
- [ADD ADDITIONAL OBSERVATIONS AS NEEDED]
- (Omitted for privacy — redact as appropriate)

---

## Defensive Posture Assessment

All [NUMBER] IPs were blocked at the [DEFENSIVE LAYER DESCRIPTION — redact 
as appropriate]. No successful intrusions were detected. The following 
observations apply:

- [OBSERVATION 1 — e.g. residual exposure, accepted risk items]
- [OBSERVATION 2]
- (Omitted for privacy — redact as appropriate)

---

## IOC Summary

| Category | IPs | Total Requests | All Blocked |
|---|---|---|---|
| Scanners | [NUMBER] | [NUMBER] | [Yes / No / Partial] |
| Scrapers | [NUMBER] | [NUMBER] | [Yes / No / Partial] |
| Shell Hunters | [NUMBER] | [NUMBER] | [Yes / No / Partial] |
| Brute Forcers | [NUMBER] | [NUMBER] | [Yes / No / Partial] |
| Additional Categories | [NUMBER] | [NUMBER] | [Yes / No / Partial] |
| **Total** | **[NUMBER]** | **[NUMBER]** | **[Yes / No / Partial]** |

Full IOC data available in /iocs/ directory.

---

## Recommendations

1. [RECOMMENDATION 1 — e.g. continue monitoring specific IPs or ASNs]
2. [RECOMMENDATION 2 — e.g. consider blocking specific ASN at network level]
3. [RECOMMENDATION 3 — e.g. monitor specific cloud provider traffic]
4. [ADD ADDITIONAL RECOMMENDATIONS AS NEEDED]
5. (Omitted for privacy — redact as appropriate)

---

*Report prepared as part of ongoing [PROJECT NAME] security research and 
threat intelligence documentation.*
**REDACTED/OMITTED FOR PRIVACY WHERE INDICATED**
