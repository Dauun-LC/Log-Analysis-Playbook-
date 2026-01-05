# Log Analysis Playbook

## Purpose
Provide a repeatable workflow for analyzing web application access logs, identifying scanner/bot activity, validating anomalies, and confirming whether traffic represents reconnaissance, exploitation, or benign noise.

## Scope
* Managed hosting environment
* Limited server access (no direct server configuration)
* Security plugins as primary controls
* CSV log exports from hosting dashboard

## Prerequisites
* Access to hosting dashboard (Admin role)
* Security monitoring plugins active
* Python 3.8+ (for automation scripts)
* Familiarity with CSV parsing
  
## Workflow Overview

### 1. Collect Logs
* Export access logs in CSV format
* Identify key fields: `timestamp`, `request_url`, `request_type`, `user_ip`, `status`, `user_agent`
* **Retention period**: Document how long logs are available (typically 7-30 days)
* **Export procedure**: Access via hosting dashboard > Logs > Export CSV

### 2. Establish Baseline
* Identify known-good IPs (admin, platform infrastructure)
* Identify expected scanner noise patterns (datacenter ASNs, common endpoints)

**Known-Good IPs to Document:**
* Your admin IP(s) (home, VPN, work)
* Platform infrastructure IPs
* Security scanner IPs (from your plugins)
* Known CDN/caching services (if applicable)

**Expected Scanner Patterns:**
* Common endpoints: `/wp-json/`, `/.well-known/`, `/sitemap.xml`
* Legitimate crawlers: Googlebot, Bingbot (verify via reverse DNS)
* ASN patterns: Document common datacenter ASNs (DigitalOcean, AWS, etc.)

### 3. Classify IPs
* Admin
* Platform infrastructure
* Legitimate crawlers
* Commodity scanners
* Unknown / needs review

### 4. Detect Reconnaissance
* Repeated hits to common target endpoints
* Randomized query strings
* POSTs from datacenter IPs

### 5. Detect Exploitation Attempts
* Encoded payloads
* Plugin exploit paths
* Suspicious POST bodies
* File upload endpoints

### 6. Detect Privilege Escalation
* Unknown IPs accessing admin areas
* REST API modification attempts
* Admin-ajax privilege actions
* Admin actions without login attempts

### 7. Validate Findings
* Confirm whether traffic is benign scanner noise
* Document anomalies
* Verify no indicators of compromise

### 8. Document Outcome
* Summary of findings
* Indicators observed
* Indicators not observed
* Final assessment

## Tools & Automation

### IP Classification
* **AbuseIPDB**: Check reputation scores
* **GreyNoise**: Identify mass-scanning IPs
* **IPinfo.io**: ASN/datacenter detection

### Log Analysis
* **jq/csvkit**: Parse CSV logs
* **Python pandas**: Pattern analysis
* **Splunk/ELK** (if available): Centralized logging

### Sample Commands
```bash
# Extract unique IPs hitting login pages
cat access.csv | grep "login" | cut -d',' -f4 | sort -u

# Count requests per IP
cat access.csv | cut -d',' -f4 | sort | uniq -c | sort -rn

# Find POST requests to non-standard endpoints
cat access.csv | awk -F',' '$3=="POST" && $2 !~ /login|xmlrpc/ {print}'
```

## Detection Rules

See [docs/detection-rules.md](docs/detection-rules.md) for detailed rule logic.

### Recon Detection
```
IF request_url CONTAINS (common_targets)
AND user_ip NOT IN admin_ips
THEN FLAG "RECON"
```

### Suspicious POST
```
IF request_type = POST
AND request_url NOT IN (expected_post_endpoints)
THEN FLAG "SUSPICIOUS_POST"
```

### Admin Anomaly
```
IF request_url CONTAINS "admin"
AND user_ip NOT IN admin_ips
THEN FLAG "ADMIN_ANOMALY"
```

### Privilege Escalation Attempt
```
IF request_url CONTAINS ("user-edit" OR "options" OR "theme-editor")
AND user_ip NOT IN admin_ips
THEN FLAG "PRIV_ESC"
```
