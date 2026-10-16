# Detection Rules

This document describes the behavioral patterns used to classify attacker activity in LabCommand log analysis. Rules are heuristics applied manually during triage. They are starting points, not fixed thresholds, and should be tuned to the traffic profile of the site being analyzed.

## How to Use These Rules

1. Filter out known-good traffic first (see Exclusions below).
2. Group remaining requests by source IP and sort by request count and time window.
3. Match each IP to the category whose pattern fits best.
4. Enrich with AbuseIPDB, VirusTotal, OTX, and IPinfo.
5. Record the category, evidence, and confidence level in the incident report.

A single indicator is rarely enough. Classification is stronger when path pattern, timing, user agent, and status codes all agree.

## Exclusions (Filter Before Classifying)

- Own infrastructure and whitelisted administrator IPs
- Hosting platform cron traffic (POSTs to `/wp-cron.php` on a schedule)
- Platform uptime monitors (regular intervals, e.g. every ~10 minutes)
- Platform REST API backup and sync calls with valid authentication
- Verified search and AI crawlers (confirm by reverse DNS or published IP ranges, not user agent alone)
- Known security scanners that check `/security.txt` or `/trust.txt`

## Category 1: Scanners

**Behavior:** Broad probing for exposed files, configuration pages, and software versions.

**Indicators:**
- Sequential requests to diagnostic or config paths (`/phpinfo`, `/info.php`, `/test.php`, `/_profiler/phpinfo`)
- Requests for files that reveal installation details (`/wlwmanifest.xml`, `/readme.html`, `/license.txt`)
- Path obfuscation such as double slashes or fake directory prefixes (`//test/wp-includes/...`)
- Short bursts across many unrelated paths from one IP
- Mostly 403 or 404 responses

**Confidence guidance:** A single scanning hit is low confidence. Repeated sweeps across many diagnostic paths in one session are medium to high.

## Category 2: Scrapers

**Behavior:** High-volume content retrieval with no attack payload.

**Indicators:**
- Many GET requests to article pages, static assets, or plugin JS files
- Headless browser user agents (HeadlessChrome) or generic HTTP clients
- No attempts at login, admin, or exploit paths
- Mostly 200 responses, steady request rate

**Notes:** Scraping is not automatically malicious. Classify by behavior and monitor. Escalate only if it combines with attack indicators or abuse reports.

## Category 3: Shell Hunters

**Behavior:** Looking for existing webshells or planting-ready locations.

**Indicators:**
- Requests to known webshell filenames and fake plugin or core-file paths (`/wp-content/plugins/fix/up.php`, `/wp-includes/.../about.php`, `/wp-includes/images/wp-login.php`)
- Core-looking filenames in directories where WordPress does not place them
- Fast bursts (dozens of paths in seconds) from cloud-hosted IPs
- Same wordlist order seen across multiple IPs

**Important:** A shell-hunting attempt is not a compromise. Check whether the path exists, what status was returned, and whether a malware scan finds anything. Report as "consistent with webshell access attempts" unless a file is actually found.

## Category 4: Brute Forcers

**Behavior:** Credential guessing or username harvesting.

**Indicators:**
- Repeated requests to `/xmlrpc.php` or `/wp-login.php` from one IP
- POSTs to `xmlrpc.php` over a sustained window (possible `system.multicall` credential stuffing)
- Sequential `/?author=1` through `/?author=N` requests (username enumeration)
- Outdated or inconsistent user agents (for example Windows NT 6.3 x86 on a modern client)
- HTTP library user agents such as Apache-HttpClient or python-requests

**Notes:** A 200 response from `xmlrpc.php` means the endpoint answered. It does not mean a login succeeded.

## Additional Category: Callback and C2-Style Probing

**Behavior:** Repeated requests to a core file with randomized parameters.

**Indicators:**
- Requests to `/wp-load.php` with random query strings (for example `?[hex]=[int]`)
- Identical user agent and URL pattern across several IPs in the same network range
- Regular timing over multiple days, consistent with automated tooling

**Important:** `wp-load.php` commonly returns HTTP 200 with a blank page for almost any request on a normal WordPress install. A 200 does not confirm a webshell. Treat this as probing activity unless a malware scan or file integrity check shows otherwise.

## Campaign Correlation

Treat multiple IPs as one campaign only when several of these match:

- Same user agent string
- Same URL pattern or wordlist order
- Same /16 or ASN
- Overlapping or alternating time windows

A shared user agent alone is weak evidence. Common browser strings are reused by many unrelated bots. Use wording such as "consistent with the same campaign" and state a confidence level (low, medium, high).

## Status Code Interpretation

| Status | Meaning in this context |
|--------|--------------------------|
| 200 | Endpoint responded. Does not prove success or compromise. |
| 301/302 | Redirect. Check the target before drawing conclusions. |
| 401/403 | Blocked or unauthorized. Request was stopped. |
| 404 | Path does not exist. Common for scanners and fingerprinting. |
| 429 | Rate limited. Common for enumeration bursts. |

## Enrichment Checks

For each classified IP, record:

- **AbuseIPDB:** confidence score, report count, distinct sources, abuse categories
- **VirusTotal:** vendor detections, passive DNS, referring files
- **OTX:** pulse matches and related indicators
- **IPinfo:** ASN, organization, country
- **Hosting type:** residential or mobile carrier, cloud provider, or hosting provider

Residential and mobile carrier IPs may be compromised personal devices. Handle them carefully when publishing and avoid naming them.

## Confidence Levels

| Level | Meaning |
|-------|---------|
| Low | One indicator, or generic behavior with no corroboration |
| Medium | Two or more matching indicators, or corroboration from one external source |
| High | Multiple matching indicators plus external reputation data or repeated activity over time |

## Limitations

- Rules are applied manually. No automated detection pipeline is in use.
- Log fields available (timestamp, URL, method, IP, status, user agent) do not include request bodies, so POST payloads cannot be inspected.
- IP-based attribution is weak. IPs rotate and may belong to compromised devices or shared infrastructure.
- Findings describe observed behavior, not confirmed intent.

Part of the Log-Analysis-Playbook project.
