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
