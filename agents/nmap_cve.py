"""
Agent: Nmap Service Scan + CVE Matcher
Runs nmap -sV against a target, pulls product/version per open port, and
checks each against the NVD CVE API (cached locally so repeat scans and
repeat report generation don't re-hit the network). Writes one 'cve_match'
finding per open service.

Requires: pip install python-nmap
Requires the 'nmap' binary to be installed on whatever host actually runs
this (apt install nmap). It does NOT need root for -sV (only -O / SYN scans
need raw sockets / root).
"""

import os
import time

import nmap
import requests

import db

NVD_API_URL = "https://services.nvd.nih.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY")  # optional, raises rate limit 5->50 req/30s


def run_nmap_scan(target_ip):
    scanner = nmap.PortScanner()
    scanner.scan(target_ip, arguments="-sV -T4")

    results = []
    if target_ip not in scanner.all_hosts():
        return results

    for proto in scanner[target_ip].all_protocols():
        for port, info in scanner[target_ip][proto].items():
            results.append(
                {
                    "port": port,
                    "protocol": proto,
                    "service": info.get("name"),
                    "product": info.get("product"),
                    "version": info.get("version"),
                    "state": info.get("state"),
                }
            )
    return results


def lookup_cves(product, version):
    if not product or not version:
        return []

    query = f"{product} {version}".strip()

    cached = db.cve_cache_get(query)
    if cached is not None:
        return cached

    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    params = {"keywordSearch": query, "resultsPerPage": 10}

    resp = requests.get(NVD_API_URL, headers=headers, params=params, timeout=15)
    # Unauthenticated NVD limit is 5 req/30s - stay well under it
    time.sleep(1 if NVD_API_KEY else 6)

    if resp.status_code != 200:
        return []

    data = resp.json()
    cves = [
        {
            "id": item["cve"]["id"],
            "description": (
                item["cve"]["descriptions"][0]["value"]
                if item["cve"].get("descriptions")
                else ""
            ),
        }
        for item in data.get("vulnerabilities", [])
    ]

    db.cve_cache_set(query, cves)
    return cves


def run(session_id, target_ip):
    services = run_nmap_scan(target_ip)
    for svc in services:
        if svc.get("state") != "open":
            continue
        cves = lookup_cves(svc.get("product"), svc.get("version"))
        db.add_finding(
            session_id=session_id,
            agent="nmap_cve",
            finding_type="cve_match",
            data={**svc, "cves": cves},
            target=target_ip,
        )
    return services