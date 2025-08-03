#!/usr/bin/env python3
import socket
import ssl
import requests
import ipaddress
import json
import sys

IPINFO_URL = "https://ipinfo.io/{ip}/json"
AWS_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
DEFAULT_PORT = 443

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def fetch_aws_ranges():
    try:
        r = requests.get(AWS_RANGES_URL, timeout=5)
        return r.json().get("prefixes", [])
    except:
        return []

def match_aws_service(ip, ranges):
    ip_obj = ipaddress.ip_address(ip)
    for entry in ranges:
        if ip_obj in ipaddress.ip_network(entry["ip_prefix"]):
            return entry["service"], entry["region"], entry["ip_prefix"]
    return None, None, None

def fetch_ipinfo(ip):
    try:
        r = requests.get(IPINFO_URL.format(ip=ip), timeout=5)
        return r.json()
    except:
        return {}

def classify_hostname(hostname):
    if not hostname:
        return "unknown"
    if "cloudfront.net" in hostname:
        return "CloudFront CDN"
    elif "elb.amazonaws.com" in hostname:
        return "AWS ELB"
    elif "compute" in hostname:
        return "AWS EC2"
    elif "cloudflare" in hostname:
        return "Cloudflare"
    elif "azure" in hostname or "microsoft" in hostname:
        return "Azure"
    elif "fastly" in hostname:
        return "Fastly"
    elif "akamai" in hostname:
        return "Akamai"
    return "Unknown or custom"

def tls_inspect(ip, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                cn = subject.get('commonName', '')
                return cn
    except:
        return None

def http_headers(ip, port=80):
    try:
        url = f"http://{ip}:{port}"
        r = requests.get(url, timeout=5)
        return dict(r.headers)
    except:
        return {}

def classify_ip(ip, port, aws_ranges):
    result = {
        "ip": ip,
        "port": port,
        "reverse_dns": None,
        "ipinfo_org": None,
        "aws_service": None,
        "aws_region": None,
        "aws_prefix": None,
        "tls_common_name": None,
        "http_headers": {},
        "classification": None,
        "likely_role": "unclassified"
    }

    rdns = reverse_dns(ip)
    result["reverse_dns"] = rdns

    aws_service, aws_region, aws_prefix = match_aws_service(ip, aws_ranges)
    result["aws_service"] = aws_service
    result["aws_region"] = aws_region
    result["aws_prefix"] = aws_prefix

    ipinfo = fetch_ipinfo(ip)
    result["ipinfo_org"] = ipinfo.get("org", "unknown")

    result["classification"] = classify_hostname(rdns or '') or result["ipinfo_org"]

    tls_cn = tls_inspect(ip, port)
    result["tls_common_name"] = tls_cn

    headers = http_headers(ip)
    result["http_headers"] = headers

    if 'cf-ray' in headers or 'cloudflare' in (result["ipinfo_org"] or "").lower():
        result["likely_role"] = "Cloudflare WAF/CDN"
    elif 'x-amzn-trace-id' in headers:
        result["likely_role"] = "AWS Load Balancer or API Gateway"
    elif 'akamai' in (result["ipinfo_org"] or "").lower():
        result["likely_role"] = "Akamai Edge / WAF"
    elif tls_cn and 'cloudfront' in tls_cn:
        result["likely_role"] = "CloudFront CDN"

    return result

def classify_bulk(ips, port=DEFAULT_PORT):
    aws_ranges = fetch_aws_ranges()
    results = [classify_ip(ip.strip(), port, aws_ranges) for ip in ips if ip.strip()]
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 classify_cloud_service.py <ip1> <ip2> ...")
        print("   or: python3 classify_cloud_service.py -f ip_list.txt")
        sys.exit(1)

    if sys.argv[1] == "-f":
        with open(sys.argv[2], 'r') as f:
            ips = f.readlines()
    else:
        ips = sys.argv[1:]

    classify_bulk(ips)

