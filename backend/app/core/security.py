import os
import re
import socket
import ipaddress
import urllib.parse
from typing import Tuple, Optional


# List of blocked IP ranges for SSRF defense
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # Cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),   # Carrier-grade NAT
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("224.0.0.0/4"),     # Multicast
    ipaddress.ip_network("240.0.0.0/4"),     # Reserved
    ipaddress.ip_network("::1/128"),         # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),        # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),       # IPv6 link-local
    ipaddress.ip_network("::ffff:0:0/96"),   # IPv4-mapped IPv6
]

# Blocked hostnames
BLOCKED_HOSTNAMES = {
    "localhost",
    "127.0.0.1",
    "metadata.google.internal",
    "instance-data",
    "169.254.169.254",
}


def validate_url_safety(target_url: str) -> Tuple[bool, str]:
    """
    Validates that a URL does not attempt Server-Side Request Forgery (SSRF),
    cloud metadata theft, or internal network scanning.
    """
    if not target_url or not isinstance(target_url, str):
        return False, "Invalid URL input"

    try:
        parsed = urllib.parse.urlparse(target_url.strip())
    except Exception as e:
        return False, f"Malformed URL: {str(e)}"

    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Unsupported scheme: {parsed.scheme}. Only HTTP/HTTPS allowed."

    hostname = parsed.hostname
    if not hostname:
        return False, "URL missing hostname"

    hostname_lower = hostname.lower()

    if hostname_lower in BLOCKED_HOSTNAMES or hostname_lower.endswith(".internal") or hostname_lower.endswith(".local"):
        return False, f"Access to private/internal hostname '{hostname}' is blocked."

    # Resolve hostname to IP addresses and check each
    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        # Domain does not resolve to an active IP address, so it cannot reach internal resources
        return True, f"Domain name '{hostname}' could not be resolved (safe from internal SSRF)."

    for item in addr_info:
        ip_str = item[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for net in BLOCKED_NETWORKS:
                if ip_obj in net:
                    return False, f"URL resolves to restricted/internal IP {ip_str}."
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
                return False, f"URL resolves to private/loopback IP {ip_str}."
        except ValueError:
            return False, f"Invalid resolved IP: {ip_str}"

    return True, "URL is safe from SSRF"


def sanitize_filename(filename: str) -> str:
    """
    Prevents path traversal and shell injection by strictly sanitizing file names.
    """
    basename = os.path.basename(filename)
    # Remove directory traversal patterns
    cleaned = re.sub(r'[^a-zA-Z0-9_.-]', '_', basename)
    # Limit length
    if len(cleaned) > 120:
        name, ext = os.path.splitext(cleaned)
        cleaned = name[:100] + ext
    return cleaned or "unnamed_file"


def check_prompt_injection(text: str) -> Tuple[bool, float, Optional[str]]:
    """
    Detects potential prompt injection attempts inside untrusted content.
    Returns (is_injection_detected, suspicion_score, description).
    """
    injection_patterns = [
        (r"(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions?", 0.9, "Instruction override attempt"),
        (r"(?i)system\s+prompt", 0.7, "System prompt mention"),
        (r"(?i)you\s+are\s+now\s+(a\s+)?(helpful\s+assistant|DAN|developer)", 0.85, "Persona hijacking attempt"),
        (r"(?i)classify\s+(this|me)\s+as\s+(safe|legitimate|clean)", 0.8, "Verdict manipulation attempt"),
        (r"(?i)disregard\s+security\s+rules?", 0.9, "Security rule bypass attempt"),
        (r"(?i)print\s+your\s+instructions", 0.75, "Prompt extraction attempt"),
        (r"(?i)do\s+not\s+flag\s+this", 0.7, "Evasion instruction"),
    ]

    for pattern, score, reason in injection_patterns:
        match = re.search(pattern, text)
        if match:
            return True, score, f"Detected adversarial prompt injection pattern: '{match.group(0)}' ({reason})"

    return False, 0.0, None
