"""
Phishing Email Analyzer
------------------------
Parses a .eml file and scores it for phishing indicators across four
categories: header red flags, sender-domain trustworthiness, suspicious
URLs, and social-engineering language patterns.

Usage:
    python analyzer.py path/to/email.eml
    python analyzer.py data/samples/          # analyze every .eml in a folder
"""

import argparse
import email
import glob
import os
import re
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse

# Known brand names commonly impersonated in phishing, used only to detect
# lookalike domains (e.g. "paypa1.com" instead of "paypal.com") — not an
# exhaustive list, just enough for demo/detection purposes.
COMMONLY_IMPERSONATED_BRANDS = [
    "paypal", "microsoft", "apple", "amazon", "google", "netflix",
    "bankofamerica", "wellsfargo", "chase", "dhl", "fedex", "dropbox",
]

FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "icloud.com", "mail.com", "protonmail.com",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
}

SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".zip", ".loan", ".gq", ".tk", ".work"}

URGENCY_PHRASES = [
    "act now", "immediately", "urgent", "act within", "suspend", "suspended",
    "limited access", "verify your account", "confirm your identity",
    "unusual activity", "unauthorized access", "expire", "final notice",
    "failure to", "restricted", "will be closed", "will be deleted",
    "action required", "avoid interruption", "within 12 hours", "within 24 hours",
]

CREDENTIAL_REQUEST_PHRASES = [
    "confirm your password", "enter your password", "update your payment",
    "verify your credentials", "provide your ssn", "confirm your credit card",
    "click here to verify", "login to confirm", "re-enter your details",
]

GENERIC_GREETINGS = ["dear customer", "dear user", "dear valued customer", "dear sir/madam", "dear account holder"]

URL_RE = re.compile(r"https?://[^\s\"'<>]+")
HREF_RE = re.compile(r'href=[\'"]([^\'"]+)[\'"][^>]*>([^<]*)', re.IGNORECASE)
IP_HOST_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def load_email(path: str):
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def get_body_text(msg) -> str:
    """Extract combined plain-text + stripped-HTML body for content analysis."""
    parts = []
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                parts.append(part.get_content())
            elif content_type == "text/html":
                # crude tag strip — good enough for keyword/link scanning
                html = part.get_content()
                parts.append(re.sub(r"<[^>]+>", " ", html))
    else:
        parts.append(msg.get_content())
    return "\n".join(parts)


def get_body_html(msg) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                return part.get_content()
    elif msg.get_content_type() == "text/html":
        return msg.get_content()
    return ""


def extract_domain(address: str) -> str:
    match = re.search(r"@([\w\.-]+)", address or "")
    return match.group(1).lower() if match else ""


def analyze_headers(msg) -> list:
    """Check From/Reply-To mismatch and authentication results."""
    findings = []

    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    from_domain = extract_domain(from_header)
    reply_domain = extract_domain(reply_to) if reply_to else ""

    if reply_domain and reply_domain != from_domain:
        findings.append({
            "severity": "high",
            "category": "header",
            "message": f"Reply-To domain ({reply_domain}) does not match From domain ({from_domain}) — "
                       f"replies would go somewhere different from where the mail claims to originate.",
        })

    auth_results = msg.get("Authentication-Results", "")
    if auth_results:
        auth_lower = auth_results.lower()
        for mechanism in ("spf", "dkim", "dmarc"):
            if f"{mechanism}=fail" in auth_lower or f"{mechanism}=softfail" in auth_lower:
                findings.append({
                    "severity": "high",
                    "category": "header",
                    "message": f"{mechanism.upper()} check failed — the sending server is not authorized "
                               f"to send mail for this domain.",
                })
    else:
        findings.append({
            "severity": "medium",
            "category": "header",
            "message": "No Authentication-Results header present — SPF/DKIM/DMARC status could not be verified.",
        })

    return findings


def analyze_sender_domain(msg) -> list:
    """Check display-name vs domain mismatch, lookalike domains, and free-mail impersonation."""
    findings = []
    from_header = msg.get("From", "")
    from_domain = extract_domain(from_header)

    display_name_match = re.match(r'^"?([^"<]+)"?\s*<', from_header)
    display_name = display_name_match.group(1).strip().lower() if display_name_match else ""

    for brand in COMMONLY_IMPERSONATED_BRANDS:
        if brand in display_name and brand not in from_domain:
            findings.append({
                "severity": "high",
                "category": "sender_domain",
                "message": f"Display name references '{brand}' but the sending domain "
                           f"('{from_domain}') has no relation to {brand}'s real domain — "
                           f"a classic brand-impersonation pattern.",
            })
            break

    # crude lookalike check: brand name with a digit substituted for a letter, or
    # brand name immediately followed by extra words in the domain
    for brand in COMMONLY_IMPERSONATED_BRANDS:
        leet_variants = [
            brand.replace("o", "0"), brand.replace("l", "1"), brand.replace("i", "1"),
            brand.replace("a", "4"), brand.replace("e", "3"),
        ]
        if any(variant in from_domain and variant != brand and brand not in from_domain for variant in leet_variants):
            findings.append({
                "severity": "high",
                "category": "sender_domain",
                "message": f"Sending domain '{from_domain}' looks like a character-substituted "
                           f"lookalike of '{brand}.com' (e.g. '0' for 'o', '1' for 'l/i').",
            })
            break

    if from_domain in FREE_MAIL_DOMAINS and any(
        term in display_name for term in ["support", "security", "helpdesk", "admin", "billing", "it "]
    ):
        findings.append({
            "severity": "medium",
            "category": "sender_domain",
            "message": f"Claims to be an official support/security team but sends from a free "
                       f"consumer mail domain ('{from_domain}') rather than a corporate domain.",
        })

    return findings


def analyze_urls(msg) -> list:
    """Check for IP-based links, URL shorteners, suspicious TLDs, and anchor-text mismatches."""
    findings = []
    body_text = get_body_text(msg)
    body_html = get_body_html(msg)

    urls_found = set(URL_RE.findall(body_text))

    for url in urls_found:
        host = urlparse(url).hostname or ""
        if IP_HOST_RE.match(host):
            findings.append({
                "severity": "high",
                "category": "url",
                "message": f"Link points directly to a raw IP address ({host}) instead of a domain name — "
                           f"legitimate organizations almost never do this.",
            })
        if host in URL_SHORTENERS:
            findings.append({
                "severity": "medium",
                "category": "url",
                "message": f"Link uses a URL shortener ({host}), which hides the real destination.",
            })
        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            findings.append({
                "severity": "medium",
                "category": "url",
                "message": f"Link uses a top-level domain ({host.split('.')[-1]}) frequently abused "
                           f"in phishing/spam campaigns.",
            })

    # anchor text vs href mismatch (only meaningful if there's HTML)
    if body_html:
        for href, anchor_text in HREF_RE.findall(body_html):
            anchor_text = anchor_text.strip()
            if anchor_text.startswith("http"):
                anchor_host = urlparse(anchor_text).hostname or ""
                href_host = urlparse(href).hostname or ""
                if anchor_host and href_host and anchor_host != href_host:
                    findings.append({
                        "severity": "high",
                        "category": "url",
                        "message": f"Displayed link text ({anchor_host}) does not match where the "
                                   f"link actually goes ({href_host}) — a common cloaking trick.",
                    })

    return findings


def analyze_content(msg) -> list:
    """Check for urgency language, credential-harvesting phrasing, and generic greetings."""
    findings = []
    body_text = get_body_text(msg).lower()
    subject = (msg.get("Subject") or "").lower()
    combined = f"{subject}\n{body_text}"

    urgency_hits = [phrase for phrase in URGENCY_PHRASES if phrase in combined]
    if len(urgency_hits) >= 2:
        findings.append({
            "severity": "medium",
            "category": "content",
            "message": f"Uses urgency/pressure language ({len(urgency_hits)} phrase(s) matched, "
                       f"e.g. '{urgency_hits[0]}') designed to rush the reader into acting without thinking.",
        })

    cred_hits = [phrase for phrase in CREDENTIAL_REQUEST_PHRASES if phrase in combined]
    if cred_hits:
        findings.append({
            "severity": "high",
            "category": "content",
            "message": f"Directly asks the reader to confirm/enter credentials or payment details "
                       f"(matched: '{cred_hits[0]}').",
        })

    if any(greeting in combined for greeting in GENERIC_GREETINGS):
        findings.append({
            "severity": "low",
            "category": "content",
            "message": "Uses a generic greeting instead of the recipient's name — mass phishing "
                       "campaigns rarely personalize this.",
        })

    return findings


SEVERITY_WEIGHTS = {"high": 25, "medium": 12, "low": 5}


def score_email(msg) -> dict:
    findings = (
        analyze_headers(msg)
        + analyze_sender_domain(msg)
        + analyze_urls(msg)
        + analyze_content(msg)
    )

    score = sum(SEVERITY_WEIGHTS[f["severity"]] for f in findings)
    score = min(100, score)

    if score >= 60:
        verdict = "Likely Phishing"
    elif score >= 30:
        verdict = "Suspicious"
    elif score > 0:
        verdict = "Low Risk"
    else:
        verdict = "No Indicators Found"

    return {
        "subject": msg.get("Subject", "(no subject)"),
        "from": msg.get("From", "(unknown sender)"),
        "score": score,
        "verdict": verdict,
        "findings": findings,
    }


def print_report(filename: str, result: dict) -> None:
    print("=" * 70)
    print(f" File:    {filename}")
    print(f" Subject: {result['subject']}")
    print(f" From:    {result['from']}")
    print(f" Score:   {result['score']} / 100")
    print(f" Verdict: {result['verdict']}")
    print("-" * 70)
    if not result["findings"]:
        print(" No phishing indicators detected.")
    else:
        for finding in result["findings"]:
            tag = finding["severity"].upper()
            print(f" [{tag}] ({finding['category']}) {finding['message']}")
    print("=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Analyze .eml files for phishing indicators.")
    parser.add_argument("path", help="Path to a .eml file, or a directory of .eml files")
    args = parser.parse_args()

    if os.path.isdir(args.path):
        eml_files = sorted(glob.glob(os.path.join(args.path, "*.eml")))
        if not eml_files:
            print(f"No .eml files found in {args.path}")
            return
    else:
        eml_files = [args.path]

    for path in eml_files:
        msg = load_email(path)
        result = score_email(msg)
        print_report(os.path.basename(path), result)


if __name__ == "__main__":
    main()
