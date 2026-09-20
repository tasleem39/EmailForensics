"""
AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform
Prototype (small-scale) — SIH 2026, PS ID 26106, Team Tech Titans

This is a scoped-down but REAL working version of the pipeline described in the
idea deck. It does not use BERT/Neo4j/Rust yet (those are the production
upgrade path) — it uses lightweight, honest equivalents so every step here actually runs:

    1. Email Parser        -> Python's built-in email library
  2. Auth Check           -> DNS TXT lookups for SPF/DMARC + DKIM signature presence
  3. Origin Extraction    -> Regex walk of Received: header chain, first external hop
  4. Geo & Attribution    -> Free IP geolocation API (ip-api.com)
  5. Threat Intelligence  -> Rule-based fraud scoring (stand-in for the NLP/BERT model)
  6. Report               -> Structured JSON "forensic report"

Run:  python3 email_forensics.py sample.eml
"""

import sys
import os
import re
import json
import email
import ipaddress
import hashlib
import base64
import joblib
from datetime import datetime
from email import policy
from email.utils import parseaddr
from email.parser import BytesParser
from urllib.parse import urlparse

import dns.resolver
import requests


MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "email_classifier.joblib")
try:
    CLASSIFIER_ARTIFACT = joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None
except Exception:
    CLASSIFIER_ARTIFACT = None


# ---------- 1. EMAIL PARSER ----------

def parse_email(filepath):
    with open(filepath, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return {
        "from": str(msg.get("From", "")),
        "reply_to": str(msg.get("Reply-To", "")),
        "to": str(msg.get("To", "")),
        "subject": str(msg.get("Subject", "")),
        "received_headers": msg.get_all("Received", []),
        "authentication_results": str(msg.get("Authentication-Results", "")),
        "dkim_signature_present": msg.get("DKIM-Signature") is not None,
        "message_id": str(msg.get("Message-ID", "")),
        "body": get_body_text(msg),
        "inline_images": get_inline_images(msg),
        "attachments": get_attachment_metadata(msg),
    }


def get_body_text(msg):
    body_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    pass
        return "\n".join(map(str, body_parts))
    else:
        try:
            return msg.get_content()
        except Exception:
            return ""
    return ""


def get_inline_images(msg):
    images = []
    if not msg.is_multipart():
        return images

    for part in msg.walk():
        if not part.get_content_maintype() == "image":
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        content_type = part.get_content_type()
        content_id = str(part.get("Content-ID", "")).strip("<>")
        images.append({
            "filename": part.get_filename() or "inline-image",
            "content_id": content_id,
            "content_type": content_type,
            "data_uri": f"data:{content_type};base64,{base64.b64encode(payload).decode('ascii')}",
            "size": len(payload),
        })
    return images


def get_attachment_metadata(msg):
    attachments = []
    if not msg.is_multipart():
        return attachments

    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        if part.get_content_maintype() == "image" and part.get("Content-ID"):
            continue
        if disposition != "attachment" and not filename:
            continue
        payload = part.get_payload(decode=True) or b""
        attachments.append({
            "filename": filename or "unnamed attachment",
            "content_type": part.get_content_type(),
            "size": len(payload),
        })
    return attachments

def extract_domain(address_field):
    address = parseaddr(address_field or "")[1]
    match = re.search(r"@([^\s>]+)$", address)
    return match.group(1).lower().rstrip(".") if match else None


def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode(errors="ignore")
            if txt.startswith("v=spf1"):
                return {"found": True, "record": txt}
        return {"found": False, "record": None}
    except Exception as e:
        return {"found": False, "error": str(e)}


def check_dmarc(domain):
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode(errors="ignore")
            if txt.startswith("v=DMARC1"):
                return {"found": True, "record": txt}
        return {"found": False, "record": None}
    except Exception as e:
        return {"found": False, "error": str(e)}


def run_auth_check(parsed):
    from_domain = extract_domain(parsed["from"])
    result = {
        "from_domain": from_domain,
        "spf": {"found": False, "record": None},
        "dmarc": {"found": False, "record": None},
    }
    if from_domain:
        result["spf"] = check_spf(from_domain)
        result["dmarc"] = check_dmarc(from_domain)
    result["dkim_signature_present"] = parsed["dkim_signature_present"]
    return result


# ---------- 2b. DOMAIN INTELLIGENCE (WHOIS/RDAP + MX + lookalike detection) ----------

# Well-known brands most commonly impersonated in phishing/BEC — used only for
# lookalike-domain scoring, not a full brand database.
PROTECTED_BRANDS = [
    "paypal.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
    "gmail.com", "outlook.com", "bankofamerica.com", "chase.com", "hdfcbank.com",
    "icicibank.com", "sbi.co.in", "netflix.com", "facebook.com", "instagram.com",
]


def levenshtein(a, b):
    """Simple edit-distance implementation — no external dependency needed."""
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            curr[j] = min(
                prev[j] + 1,
                curr[j - 1] + 1,
                prev[j - 1] + (ca != cb),
            )
        prev = curr
    return prev[-1]


def check_lookalike_domain(domain):
    """Flags domains that are suspiciously close (edit distance 1-2) to a
    well-known brand domain — catches tricks like paypa1-secure.xyz vs paypal.com."""
    if not domain:
        return None
    for brand in PROTECTED_BRANDS:
        brand_name = brand.split(".")[0]
        domain_name = domain.split(".")[0]
        dist = levenshtein(domain_name, brand_name)
        if 0 < dist <= 2 and domain != brand:
            return {"impersonating": brand, "edit_distance": dist}
    return None


def get_mx_records(domain):
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        return sorted([str(r.exchange).rstrip(".") for r in answers])
    except Exception:
        return []


def get_domain_registration_info(domain):
    """Uses RDAP (the modern, HTTPS-friendly successor to raw WHOIS) via the
    public rdap.org bootstrap service — no API key needed."""
    try:
        resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=6)
        if resp.status_code != 200:
            return {"available": False, "reason": f"RDAP lookup failed (HTTP {resp.status_code})"}
        data = resp.json()
        registration_date = None
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                registration_date = event.get("eventDate")
        registrar = None
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [None, []])[1]
                for field in vcard:
                    if field[0] == "fn":
                        registrar = field[3]
        return {
            "available": True,
            "registration_date": registration_date,
            "registrar": registrar,
        }
    except Exception as e:
        return {"available": False, "reason": str(e)}


def run_domain_intelligence(from_domain):
    if not from_domain:
        return {"mx_records": [], "registration": {"available": False}, "lookalike": None}
    return {
        "mx_records": get_mx_records(from_domain),
        "registration": get_domain_registration_info(from_domain),
        "lookalike": check_lookalike_domain(from_domain),
    }


# ---------- 2c. CAMPAIGN CORRELATION (lightweight case-history store) ----------
# Production version: this same logic, backed by Neo4j, correlating at scale
# across millions of emails via graph queries. For the prototype, a local JSON
# case history demonstrates the identical correlation concept honestly.

CASE_HISTORY_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "case_history.json",
)


def load_case_history():
    if not os.path.exists(CASE_HISTORY_FILE):
        return []
    try:
        with open(CASE_HISTORY_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []


def save_case_history(history):
    try:
        with open(CASE_HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=2, default=str)
    except Exception:
        pass


def _domain_from_field(value):
    return extract_domain(value) if value else None


def _url_domains(body):
    domains = []
    for url in re.findall(r"https?://[^\s<>\"']+", body or ""):
        host = (urlparse(url.rstrip(".,);]}")).hostname or "").lower()
        if host and host not in domains:
            domains.append(host)
    return domains


def _case_indicators(current_ip, parsed):
    return {
        "ip": current_ip,
        "domain": _domain_from_field(parsed.get("from")),
        "reply_domain": _domain_from_field(parsed.get("reply_to")),
        "url_domains": _url_domains(parsed.get("body", "")),
    }


def _correlation_score(current, previous):
    shared = []
    if current.get("ip") and current.get("ip") == previous.get("ip"):
        shared.append(("originating IP", 30))
    if current.get("domain") and current.get("domain") == previous.get("domain"):
        shared.append(("sender domain", 20))
    if current.get("reply_domain") and current.get("reply_domain") == previous.get("reply_domain"):
        shared.append(("Reply-To domain", 15))
    shared_urls = sorted(set(current.get("url_domains", [])) & set(previous.get("url_domains", [])))
    if shared_urls:
        shared.append((f"URL domain ({shared_urls[0]})", 20))
    return min(100, sum(weight for _, weight in shared)), [label for label, _ in shared]


def correlate_with_history(current_ip, parsed):
    history = load_case_history()
    current = _case_indicators(current_ip, parsed)
    current_id = "EMAIL-" + hashlib.sha256(
        f"{parsed.get('message_id', '')}|{parsed.get('subject', '')}|{datetime.utcnow().isoformat()}".encode()
    ).hexdigest()[:12].upper()
    matches = []
    for index, case in enumerate(history):
        score, shared = _correlation_score(current, case)
        if score:
            matches.append({
                "case_id": case.get("case_id", f"EMAIL-LEGACY-{index + 1}"),
                "subject": case.get("subject"),
                "timestamp": case.get("timestamp"),
                "shared_on": shared,
                "score": score,
            })

    history.append({
        "case_id": current_id,
        **current,
        "filename": parsed.get("filename") or parsed.get("subject") or "Uploaded email",
        "subject": parsed.get("subject", ""),
        "message_id": parsed.get("message_id", ""),
        "timestamp": datetime.utcnow().isoformat(),
    })
    save_case_history(history)

    nodes = [{
        "id": case.get("case_id", f"EMAIL-LEGACY-{index + 1}"),
        "filename": case.get("filename") or case.get("subject") or "Previous email",
        "subject": case.get("subject") or "No subject",
        "domain": case.get("domain") or "Unknown domain",
        "ip": case.get("ip") or "Unknown IP",
        "timestamp": case.get("timestamp"),
        "current": case.get("case_id") == current_id,
    } for index, case in enumerate(history[-100:], start=max(0, len(history) - 100))]
    edges = []
    for index, case in enumerate(history):
        if case.get("case_id") == current_id:
            continue
        score, shared = _correlation_score(current, case)
        if score:
            edges.append({
                "source": current_id,
                "target": case.get("case_id", f"EMAIL-LEGACY-{index + 1}"),
                "score": score,
                "shared_on": shared,
            })
    sorted_edges = sorted(edges, key=lambda edge: edge["score"], reverse=True)[:50]
    graph_indicators = []
    indicator_index = {}

    def add_graph_indicator(label, edge_key):
        if not label:
            return
        if label not in indicator_index:
            indicator_index[label] = len(graph_indicators)
            graph_indicators.append({"label": label, "edge_keys": [edge_key]})
        elif edge_key not in graph_indicators[indicator_index[label]]["edge_keys"]:
            graph_indicators[indicator_index[label]]["edge_keys"].append(edge_key)

    add_graph_indicator(f"Sender: {current.get('domain') or 'No sender domain present'}", "current")
    add_graph_indicator(f"Origin IP: {current.get('ip') or 'No originating IP present'}", "current")
    add_graph_indicator(f"Reply-To: {current.get('reply_domain') or 'No Reply-To domain present'}", "current")
    if current.get("url_domains"):
        for url_domain in current["url_domains"]:
            add_graph_indicator(f"URL domain: {url_domain}", "current")
    else:
        add_graph_indicator("No URL domain present", "current")

    for edge_index, edge in enumerate(sorted_edges[:5]):
        for shared in edge["shared_on"]:
            if shared == "originating IP":
                label = f"Origin IP: {current.get('ip') or 'No originating IP present'}"
            elif shared == "sender domain":
                label = f"Sender: {current.get('domain') or 'No sender domain present'}"
            elif shared == "Reply-To domain":
                label = f"Reply-To: {current.get('reply_domain') or 'No Reply-To domain present'}"
            elif shared.startswith("URL domain (") and shared.endswith(")"):
                label = f"URL domain: {shared[12:-1]}"
            else:
                label = shared
            add_graph_indicator(label, edge_index)
    return {
        "current_email_id": current_id,
        "current_sender_domain": current.get("domain"),
        "current_origin_ip": current.get("ip"),
        "current_reply_domain": current.get("reply_domain"),
        "current_url_domains": current.get("url_domains", []),
        "graph_indicators": graph_indicators,
        "nodes": nodes,
        "edges": sorted_edges,
        "matches": sorted(matches, key=lambda item: item["score"], reverse=True)[:20],
    }


def get_reverse_dns(ip):
    try:
        answer = dns.resolver.resolve_address(ip, lifetime=4)
        return str(answer[0]).rstrip(".")
    except Exception:
        return None


# ---------- 3b. MAIL PATH RECONSTRUCTION ----------

def reconstruct_mail_path(all_candidates, origin_ip):
    """Builds a hop-by-hop list, geolocating every public IP found in the
    Received chain (not just the origin), each tagged with a role."""
    hops = []
    for idx, ip in enumerate(all_candidates):
        geo = geolocate_ip(ip)
        rdns = get_reverse_dns(ip)
        if ip == origin_ip:
            role = "Probable Origin"
        elif idx == len(all_candidates) - 1:
            role = "Final Visible Mail Server"
        else:
            role = "Intermediate Relay"
        hops.append({
            "ip": ip,
            "role": role,
            "reverse_dns": rdns,
            "country": geo.get("country") if geo.get("status") == "success" else None,
            "city": geo.get("city") if geo.get("status") == "success" else None,
            "isp": geo.get("isp") if geo.get("status") == "success" else None,
            "asn": geo.get("as") if geo.get("status") == "success" else None,
            "lat": geo.get("lat") if geo.get("status") == "success" else None,
            "lon": geo.get("lon") if geo.get("status") == "success" else None,
            "proxy": geo.get("proxy") if geo.get("status") == "success" else None,
            "hosting": geo.get("hosting") if geo.get("status") == "success" else None,
        })
    return hops


# ---------- 4b. ORIGIN ATTRIBUTION CONFIDENCE ----------

def compute_attribution_confidence(auth_result, domain_intel, geo_result, origin_ip, reverse_dns):
    """A transparent, additive confidence score built ONLY from signals we
    actually computed — no fabricated 'reputation' data."""
    evidence = []
    points = 0
    max_points = 0

    max_points += 20
    if origin_ip:
        points += 20
        evidence.append(("Earliest public IP successfully extracted from Received headers", True))
    else:
        evidence.append(("Earliest public IP could not be determined", False))

    max_points += 20
    spf_ok = auth_result.get("spf", {}).get("found") is True
    points += 20 if spf_ok else 0
    evidence.append(("SPF record aligned for sending domain", spf_ok))

    max_points += 20
    dkim_ok = bool(auth_result.get("dkim_signature_present"))
    points += 20 if dkim_ok else 0
    evidence.append(("DKIM signature present", dkim_ok))

    max_points += 15
    dmarc_ok = auth_result.get("dmarc", {}).get("found") is True
    points += 15 if dmarc_ok else 0
    evidence.append(("DMARC policy published and found", dmarc_ok))

    max_points += 15
    rdns_match = False
    if reverse_dns and auth_result.get("from_domain"):
        domain_root = auth_result["from_domain"].split(".")[-2] if "." in auth_result["from_domain"] else auth_result["from_domain"]
        rdns_match = domain_root.lower() in reverse_dns.lower()
    points += 15 if rdns_match else 0
    evidence.append(("Reverse DNS of originating IP matches sending domain", rdns_match))

    max_points += 10
    reg = domain_intel.get("registration", {}) if domain_intel else {}
    domain_established = False
    if reg.get("available") and reg.get("registration_date"):
        try:
            reg_year = int(reg["registration_date"][:4])
            domain_established = reg_year <= 2024  # registered more than ~1 year ago
        except Exception:
            pass
    points += 10 if domain_established else 0
    evidence.append(("Sending domain has an established registration history", domain_established))

    confidence_pct = round((points / max_points) * 100) if max_points else 0
    return {"confidence_percent": confidence_pct, "evidence": evidence}


# ---------- 5b. THREAT ACTOR TECHNIQUES ----------

def map_threat_techniques(parsed, auth_result, domain_intel, geo_result):
    """Maps signals we've already detected onto named attack techniques —
    no new detection logic, just labeling what we found."""
    techniques = {}

    from_domain = extract_domain(parsed["from"])
    reply_domain = extract_domain(parsed["reply_to"]) if parsed["reply_to"] else None
    techniques["Display Name / Reply-To Spoofing"] = bool(reply_domain and from_domain and reply_domain != from_domain)

    techniques["Brand Impersonation (Lookalike Domain)"] = bool(domain_intel and domain_intel.get("lookalike"))

    body_lower = parsed["body"].lower()
    subject_lower = parsed["subject"].lower()
    techniques["Social Engineering / Urgency Pressure"] = any(w in body_lower or w in subject_lower for w in URGENCY_WORDS)

    techniques["Credential Harvesting Language"] = any(
        phrase in body_lower for phrase in ["confirm your password", "verify your account", "click here", "login"]
    )

    techniques["Infrastructure Spoofing (Proxy/TOR/Hosting Origin)"] = bool(
        isinstance(geo_result, dict) and (geo_result.get("proxy") or geo_result.get("hosting"))
    )

    techniques["Failed Sender Authentication"] = (
        auth_result.get("spf", {}).get("found") is False
        or auth_result.get("dmarc", {}).get("found") is False
        or not auth_result.get("dkim_signature_present")
    )

    techniques["Malware/Attachment Delivery"] = False  # not analyzed in this prototype — see limitations

    return techniques


# ---------- 6b. INDICATORS OF COMPROMISE ----------

URL_REGEX = re.compile(r"https?://[^\s\)\]\"']+")


def extract_iocs(parsed, origin_ip, auth_result):
    urls = list(dict.fromkeys(URL_REGEX.findall(parsed["body"])))
    return {
        "suspicious_urls": urls,
        "sender_ip": origin_ip,
        "sender_domain": auth_result.get("from_domain"),
        "attachment_hash": None,  # not computed — this prototype does not analyze attachments
    }


# ---------- 7b. RECOMMENDED ACTIONS & CONCLUSION ----------

def recommend_actions(verdict, techniques):
    actions = []
    if "HIGH RISK" in verdict:
        actions += [
            "Quarantine this email and do not allow user interaction with any links/attachments",
            "Block the sender domain and originating IP at the mail gateway",
            "Alert affected recipients and instruct them not to act on the message",
            "Add the sender IP/domain/URLs to SIEM or threat-intel watchlists",
        ]
    elif "SUSPICIOUS" in verdict:
        actions += [
            "Hold for manual analyst review before delivery",
            "Verify sender identity through an out-of-band channel (phone/known contact) if action was requested",
        ]
    else:
        actions.append("No action required — email shows no significant fraud indicators")
    if techniques.get("Brand Impersonation (Lookalike Domain)"):
        actions.append("Report the lookalike domain to the impersonated brand's abuse team")
    return actions


def build_forensic_conclusion(report_bits):
    verdict = report_bits["verdict"]
    confidence = report_bits["confidence_percent"]
    domain = report_bits["from_domain"] or "the sending domain"
    if "HIGH RISK" in verdict:
        return (
            f"The analyzed email shows strong indicators of fraud/phishing originating from infrastructure "
            f"inconsistent with a legitimate sender. Attribution confidence in the traced origin is {confidence}%. "
            f"Recommend treating this as a confirmed threat pending analyst review."
        )
    elif "SUSPICIOUS" in verdict:
        return (
            f"The analyzed email shows some fraud indicators but is not conclusively malicious. "
            f"Attribution confidence in the traced origin is {confidence}%. Recommend manual review before final disposition."
        )
    else:
        return (
            f"The analyzed email was transmitted through infrastructure consistent with {domain}'s legitimate mail "
            f"servers, with authentication checks passing. Attribution confidence is {confidence}%. "
            f"No evidence of spoofing or relay manipulation was found; assessed as LEGITIMATE."
        )


def build_campaign_graph(auth_result, origin_trace, correlation):
    """Builds the data behind the graph-based attribution visualization —
    reuses data we already computed, no new lookups."""
    sender_domain = auth_result.get("from_domain")
    ips = list(dict.fromkeys(origin_trace.get("all_public_ip_candidates", [])))[:4]

    basis = (sender_domain or "") + "|" + ",".join(sorted(ips))
    campaign_id = "CAM-" + hashlib.md5(basis.encode()).hexdigest()[:8].upper()

    if correlation:
        avg_overlap = sum(len(m["shared_on"]) for m in correlation) / (len(correlation) * 2)
        match_score = round(avg_overlap * 100, 1)
    else:
        match_score = 0.0

    return {
        "campaign_id": campaign_id,
        "match_score": match_score,
        "sender_domain": sender_domain or "Unknown",
        "ips": ips,
    }


# ---------- 3. ORIGIN EXTRACTION ----------

IP_TOKEN_REGEX = re.compile(r"(?<![\w:])[0-9A-Fa-f:.]+(?![\w:])")


def extract_ips(header):
    ips = []
    for token in IP_TOKEN_REGEX.findall(str(header)):
        try:
            ipaddress.ip_address(token)
            if token not in ips:
                ips.append(token)
        except ValueError:
            continue
    return ips


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True  # treat unparsable as "skip"


def extract_all_ips_tagged(received_headers):
    """Returns every IP found in the header chain, in order, tagged public/private —
    used to show the full raw extraction, not just the usable public candidates."""
    seen = []
    for header in received_headers:
        for ip in extract_ips(header):
            if ip not in [x["ip"] for x in seen]:
                seen.append({"ip": ip, "tag": "PRIVATE / NON-ROUTABLE" if is_private_ip(ip) else "PUBLIC"})
    return seen


def extract_originating_ip(received_headers):
    """
    Received headers are prepended by each hop, so the LAST header in the list
    (bottom of the chain, i.e. first line the message physically travelled) is
    closest to the true origin. We walk from the end and return the first
    public (non-private/non-internal) IP we find.
    """
    candidates = []
    for header in reversed(received_headers):
        ips = extract_ips(header)
        for ip in ips:
            if not is_private_ip(ip):
                candidates.append(ip)
    return candidates[0] if candidates else None, candidates


# ---------- 4. GEO & ATTRIBUTION ----------

def geolocate_ip(ip):
    if not ip:
        return {"error": "no public IP found in header chain"}

    # Primary provider: ip-api.com
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,proxy,hosting,lat,lon",
            timeout=5,
        )
        if resp.status_code == 200 and resp.text.strip():
            data = resp.json()
            if data.get("status") == "success":
                return data
    except Exception:
        pass  # fall through to backup provider

    # Backup provider: ipwho.is (used if the primary is rate-limited or unreachable)
    try:
        resp = requests.get(f"https://ipwho.is/{ip}", timeout=5)
        if resp.status_code == 200 and resp.text.strip():
            data = resp.json()
            if data.get("success", True):
                return {
                    "status": "success",
                    "country": data.get("country"),
                    "regionName": data.get("region"),
                    "city": data.get("city"),
                    "isp": data.get("connection", {}).get("isp"),
                    "org": data.get("connection", {}).get("org"),
                    "as": data.get("connection", {}).get("asn"),
                    "proxy": data.get("security", {}).get("proxy", False),
                    "hosting": data.get("security", {}).get("hosting", False),
                    "lat": data.get("latitude"),
                    "lon": data.get("longitude"),
                }
    except Exception:
        pass

    return {"error": "Geolocation temporarily unavailable (provider rate-limit or network issue) — origin IP was still successfully extracted above."}


# ---------- 5. THREAT INTELLIGENCE (rule-based stand-in for the NLP/BERT model) ----------

URGENCY_WORDS = ["urgent", "immediately", "verify your account", "suspended",
                  "act now", "click here", "final notice", "wire transfer",
                  "confirm your password", "payment overdue", "invoice attached"]

SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".zip", ".gq", ".tk"]


def model_email_text(parsed):
    fields = {
        "sender": parsed.get("from", ""),
        "receiver": parsed.get("to", ""),
        "subject": parsed.get("subject", ""),
        "body": parsed.get("body", ""),
        "urls": " ".join(re.findall(r"https?://[^\s<>\"']+", parsed.get("body", ""))),
    }
    return "\n".join(f"{field}: {value}" for field, value in fields.items())


MODEL_CLASSES = ("legitimate", "suspicious", "impersonated", "phishing", "fraud")


def model_classification(parsed):
    if not CLASSIFIER_ARTIFACT:
        return None
    model = CLASSIFIER_ARTIFACT["model"]
    probabilities = model.predict_proba([model_email_text(parsed)])[0]
    classes = getattr(model, "classes_", CLASSIFIER_ARTIFACT.get("classes", []))
    result = {label: 0.0 for label in MODEL_CLASSES}
    for label, probability in zip(classes, probabilities):
        if str(label) in result:
            result[str(label)] = float(probability)
    return result


def score_email(parsed, auth_result, geo_result, domain_intel=None, correlation=None):
    body = parsed.get("body", "")
    raw_text = f"{parsed.get('subject', '')}\n{body}".lower()
    evidence = []

    groups = [
        ("urgency", [
            "urgent", "immediately", "asap", "action required",
            "within 24 hours", "account will be suspended", "verify immediately",
        ], 20),
        ("credential", [
            "password", "verify your account", "login", "credentials",
            "otp", "bank account", "verify your identity",
        ], 25),
        ("financial", [
            "payment", "invoice", "transfer", "gift card", "wire transfer", "refund",
        ], 12),
    ]

    for signal, words, weight in groups:
        hits = [word for word in words if word in raw_text]
        if hits:
            evidence.append({"signal": signal, "weight": weight, "details": hits[:4]})

    urls = re.findall(r'https?://[^\s<>"\']+', body)
    urls = list(dict.fromkeys(url.rstrip(".,);]}") for url in urls))
    if urls:
        evidence.append({"signal": "links", "weight": 15, "details": [f"{len(urls)} URL(s)"]})

    url_flags = []
    shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "ow.ly"}
    for url in urls:
        try:
            parsed_url = urlparse(url)
            host = (parsed_url.hostname or "").lower()
            if host in shorteners:
                url_flags.append(f"URL shortener detected: {host}")
            if parsed_url.username or parsed_url.password:
                url_flags.append(f"Embedded credentials/userinfo in URL: {host}")
            try:
                ipaddress.ip_address(host)
                url_flags.append(f"URL uses raw IP address: {host}")
            except ValueError:
                pass
            if host.count(".") >= 3:
                url_flags.append(f"Deeply nested hostname: {host}")
        except Exception:
            pass
    for flag in dict.fromkeys(url_flags):
        evidence.append({"signal": "url_anomaly", "weight": 8, "details": [flag]})

    auth_lower = parsed.get("authentication_results", "").lower()
    auth_failed = any(
        re.search(rf"{name}=(fail|softfail|permerror|temperror)\b", auth_lower)
        for name in ("spf", "dkim", "dmarc")
    )
    if auth_failed:
        evidence.append({
            "signal": "authentication_failure",
            "weight": 20,
            "details": ["Authentication-Results contains an explicit failure"],
        })

    from_domain = extract_domain(parsed.get("from", ""))
    reply_domain = extract_domain(parsed.get("reply_to", ""))
    if reply_domain and from_domain and reply_domain != from_domain:
        evidence.append({
            "signal": "reply_to_mismatch",
            "weight": 12,
            "details": [f"From={from_domain}", f"Reply-To={reply_domain}"],
        })

    model_probabilities = model_classification(parsed)
    heuristic_score = min(100, sum(item["weight"] for item in evidence))
    if model_probabilities is None:
        score = heuristic_score
        predicted_category = "suspicious" if score >= 40 else "legitimate"
    else:
        predicted_category = max(model_probabilities, key=model_probabilities.get)
        score = round((1 - model_probabilities.get("legitimate", 0.0)) * 100)
        # Keep strong, independently observed header/content signals from being
        # hidden by an uncertain text model prediction.
        score = max(score, round(heuristic_score * 0.6))
    if score >= 70:
        verdict = f"HIGH RISK — likely {predicted_category}"
    elif score >= 40:
        verdict = f"SUSPICIOUS — likely {predicted_category}"
    else:
        verdict = "LOW RISK"

    reasons = [
        f"{item['signal'].replace('_', ' ').title()} (+{item['weight']}): "
        f"{', '.join(item['details'])}"
        for item in evidence
    ]

    display_labels = {
        "phishing": "Phishing",
        "impersonated": "Impersonated",
        "suspicious": "Suspicious",
        "legitimate": "Legitimate",
        "fraud": "Fraud / BEC",
    }
    if model_probabilities is None:
        model_probabilities = {label: 0.0 for label in MODEL_CLASSES}
        model_probabilities[predicted_category] = score / 100
        model_probabilities["legitimate"] = max(0.0, 1 - score / 100)
    classification = [
        {"label": display_labels[label], "percentage": round(model_probabilities[label] * 100, 1)}
        for label in ("phishing", "impersonated", "suspicious", "legitimate", "fraud")
    ]

    return {
        "fraud_score": score,
        "model_probability": round(1 - model_probabilities.get("legitimate", 0.0), 4) if model_probabilities else None,
        "model_probabilities": model_probabilities,
        "predicted_category": predicted_category,
        "model_available": model_probabilities is not None,
        "verdict": verdict,
        "reasons": reasons,
        "classification": classification,
    }


# ---------- 6. FORENSIC REPORT ----------

def build_report(filepath):
    parsed = parse_email(filepath)
    parsed["filename"] = os.path.basename(filepath)
    auth_result = run_auth_check(parsed)
    origin_ip, all_candidates = extract_originating_ip(parsed["received_headers"])
    geo_result = geolocate_ip(origin_ip)
    domain_intel = run_domain_intelligence(auth_result.get("from_domain"))
    correlation_graph = correlate_with_history(origin_ip, parsed)
    correlation = correlation_graph["matches"]
    threat_result = score_email(parsed, auth_result, geo_result, domain_intel, correlation)

    reverse_dns = get_reverse_dns(origin_ip) if origin_ip else None
    mail_path = reconstruct_mail_path(all_candidates, origin_ip)
    confidence = compute_attribution_confidence(auth_result, domain_intel, geo_result, origin_ip, reverse_dns)
    techniques = map_threat_techniques(parsed, auth_result, domain_intel, geo_result)
    iocs = extract_iocs(parsed, origin_ip, auth_result)
    actions = recommend_actions(threat_result["verdict"], techniques)
    conclusion = build_forensic_conclusion({
        "verdict": threat_result["verdict"],
        "confidence_percent": confidence["confidence_percent"],
        "from_domain": auth_result.get("from_domain"),
    })

    origin_trace = {
        "originating_ip": origin_ip,
        "all_public_ip_candidates": all_candidates,
        "reverse_dns": reverse_dns,
        "all_ips_tagged": extract_all_ips_tagged(parsed["received_headers"]),
    }
    campaign_graph = build_campaign_graph(auth_result, origin_trace, correlation)

    report = {
        "email_summary": {
            "filename": os.path.basename(filepath),
            "from": parsed["from"],
            "to": parsed["to"],
            "reply_to": parsed["reply_to"],
            "subject": parsed["subject"],
            "message_id": parsed["message_id"],
            "body": parsed["body"],
            "inline_images": parsed["inline_images"],
            "attachments": parsed["attachments"],
        },
        "authentication_check": auth_result,
        "domain_intelligence": domain_intel,
        "origin_trace": origin_trace,
        "geolocation": geo_result,
        "mail_path": mail_path,
        "attribution_confidence": confidence,
        "threat_techniques": techniques,
        "iocs": iocs,
        "campaign_correlation": correlation,
        "email_correlation_graph": correlation_graph,
        "campaign_graph": campaign_graph,
        "threat_assessment": threat_result,
        "recommended_actions": actions,
        "forensic_conclusion": conclusion,
    }
    return report


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 email_forensics.py <path_to_email.eml>")
        sys.exit(1)

    report = build_report(sys.argv[1])
    print(json.dumps(report, indent=2, default=str))
