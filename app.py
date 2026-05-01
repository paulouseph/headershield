from flask import Flask, Response, redirect, render_template, request, url_for
from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import ssl
import tempfile
from time import perf_counter
from bs4 import BeautifulSoup
try:
    import pdfkit
except ImportError:
    pdfkit = None
import requests
import sqlite3
from urllib.parse import urlparse

app = Flask(__name__)

DATABASE_PATH = str(Path(__file__).resolve().parent / "scan_history.db")
WKHTMLTOPDF_PATH = r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe"
REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
}
DUPLICATE_HEADER_PENALTY = 1
COOKIE_ISSUE_PENALTY = 4
INFO_DISCLOSURE_PENALTY = 1

HEADER_RULES = [
    {
        "name": "Content-Security-Policy",
        "weight": 20,
        "missing_penalty": 20,
        "weak_penalty": 10,
        "explanation": "Restricts which sources the browser can load scripts, styles, frames, and other content from.",
        "impact": "Helps reduce XSS and malicious content injection.",
    },
    {
        "name": "X-Frame-Options",
        "weight": 15,
        "missing_penalty": 8,
        "weak_penalty": 4,
        "explanation": "Controls whether the page can be embedded inside a frame or iframe.",
        "impact": "Helps prevent clickjacking attacks.",
    },
    {
        "name": "Strict-Transport-Security",
        "weight": 20,
        "missing_penalty": 12,
        "weak_penalty": 6,
        "explanation": "Tells browsers to use HTTPS for future requests to the site.",
        "impact": "Helps prevent SSL stripping and insecure HTTP access.",
    },
    {
        "name": "X-Content-Type-Options",
        "weight": 10,
        "missing_penalty": 4,
        "weak_penalty": 2,
        "explanation": "Stops browsers from MIME-sniffing a response away from the declared content type.",
        "impact": "Reduces the risk of content-type confusion attacks.",
    },
    {
        "name": "Referrer-Policy",
        "weight": 10,
        "missing_penalty": 3,
        "weak_penalty": 2,
        "explanation": "Controls how much referrer information is sent when users follow links or load external resources.",
        "impact": "Helps limit leakage of internal URLs and sensitive browsing context.",
    },
    {
        "name": "Permissions-Policy",
        "weight": 10,
        "missing_penalty": 3,
        "weak_penalty": 2,
        "explanation": "Defines which browser features and APIs are allowed for the current page and embedded content.",
        "impact": "Reduces exposure to unnecessary powerful browser capabilities.",
    },
    {
        "name": "Cache-Control",
        "weight": 15,
        "missing_penalty": 3,
        "weak_penalty": 2,
        "explanation": "Tells browsers and intermediaries how content may be cached.",
        "impact": "Helps avoid sensitive data being stored in shared or long-lived caches.",
    },
]

VULNERABILITY_RULES = {
    "Content-Security-Policy": {
        "title": "Cross-Site Scripting (XSS) Risk",
        "category": "XSS",
        "severity_missing": "Medium",
        "severity_weak": "Medium",
        "description": "A missing or weak Content-Security-Policy can allow browsers to execute untrusted scripts.",
        "impact": "Attackers may inject malicious JavaScript, steal session data, or perform actions as the victim.",
    },
    "X-Frame-Options": {
        "title": "Clickjacking Risk",
        "category": "Clickjacking",
        "severity_missing": "Medium",
        "severity_weak": "Medium",
        "description": "Without strong frame protections, the page may be embedded inside a malicious site.",
        "impact": "Users can be tricked into clicking hidden or disguised interface elements.",
    },
    "Strict-Transport-Security": {
        "title": "Man-in-the-Middle (MITM) Risk",
        "category": "MITM",
        "severity_missing": "Medium",
        "severity_weak": "Medium",
        "description": "Missing or weak HSTS allows browsers to fall back to insecure HTTP connections.",
        "impact": "Attackers on the network may intercept, downgrade, or tamper with traffic.",
    },
    "X-Content-Type-Options": {
        "title": "Content Type Confusion Risk",
        "category": "Content Sniffing",
        "severity_missing": "Low",
        "severity_weak": "Low",
        "description": "Without X-Content-Type-Options, browsers may MIME-sniff responses and treat content as a different type.",
        "impact": "Unexpected content interpretation can increase exposure to content-type confusion and script execution edge cases.",
    },
}

RECOMMENDATION_RULES = {
    "Content-Security-Policy": "Fix: Add Content-Security-Policy header.",
    "X-Frame-Options": "Fix: Set X-Frame-Options to DENY or SAMEORIGIN.",
    "Strict-Transport-Security": "Fix: Enable HSTS with max-age=31536000.",
    "X-Content-Type-Options": "Fix: Set X-Content-Type-Options to nosniff.",
    "Referrer-Policy": "Fix: Set Referrer-Policy to strict-origin-when-cross-origin.",
    "Permissions-Policy": "Fix: Add a restrictive Permissions-Policy header.",
    "Cache-Control": "Fix: Tighten Cache-Control for sensitive responses.",
}

UPCOMING_HEADER_RULES = [
    {
        "name": "Cross-Origin-Embedder-Policy",
        "explanation": "Controls whether the document can load cross-origin resources that are not explicitly permitted for embedding.",
        "impact": "Without it, powerful browser isolation features may remain unavailable and cross-origin resource loading boundaries can be weaker.",
        "recommendation": "Add Cross-Origin-Embedder-Policy with a value such as require-corp after validating third-party resource compatibility.",
    },
    {
        "name": "Cross-Origin-Opener-Policy",
        "explanation": "Isolates the browsing context from cross-origin windows to reduce cross-window attacks and enable stronger process isolation.",
        "impact": "Without it, the application may be more exposed to cross-window interaction risks and lose access to stronger isolation guarantees.",
        "recommendation": "Set Cross-Origin-Opener-Policy to same-origin where application flows support full browsing context isolation.",
    },
    {
        "name": "Cross-Origin-Resource-Policy",
        "explanation": "Restricts which origins are allowed to load the resource, helping reduce unintended cross-origin data exposure.",
        "impact": "Without it, browsers may allow broader cross-origin resource loading than intended for sensitive assets.",
        "recommendation": "Apply Cross-Origin-Resource-Policy with the narrowest value that fits the asset, such as same-origin or same-site.",
    },
]

INFORMATIONAL_HEADER_RULES = [
    {
        "name": "Server",
        "issue": "Information Disclosure",
        "recommendation": "Remove or obfuscate server details",
        "explanation": "Exposes web server implementation details that can help attackers fingerprint the stack.",
        "impact": "Visible server banners can make targeted reconnaissance and version-based attack planning easier.",
    },
    {
        "name": "X-Powered-By",
        "issue": "Information Disclosure",
        "recommendation": "Remove or obfuscate server details",
        "explanation": "Reveals framework or platform information that may assist targeted exploitation attempts.",
        "impact": "Framework disclosure can help attackers identify stack-specific weaknesses or prioritize exploit paths.",
    },
]


def calculate_grade(score):
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "E"


def calculate_duplicate_penalty(analysis):
    has_duplicate_headers = any(
        item.get("duplicate") and item.get("status") != "Missing"
        for item in analysis or []
    )
    return DUPLICATE_HEADER_PENALTY if has_duplicate_headers else 0


def calculate_cookie_issue_penalty(cookie_issues):
    return COOKIE_ISSUE_PENALTY if cookie_issues else 0


def calculate_info_disclosure_penalty(informational_headers):
    return INFO_DISCLOSURE_PENALTY if informational_headers else 0


def normalize_fix_text(recommendation):
    if not recommendation:
        return recommendation

    cleaned = " ".join(str(recommendation).split()).strip()
    while cleaned.lower().startswith("fix:"):
        cleaned = cleaned[4:].strip()

    return f"Fix: {cleaned}" if cleaned else "Fix: Review the affected control."


def current_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_url(raw_url):
    cleaned = raw_url.strip()
    if not cleaned:
        raise ValueError("Please enter a URL to scan.")

    if not cleaned.startswith(("http://", "https://")):
        cleaned = "https://" + cleaned

    parsed = urlparse(cleaned)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Please provide a valid URL such as https://example.com.")

    return cleaned


def get_db_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    connection = get_db_connection()
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            score INTEGER NOT NULL,
            grade TEXT NOT NULL,
            status_code TEXT NOT NULL,
            vulnerability_count INTEGER NOT NULL DEFAULT 0,
            previous_score INTEGER,
            change_status TEXT,
            vulnerabilities TEXT NOT NULL,
            analysis TEXT NOT NULL DEFAULT '[]',
            recommendations TEXT NOT NULL DEFAULT '[]',
            error_message TEXT
        )
        """
    )

    existing_columns = {
        row[1]
        for row in connection.execute("PRAGMA table_info(scans)").fetchall()
    }
    if "analysis" not in existing_columns:
        connection.execute("ALTER TABLE scans ADD COLUMN analysis TEXT NOT NULL DEFAULT '[]'")
    if "recommendations" not in existing_columns:
        connection.execute("ALTER TABLE scans ADD COLUMN recommendations TEXT NOT NULL DEFAULT '[]'")
    if "error_message" not in existing_columns:
        connection.execute("ALTER TABLE scans ADD COLUMN error_message TEXT")
    if "vulnerability_count" not in existing_columns:
        connection.execute("ALTER TABLE scans ADD COLUMN vulnerability_count INTEGER NOT NULL DEFAULT 0")
    if "previous_score" not in existing_columns:
        connection.execute("ALTER TABLE scans ADD COLUMN previous_score INTEGER")
    if "change_status" not in existing_columns:
        connection.execute("ALTER TABLE scans ADD COLUMN change_status TEXT")

    connection.commit()
    connection.close()


def save_scan(url, timestamp, score, grade, status_code, vulnerabilities, analysis, recommendations, error_message):
    connection = get_db_connection()
    previous_row = connection.execute(
        """
        SELECT score
        FROM scans
        WHERE url = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (url,),
    ).fetchone()

    previous_score = previous_row["score"] if previous_row else None
    change_status = None
    if previous_score is not None:
        if score > previous_score:
            change_status = "Improved"
        elif score < previous_score:
            change_status = "Degraded"
        else:
            change_status = "Unchanged"

    vulnerability_count = len(vulnerabilities or [])

    connection.execute(
        """
        INSERT INTO scans (
            url, timestamp, score, grade, status_code,
            vulnerability_count, previous_score, change_status,
            vulnerabilities, analysis, recommendations, error_message
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            url,
            timestamp,
            score,
            grade,
            str(status_code),
            vulnerability_count,
            previous_score,
            change_status,
            json.dumps(vulnerabilities),
            json.dumps(analysis or []),
            json.dumps(recommendations or []),
            error_message,
        )
    )
    connection.commit()
    connection.close()


def get_scan_history(limit=None):
    connection = get_db_connection()
    query = """
        SELECT
            id, url, timestamp, score, grade, status_code,
            vulnerability_count, previous_score, change_status,
            vulnerabilities, analysis, recommendations, error_message
        FROM scans
        ORDER BY id DESC
    """

    if limit is not None:
        query += " LIMIT ?"
        rows = connection.execute(query, (limit,)).fetchall()
    else:
        rows = connection.execute(query).fetchall()

    history = []
    for row in rows:
        history.append({
            "id": row["id"],
            "url": row["url"],
            "timestamp": row["timestamp"],
            "score": row["score"],
            "grade": row["grade"],
            "status": row["status_code"],
            "vulnerability_count": row["vulnerability_count"],
            "previous_score": row["previous_score"],
            "change_status": row["change_status"],
            "vulnerabilities": json.loads(row["vulnerabilities"] or "[]"),
            "analysis": json.loads(row["analysis"] or "[]"),
            "recommendations": json.loads(row["recommendations"] or "[]"),
            "error_message": row["error_message"],
        })

    connection.close()
    return history


def delete_scan(scan_id):
    connection = get_db_connection()
    connection.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    connection.commit()
    connection.close()


def clear_scan_history():
    connection = get_db_connection()
    connection.execute("DELETE FROM scans")
    connection.commit()
    connection.close()


init_db()


def build_recommendations(analysis, cookie_issues=None, informational_headers=None):
    recommendations = []
    seen = set()

    for item in analysis or []:
        if item.get("status") == "Present":
            continue
        recommendation = normalize_fix_text(item.get("recommendation") or RECOMMENDATION_RULES.get(item["name"]))
        if recommendation and recommendation not in seen:
            recommendations.append(recommendation)
            seen.add(recommendation)

    for item in cookie_issues or []:
        recommendation = normalize_fix_text(item.get("recommendation"))
        if recommendation and recommendation not in seen:
            recommendations.append(recommendation)
            seen.add(recommendation)

    for item in informational_headers or []:
        recommendation = normalize_fix_text(item.get("recommendation"))
        if recommendation and recommendation not in seen:
            recommendations.append(recommendation)
            seen.add(recommendation)

    if not recommendations:
        recommendations.append("Maintain the current header configuration and continue reviewing it as the application changes.")

    return recommendations


def build_warnings(analysis):
    warnings = []
    seen = set()

    for item in analysis or []:
        if item.get("duplicate"):
            warning_title = f"Duplicate {item['name']} header detected"
            if warning_title not in seen:
                explanation = "The same header value appears multiple times in the response for this control."
                impact = "Duplicate security headers can indicate inconsistent upstream configuration and may cause ambiguous browser behavior."
                recommendation = normalize_fix_text("Remove duplicate header injections so the response sends one clear, authoritative value.")

                if item["name"] == "X-Frame-Options":
                    warning_title = "Duplicate X-Frame-Options may weaken clickjacking protection"
                    explanation = "Multiple X-Frame-Options headers were detected, which can lead to inconsistent frame protection handling."
                    impact = "Conflicting or repeated frame-control headers can weaken clickjacking defenses in some clients or proxy chains."
                    recommendation = normalize_fix_text("Send one authoritative X-Frame-Options value such as DENY or SAMEORIGIN.")

                warnings.append({
                    "title": warning_title,
                    "explanation": explanation,
                    "impact": impact,
                    "recommendation": recommendation,
                })
                seen.add(warning_title)

        if item.get("status") == "Weak":
            warning_title = f"Weak {item['name']} configuration detected"
            if warning_title not in seen:
                warnings.append({
                    "title": warning_title,
                    "explanation": item.get("details") or f"The {item['name']} header is present but configured weakly.",
                    "impact": item.get("impact") or "A weak configuration can reduce the intended protection offered by this header.",
                    "recommendation": normalize_fix_text(item.get("recommendation") or get_header_recommendation(item["name"], item["status"])),
                })
                seen.add(warning_title)

    return warnings


def build_upcoming_headers(headers):
    upcoming_headers = []

    for rule in UPCOMING_HEADER_RULES:
        if not headers.get(rule["name"]):
            upcoming_headers.append({
                "name": rule["name"],
                "explanation": rule["explanation"],
                "impact": rule["impact"],
                "recommendation": rule["recommendation"],
            })

    return upcoming_headers


def build_informational_headers(headers):
    informational_headers = []

    for rule in INFORMATIONAL_HEADER_RULES:
        value = headers.get(rule["name"])
        if value:
            informational_headers.append({
                "name": rule["name"],
                "value": " ".join(str(value).split()),
                "issue": rule["issue"],
                "explanation": rule["explanation"],
                "impact": rule["impact"],
                "recommendation": rule["recommendation"],
            })

    return informational_headers


def extract_set_cookie_headers(response):
    raw_header_source = getattr(getattr(response, "raw", None), "headers", None)

    if raw_header_source is not None:
        try:
            cookies = raw_header_source.get_all("Set-Cookie")
            if cookies:
                return list(cookies)
        except Exception:
            pass

    merged_cookie = response.headers.get("Set-Cookie")
    if merged_cookie:
        return [merged_cookie]

    return []


def analyze_cookie_issues(response):
    cookie_issues = []

    for cookie_header in extract_set_cookie_headers(response):
        parts = [part.strip() for part in str(cookie_header).split(";") if part.strip()]
        if not parts:
            continue

        cookie_name = parts[0].split("=", 1)[0].strip() or "Unknown Cookie"
        attributes = [part.lower() for part in parts[1:]]

        if "httponly" not in attributes:
            cookie_issues.append({
                "cookie": cookie_name,
                "issue": "Cookie missing HttpOnly flag",
                "explanation": "The cookie can be read by client-side scripts because the HttpOnly attribute is not set.",
                "impact": "If an attacker achieves script execution in the browser, the cookie may be easier to steal or reuse.",
                "recommendation": "Set the HttpOnly attribute on this cookie unless client-side JavaScript must access it.",
            })

        if "secure" not in attributes:
            cookie_issues.append({
                "cookie": cookie_name,
                "issue": "Cookie missing Secure flag",
                "explanation": "The cookie does not require transmission over HTTPS because the Secure attribute is missing.",
                "impact": "The cookie may be exposed over insecure transport paths or mixed deployment scenarios.",
                "recommendation": "Set the Secure attribute so the cookie is only sent over HTTPS connections.",
            })

        if not any(attribute.startswith("samesite=") for attribute in attributes):
            cookie_issues.append({
                "cookie": cookie_name,
                "issue": "Cookie missing SameSite attribute",
                "explanation": "The cookie does not define a SameSite policy to control cross-site sending behavior.",
                "impact": "Cross-site requests may include the cookie more broadly, which can increase CSRF and session abuse risk.",
                "recommendation": "Set SameSite=Lax or SameSite=Strict unless a cross-site use case explicitly requires SameSite=None; Secure.",
            })

    return cookie_issues


def split_analysis_sections(analysis):
    present_or_weak = []
    missing_headers = []

    for item in analysis or []:
        if item.get("status") == "Missing":
            missing_headers.append(item)
        else:
            present_or_weak.append(item)

    return present_or_weak, missing_headers


def get_header_recommendation(header_name, status):
    if status == "Present":
        return None
    return normalize_fix_text(
        RECOMMENDATION_RULES.get(
            header_name,
            "Review this header and harden its configuration based on the application's security requirements.",
        )
    )


def normalize_header_value(header_value):
    if not header_value:
        return header_value

    parts = [part.strip() for part in str(header_value).split(",") if part.strip()]
    if not parts:
        return header_value

    deduped_parts = []
    seen = set()
    for part in parts:
        key = part.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped_parts.append(part)

    return ", ".join(deduped_parts)


def count_header_occurrences(raw_headers, header_name):
    target_name = (header_name or "").strip().lower()
    if not target_name:
        return 0

    return sum(
        1
        for header in raw_headers or []
        if (header.get("name") or "").strip().lower() == target_name
    )


def generate_pdf_report(html_content):
    if pdfkit is None:
        raise RuntimeError("pdfkit is not installed. Install pdfkit and wkhtmltopdf to enable PDF export.")

    config = pdfkit.configuration(wkhtmltopdf=WKHTMLTOPDF_PATH)
    return pdfkit.from_string(html_content, False, configuration=config)


def analyze_redirect_chain(response, requested_url):
    chain = [requested_url]
    for hop in response.history:
        hop_url = getattr(hop, "url", None)
        if hop_url and hop_url != chain[-1]:
            chain.append(hop_url)

    final_url = getattr(response, "url", requested_url) or requested_url
    if not chain or chain[-1] != final_url:
        chain.append(final_url)

    redirect_count = max(len(chain) - 1, 0)
    secure_upgrade = False
    downgrade_detected = False

    for current_url, next_url in zip(chain, chain[1:]):
        current_scheme = urlparse(current_url).scheme.lower()
        next_scheme = urlparse(next_url).scheme.lower()

        if current_scheme == "http" and next_scheme == "https":
            secure_upgrade = True
        if current_scheme == "https" and next_scheme == "http":
            downgrade_detected = True

    return {
        "redirect_count": redirect_count,
        "redirect_chain": chain,
        "final_url": final_url,
        "secure_upgrade": secure_upgrade,
        "downgrade_detected": downgrade_detected,
    }


def extract_raw_headers(response):
    raw_header_items = []
    raw_header_source = getattr(getattr(response, "raw", None), "headers", None)

    if raw_header_source is not None:
        try:
            raw_header_items = list(raw_header_source.items())
        except Exception:
            raw_header_items = []

    if not raw_header_items:
        raw_header_items = list(response.headers.items())

    formatted_headers = []
    for name, value in raw_header_items:
        formatted_headers.append({
            "name": str(name).strip(),
            "value": " ".join(str(value).split()),
        })

    return formatted_headers


def get_response_size(response):
    content_length = response.headers.get("Content-Length")
    if content_length:
        try:
            return int(content_length)
        except ValueError:
            pass

    try:
        return len(response.content or b"")
    except Exception:
        return 0


def get_server_info(headers):
    server_info = {}

    server_header = headers.get("Server")
    powered_by_header = headers.get("X-Powered-By")

    if server_header:
        server_info["server"] = " ".join(str(server_header).split())
    if powered_by_header:
        server_info["x_powered_by"] = " ".join(str(powered_by_header).split())

    return server_info


def format_certificate_issuer(issuer):
    issuer_parts = []

    for part in issuer or []:
        for key, value in part:
            issuer_parts.append(f"{key}={value}")

    return ", ".join(issuer_parts) if issuer_parts else None


def decode_certificate(binary_certificate):
    if not binary_certificate:
        return None

    pem_certificate = ssl.DER_cert_to_PEM_cert(binary_certificate)

    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as temp_cert:
        temp_cert.write(pem_certificate)
        temp_cert_path = temp_cert.name

    try:
        return ssl._ssl._test_decode_cert(temp_cert_path)
    finally:
        Path(temp_cert_path).unlink(missing_ok=True)


def analyze_tls(final_url):
    parsed = urlparse(final_url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        return {
            "uses_https": False,
            "ssl_valid": False,
            "ssl_expiry_date": None,
            "ssl_expiry_days": None,
            "ssl_issuer": None,
            "ssl_expired": False,
            "ssl_near_expiry": False,
        }

    hostname = parsed.hostname
    port = 443

    try:
        context = ssl._create_unverified_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                certificate = decode_certificate(secure_sock.getpeercert(binary_form=True)) or {}

        expiry_raw = certificate.get("notAfter")
        expiry_date = datetime.strptime(expiry_raw, "%b %d %H:%M:%S %Y %Z") if expiry_raw else None
        expiry_date_display = expiry_date.strftime("%Y-%m-%d %H:%M:%S UTC") if expiry_date else None
        expiry_days = None
        expired = False
        near_expiry = False

        if expiry_date:
            expiry_days = (expiry_date.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
            expired = expiry_days < 0
            near_expiry = 0 <= expiry_days < 30

        return {
            "uses_https": True,
            "ssl_valid": not expired,
            "ssl_expiry_date": expiry_date_display,
            "ssl_expiry_days": expiry_days,
            "ssl_issuer": format_certificate_issuer(certificate.get("issuer")),
            "ssl_expired": expired,
            "ssl_near_expiry": near_expiry,
        }
    except Exception:
        return {
            "uses_https": True,
            "ssl_valid": False,
            "ssl_expiry_date": None,
            "ssl_expiry_days": None,
            "ssl_issuer": None,
            "ssl_expired": False,
            "ssl_near_expiry": False,
        }


def classify_header(header_name, header_value, report_only_value=None):
    if not header_value:
        if header_name == "Content-Security-Policy" and report_only_value:
            return "Weak", "Only a report-only CSP is present, so the policy is monitored but not enforced."
        return "Missing", "Header not found in the response."

    value = header_value.lower()
    parts = [part.strip() for part in value.split(",") if part.strip()]

    if header_name == "Content-Security-Policy":
        if "unsafe-inline" in value or "unsafe-eval" in value:
            return "Weak", "Allows unsafe script execution directives that weaken XSS protection."
        return "Present", "Policy is present and does not use common unsafe directives."

    if header_name == "X-Frame-Options":
        if not parts:
            return "Weak", "Value should normally be DENY or SAMEORIGIN."
        if any(part not in ["deny", "sameorigin"] for part in parts):
            return "Weak", "Value should normally be DENY or SAMEORIGIN."
        return "Present", "Frame embedding restrictions are configured."

    if header_name == "Strict-Transport-Security":
        if "max-age=" not in value:
            return "Weak", "HSTS is present but does not define a max-age directive."
        if "max-age=0" in value:
            return "Weak", "HSTS is effectively disabled with max-age=0."
        return "Present", "Browser HTTPS enforcement is configured."

    if header_name == "X-Content-Type-Options":
        if not parts:
            return "Weak", "Recommended value is nosniff."
        if any(part != "nosniff" for part in parts):
            return "Weak", "Recommended value is nosniff."
        return "Present", "MIME sniffing protection is enabled."

    if header_name == "Referrer-Policy":
        weak_values = ["unsafe-url", "no-referrer-when-downgrade"]
        if any(item in value for item in weak_values):
            return "Weak", "Policy may leak more referrer data than recommended."
        return "Present", "Referrer sharing is restricted."

    if header_name == "Permissions-Policy":
        if value.strip() in ["*", "fullscreen=*"]:
            return "Weak", "Policy is overly broad and allows unnecessary browser features."
        return "Present", "Browser feature access is explicitly controlled."

    if header_name == "Cache-Control":
        weak_markers = ["public", "immutable"]
        if any(item in value for item in weak_markers) and "no-store" not in value:
            return "Weak", "Caching policy may allow sensitive pages to be stored too broadly."
        return "Present", "Caching behavior is explicitly controlled."

    return "Present", "Header is present."


def map_vulnerabilities(analysis, tls_data=None, cookie_issues=None):
    vulnerabilities = []

    for item in analysis or []:
        rule = VULNERABILITY_RULES.get(item["name"])
        if not rule or item["status"] == "Present":
            continue

        severity = rule["severity_missing"]
        if item["status"] == "Weak":
            severity = rule["severity_weak"]
        elif item["name"] == "Strict-Transport-Security":
            uses_https = (tls_data or {}).get("uses_https", False)
            if uses_https:
                severity = "High"

        vulnerabilities.append({
            "header": item["name"],
            "title": rule["title"],
            "severity": severity,
            "category": rule["category"],
            "description": rule["description"],
            "explanation": rule["description"],
            "impact": rule["impact"],
            "status": item["status"],
            "triggers": [f"{item['name']} ({item['status']})"],
            "recommendation": normalize_fix_text(item.get("recommendation") or RECOMMENDATION_RULES.get(item["name"])),
        })

    if cookie_issues:
        cookie_recommendations = []
        cookie_triggers = []

        for item in cookie_issues:
            cookie_triggers.append(f"{item['cookie']}: {item['issue']}")
            recommendation = item.get("recommendation")
            if recommendation and recommendation not in cookie_recommendations:
                cookie_recommendations.append(normalize_fix_text(recommendation))

        vulnerabilities.append({
            "header": "Set-Cookie",
            "title": "Session Hijacking Risk",
            "severity": "High",
            "category": "Session Hijacking",
            "description": "Missing protective cookie attributes can expose session cookies to theft or unsafe cross-site use.",
            "explanation": "One or more cookies are missing security attributes that help protect active sessions in the browser.",
            "impact": "Exposed session cookies can be easier to steal, reuse, or send in unsafe cross-site scenarios.",
            "status": "Multiple cookie issues",
            "triggers": cookie_triggers,
            "recommendation": " ".join(cookie_recommendations) if cookie_recommendations else normalize_fix_text("Add Secure, HttpOnly, and SameSite to sensitive cookies."),
        })

    return vulnerabilities


def fetch_response(url):
    with requests.Session() as session:
        session.headers.update(REQUEST_HEADERS)

        try:
            head_response = session.head(url, timeout=10, allow_redirects=True)
            if head_response.ok and head_response.headers:
                return head_response
        except requests.exceptions.RequestException:
            pass

        return session.get(url, timeout=10, allow_redirects=True)


def fetch_html_response(url):
    with requests.Session() as session:
        session.headers.update(REQUEST_HEADERS)
        return session.get(url, timeout=10, allow_redirects=True)


def ensure_full_response(response, fallback_url):
    if getattr(response.request, "method", "").upper() == "GET":
        return response

    try:
        return fetch_html_response(fallback_url)
    except requests.exceptions.RequestException:
        return response


def analyze_mixed_content(response, final_url):
    if urlparse(final_url).scheme.lower() != "https":
        return False

    candidate_response = response

    try:
        if getattr(response.request, "method", "").upper() != "GET":
            candidate_response = fetch_html_response(final_url)
    except requests.exceptions.RequestException:
        candidate_response = response

    content_type = (candidate_response.headers.get("Content-Type") or "").lower()
    if "html" not in content_type:
        return False

    try:
        response_text = candidate_response.text or ""
    except Exception:
        return False

    try:
        soup = BeautifulSoup(response_text, "html.parser")
    except Exception:
        return False

    resource_selectors = [
        ("script", "src"),
        ("img", "src"),
        ("link", "href"),
    ]

    for tag_name, attribute_name in resource_selectors:
        for element in soup.find_all(tag_name):
            attribute_value = (element.get(attribute_name) or "").strip().lower()
            if attribute_value.startswith("http://"):
                return True

    return False


def check_security_headers(url):
    start_time = perf_counter()
    try:
        initial_response = fetch_response(url)
        redirect_data = analyze_redirect_chain(initial_response, url)
        response = ensure_full_response(initial_response, redirect_data["final_url"])
        redirect_data = analyze_redirect_chain(response, url)
        tls_data = analyze_tls(redirect_data["final_url"])
        mixed_content = analyze_mixed_content(response, redirect_data["final_url"])

        headers = response.headers
        status_code = response.status_code
        raw_headers = extract_raw_headers(response)
        scan_time = round(perf_counter() - start_time, 4)
        response_size = get_response_size(response)
        server_info = get_server_info(headers)

        analysis = []
        score = 100

        for rule in HEADER_RULES:
            header_name = rule["name"]
            header_value = headers.get(header_name)
            report_only_value = None
            if header_name == "Content-Security-Policy":
                report_only_value = headers.get("Content-Security-Policy-Report-Only")

            normalized_header_value = normalize_header_value(header_value)
            normalized_report_only_value = normalize_header_value(report_only_value)
            effective_value = normalized_header_value or normalized_report_only_value
            status, details = classify_header(header_name, header_value, report_only_value)
            has_duplicates = count_header_occurrences(raw_headers, header_name) > 1
            if header_name == "Content-Security-Policy":
                has_duplicates = has_duplicates or count_header_occurrences(raw_headers, "Content-Security-Policy-Report-Only") > 1
            display_status = f"{status} (Duplicate)" if has_duplicates and status != "Missing" else status
            if has_duplicates and status != "Missing":
                details = f"{details} Duplicate headers detected. This may indicate misconfiguration."
            penalty = 0

            if status == "Missing":
                penalty = rule["missing_penalty"]
            elif status == "Weak":
                penalty = rule["weak_penalty"]

            score -= penalty

            analysis.append({
                "name": header_name,
                "value": effective_value or "Not set",
                "status": status,
                "display_status": display_status,
                "duplicate": has_duplicates,
                "has_duplicates": has_duplicates,
                "weight": rule["weight"],
                "penalty": penalty,
                "details": details,
                "explanation": rule["explanation"],
                "impact": rule["impact"],
                "recommendation": get_header_recommendation(header_name, status),
            })

        cookie_issues = analyze_cookie_issues(response)
        vulnerabilities = map_vulnerabilities(analysis, tls_data, cookie_issues)
        score = max(score, 0)
        grade = calculate_grade(score)

        warnings = build_warnings(analysis)
        upcoming_headers = build_upcoming_headers(headers)
        informational_headers = build_informational_headers(headers)
        recommendations = build_recommendations(analysis, cookie_issues, informational_headers)

        score -= calculate_duplicate_penalty(analysis)
        score -= calculate_cookie_issue_penalty(cookie_issues)
        score -= calculate_info_disclosure_penalty(informational_headers)

        score = max(score, 0)
        grade = calculate_grade(score)

        return analysis, vulnerabilities, recommendations, warnings, upcoming_headers, informational_headers, cookie_issues, raw_headers, redirect_data, tls_data, mixed_content, scan_time, response_size, server_info, score, grade, status_code, None

    except requests.exceptions.SSLError:
        fallback_tls = analyze_tls(url)
        return None, [], [], [], [], [], [], [], {
            "redirect_count": 0,
            "redirect_chain": [url],
            "final_url": url,
            "secure_upgrade": False,
            "downgrade_detected": False,
        }, fallback_tls, False, round(perf_counter() - start_time, 4), 0, {}, 0, "D", "SSL Error", (
            "SSL certificate validation failed. The production version enforces SSL verification and "
            "does not continue when a certificate is invalid."
        )

    except requests.exceptions.Timeout:
        return None, [], [], [], [], [], [], [], {
            "redirect_count": 0,
            "redirect_chain": [url],
            "final_url": url,
            "secure_upgrade": False,
            "downgrade_detected": False,
        }, {
            "uses_https": urlparse(url).scheme.lower() == "https",
            "ssl_valid": False,
            "ssl_expiry_date": None,
            "ssl_expiry_days": None,
            "ssl_issuer": None,
            "ssl_expired": False,
            "ssl_near_expiry": False,
        }, False, round(perf_counter() - start_time, 4), 0, {}, 0, "D", "Timeout", "The target site did not respond before the request timed out."

    except requests.exceptions.ConnectionError:
        return None, [], [], [], [], [], [], [], {
            "redirect_count": 0,
            "redirect_chain": [url],
            "final_url": url,
            "secure_upgrade": False,
            "downgrade_detected": False,
        }, {
            "uses_https": urlparse(url).scheme.lower() == "https",
            "ssl_valid": False,
            "ssl_expiry_date": None,
            "ssl_expiry_days": None,
            "ssl_issuer": None,
            "ssl_expired": False,
            "ssl_near_expiry": False,
        }, False, round(perf_counter() - start_time, 4), 0, {}, 0, "D", "Connection Error", "The scanner could not establish a connection to the target."

    except Exception as e:
        print("REAL ERROR:", e)
        return None, [], [], [], [], [], [], [], {
            "redirect_count": 0,
            "redirect_chain": [url],
            "final_url": url,
            "secure_upgrade": False,
            "downgrade_detected": False,
        }, {
            "uses_https": urlparse(url).scheme.lower() == "https",
            "ssl_valid": False,
            "ssl_expiry_date": None,
            "ssl_expiry_days": None,
            "ssl_issuer": None,
            "ssl_expired": False,
            "ssl_near_expiry": False,
        }, False, round(perf_counter() - start_time, 4), 0, {}, 0, "D", "N/A", "An unexpected error occurred while scanning the target."


@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "GET":
        return render_template("index.html", form_error=None, error=None)

    if request.method == "POST":
        # 🔥 CLEAN INPUT HERE
        try:
            print("Form data:", request.form)
            url = request.form.get("url")
            if not url:
                return render_template("index.html", error="Please enter a valid URL", form_error="Please enter a valid URL"), 400
            url = normalize_url(url)
        except ValueError as exc:
            return render_template("index.html", form_error=str(exc), error=str(exc)), 400

        analysis, vulnerabilities, recommendations, warnings, upcoming_headers, informational_headers, cookie_issues, raw_headers, redirect_data, tls_data, mixed_content, scan_time, response_size, server_info, score, grade, status_code, error_message = check_security_headers(url)
        timestamp = current_timestamp()

        save_scan(
            url=url,
            timestamp=timestamp,
            score=score,
            grade=grade,
            status_code=status_code,
            vulnerabilities=vulnerabilities,
            analysis=analysis,
            recommendations=recommendations,
            error_message=error_message,
        )
        history = get_scan_history(limit=10)
        header_analysis, missing_headers = split_analysis_sections(analysis)

        return render_template(
            "result.html",
            url=url,
            analysis=analysis,
            header_analysis=header_analysis,
            missing_headers=missing_headers,
            vulnerabilities=vulnerabilities,
            recommendations=recommendations,
            warnings=warnings,
            upcoming_headers=upcoming_headers,
            informational_headers=informational_headers,
            cookie_issues=cookie_issues,
            raw_headers=raw_headers,
            redirect_count=redirect_data["redirect_count"],
            redirect_chain=redirect_data["redirect_chain"],
            final_url=redirect_data["final_url"],
            secure_upgrade=redirect_data["secure_upgrade"],
            downgrade_detected=redirect_data["downgrade_detected"],
            ssl_valid=tls_data["ssl_valid"],
            ssl_expiry_days=tls_data["ssl_expiry_days"],
            ssl_issuer=tls_data["ssl_issuer"],
            uses_https=tls_data["uses_https"],
            ssl_expired=tls_data["ssl_expired"],
            ssl_near_expiry=tls_data["ssl_near_expiry"],
            mixed_content=mixed_content,
            scan_time=scan_time,
            response_size=response_size,
            server_info=server_info,
            score=score,
            grade=grade,
            status_code=status_code,
            timestamp=timestamp,
            error_message=error_message,
            history=history
        )

    return render_template("index.html", form_error=None, error=None)


@app.route("/history")
def history():
    return render_template("history.html", history=get_scan_history())


@app.route("/history/delete/<int:scan_id>", methods=["POST"])
def delete_history_item(scan_id):
    delete_scan(scan_id)
    return redirect(url_for("history"))


@app.route("/history/clear", methods=["POST"])
def clear_history():
    clear_scan_history()
    return redirect(url_for("history"))


@app.route("/download-report", methods=["POST"])
def download_report():
    url = request.form["url"]
    timestamp = request.form["timestamp"]
    status_code = request.form["status_code"]
    score = request.form["score"]
    grade = request.form["grade"]
    analysis = json.loads(request.form["analysis_json"])
    vulnerabilities = json.loads(request.form["vulnerabilities_json"])
    recommendations = json.loads(request.form["recommendations_json"])
    warnings = json.loads(request.form.get("warnings_json", "[]"))
    upcoming_headers = json.loads(request.form.get("upcoming_headers_json", "[]"))
    informational_headers = json.loads(request.form.get("informational_headers_json", "[]"))
    cookie_issues = json.loads(request.form.get("cookie_issues_json", "[]"))
    raw_headers = json.loads(request.form.get("raw_headers_json", "[]"))
    error_message = request.form.get("error_message") or None
    header_analysis, missing_headers = split_analysis_sections(analysis)

    report_html = render_template(
        "report.html",
        url=url,
        timestamp=timestamp,
        score=score,
        grade=grade,
        status_code=status_code,
        analysis=analysis,
        header_analysis=header_analysis,
        missing_headers=missing_headers,
        vulnerabilities=vulnerabilities,
        recommendations=recommendations,
        warnings=warnings,
        upcoming_headers=upcoming_headers,
        informational_headers=informational_headers,
        cookie_issues=cookie_issues,
        raw_headers=raw_headers,
        error_message=error_message,
    )
    pdf_data = generate_pdf_report(report_html)

    safe_name = "".join(char if char.isalnum() else "_" for char in url)[:40] or "scan"
    return Response(
        pdf_data,
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}_report.pdf"'},
    )


if __name__ == "__main__":
    app.run(debug=True)

