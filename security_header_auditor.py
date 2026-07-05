"""Audit common HTTP security headers for authorized websites."""

from __future__ import annotations

import argparse
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass


HEADER_POLICIES = {
    "strict-transport-security": {
        "description": "Enforces HTTPS for future browser connections.",
        "recommendation": "Use a long max-age value and includeSubDomains after validating HTTPS coverage.",
    },
    "content-security-policy": {
        "description": "Restricts where browser-loaded content may come from.",
        "recommendation": "Define a restrictive policy and avoid unsafe-inline where possible.",
    },
    "x-frame-options": {
        "description": "Reduces clickjacking risk in legacy browser contexts.",
        "recommendation": "Use DENY or SAMEORIGIN unless framing is explicitly required.",
    },
    "x-content-type-options": {
        "description": "Prevents MIME type sniffing.",
        "recommendation": "Set to nosniff.",
    },
    "referrer-policy": {
        "description": "Controls how much referrer information browsers send.",
        "recommendation": "Use no-referrer or strict-origin-when-cross-origin.",
    },
    "permissions-policy": {
        "description": "Restricts access to powerful browser features.",
        "recommendation": "Disable features that the application does not require.",
    },
}


@dataclass(frozen=True)
class HeaderFinding:
    header: str
    present: bool
    value: str | None
    status: str
    description: str
    recommendation: str


def normalize_headers(headers: dict[str, str]) -> dict[str, str]:
    return {key.lower(): value.strip() for key, value in headers.items()}


def validate_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("URL must include http:// or https:// and a hostname.")
    return url


def _status_for_header(header: str, value: str | None) -> str:
    if value is None:
        return "missing"

    lowered = value.lower()
    if header == "strict-transport-security":
        max_age = re.search(r"max-age=(\d+)", lowered)
        if not max_age:
            return "weak"
        if int(max_age.group(1)) < 15552000:
            return "weak"
    if header == "content-security-policy" and "unsafe-inline" in lowered:
        return "review"
    if header == "x-content-type-options" and lowered != "nosniff":
        return "weak"
    if header == "x-frame-options" and lowered not in {"deny", "sameorigin"}:
        return "weak"

    return "present"


def audit_headers(headers: dict[str, str]) -> dict:
    normalized = normalize_headers(headers)
    findings: list[HeaderFinding] = []

    for header, policy in HEADER_POLICIES.items():
        value = normalized.get(header)
        findings.append(
            HeaderFinding(
                header=header,
                present=value is not None,
                value=value,
                status=_status_for_header(header, value),
                description=policy["description"],
                recommendation=policy["recommendation"],
            )
        )

    strong = sum(1 for finding in findings if finding.status == "present")
    review = sum(1 for finding in findings if finding.status == "review")
    weak = sum(1 for finding in findings if finding.status == "weak")
    missing = sum(1 for finding in findings if finding.status == "missing")
    total = len(findings)
    score = round(((strong + (review * 0.5)) / total) * 100)

    return {
        "score": score,
        "summary": {
            "strong": strong,
            "review": review,
            "weak": weak,
            "missing": missing,
            "total": total,
        },
        "findings": [asdict(finding) for finding in findings],
    }


def fetch_headers(url: str, timeout: int = 10) -> dict[str, str]:
    validate_url(url)
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "security-header-auditor/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return dict(response.headers.items())
    except urllib.error.HTTPError as error:
        return dict(error.headers.items())
    except urllib.error.URLError:
        request = urllib.request.Request(url, headers={"User-Agent": "security-header-auditor/1.0"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return dict(response.headers.items())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit common HTTP security headers for an authorized site.")
    parser.add_argument("url")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    headers = fetch_headers(args.url, timeout=args.timeout)
    print(json.dumps(audit_headers(headers), indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
