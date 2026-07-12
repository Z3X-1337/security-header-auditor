"""Audit common HTTP security headers for authorized websites."""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass


SCHEMA_VERSION = "1.1"
USER_AGENT = "security-header-auditor/1.1"
HEAD_FALLBACK_STATUS_CODES = {405, 501}

HEADER_POLICIES = {
    "strict-transport-security": {
        "description": "Enforces HTTPS for future browser connections.",
        "recommendation": "Use max-age of at least 15552000 seconds and add includeSubDomains only after validating HTTPS coverage.",
    },
    "content-security-policy": {
        "description": "Restricts where browser-loaded content may come from.",
        "recommendation": "Use a restrictive policy with explicit script, object, base, and framing controls; avoid broad or unsafe sources.",
    },
    "x-frame-options": {
        "description": "Reduces clickjacking risk in legacy browser contexts.",
        "recommendation": "Use DENY or SAMEORIGIN unless framing is explicitly required; prefer CSP frame-ancestors for modern control.",
    },
    "x-content-type-options": {
        "description": "Prevents MIME type sniffing.",
        "recommendation": "Set to nosniff.",
    },
    "referrer-policy": {
        "description": "Controls how much referrer information browsers send.",
        "recommendation": "Use no-referrer or strict-origin-when-cross-origin unless the application has a documented alternative.",
    },
    "permissions-policy": {
        "description": "Restricts access to powerful browser features.",
        "recommendation": "Explicitly disable browser features that the application does not require.",
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
    observations: list[str]


@dataclass(frozen=True)
class RedirectHop:
    status_code: int
    from_url: str
    to_url: str


@dataclass(frozen=True)
class FetchResult:
    requested_url: str
    final_url: str
    request_method: str
    status_code: int
    headers: dict[str, str]
    redirects: list[RedirectHop]


class AuditNetworkError(RuntimeError):
    """Raised when a target cannot be reached or audited."""


class RedirectRecorder(urllib.request.HTTPRedirectHandler):
    """Follow redirects while retaining an ordered redirect chain."""

    def __init__(self) -> None:
        super().__init__()
        self.redirects: list[RedirectHop] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        resolved = urllib.parse.urljoin(req.full_url, newurl)
        self.redirects.append(RedirectHop(status_code=code, from_url=req.full_url, to_url=resolved))
        return super().redirect_request(req, fp, code, msg, headers, resolved)


def normalize_headers(headers: dict[str, str]) -> dict[str, str]:
    return {key.lower(): value.strip() for key, value in headers.items()}


def validate_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must include http:// or https:// and a hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing embedded credentials are not accepted.")
    return url


def parse_csp(value: str) -> dict[str, list[str]]:
    """Parse a CSP header into normalized directive tokens."""

    directives: dict[str, list[str]] = {}
    for raw_directive in value.split(";"):
        parts = raw_directive.strip().split()
        if not parts:
            continue
        name = parts[0].lower()
        directives[name] = parts[1:]
    return directives


def _csp_status(value: str) -> tuple[str, list[str]]:
    directives = parse_csp(value)
    observations: list[str] = []

    if "default-src" not in directives and "script-src" not in directives:
        observations.append("Neither default-src nor script-src is defined.")
        return "weak", observations

    script_sources = directives.get("script-src", directives.get("default-src", []))
    risky_script_sources = {"'unsafe-inline'", "'unsafe-eval'", "*", "data:"}
    observed_risky_sources = sorted(source for source in script_sources if source.lower() in risky_script_sources)
    if observed_risky_sources:
        observations.append(f"Risky script source tokens: {', '.join(observed_risky_sources)}.")

    object_sources = [token.lower() for token in directives.get("object-src", [])]
    if object_sources != ["'none'"]:
        observations.append("object-src is not explicitly restricted to 'none'.")

    if "base-uri" not in directives:
        observations.append("base-uri is not defined.")

    if "frame-ancestors" not in directives:
        observations.append("frame-ancestors is not defined; review framing controls.")

    return ("review", observations) if observations else ("present", [])


def _status_for_header(header: str, value: str | None) -> tuple[str, list[str]]:
    if value is None:
        return "missing", ["Header is not present in the audited response."]

    lowered = value.lower()
    observations: list[str] = []

    if header == "strict-transport-security":
        max_age = re.search(r"(?:^|;)\s*max-age=(\d+)", lowered)
        if not max_age:
            return "weak", ["max-age is missing or malformed."]
        if int(max_age.group(1)) < 15552000:
            return "weak", ["max-age is below 15552000 seconds."]

    if header == "content-security-policy":
        return _csp_status(value)

    if header == "x-content-type-options" and lowered != "nosniff":
        return "weak", ["Expected the exact value nosniff."]

    if header == "x-frame-options" and lowered not in {"deny", "sameorigin"}:
        return "weak", ["Expected DENY or SAMEORIGIN."]

    if header == "referrer-policy":
        accepted = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
        policies = {part.strip() for part in lowered.split(",") if part.strip()}
        if not policies.intersection(accepted):
            return "review", ["The policy is present but is not one of the conservative baseline values."]

    if header == "permissions-policy" and "*" in lowered:
        return "review", ["Wildcard feature access is present and requires application-specific review."]

    return "present", observations


def audit_headers(headers: dict[str, str]) -> dict:
    normalized = normalize_headers(headers)
    findings: list[HeaderFinding] = []

    for header, policy in HEADER_POLICIES.items():
        value = normalized.get(header)
        status, observations = _status_for_header(header, value)
        findings.append(
            HeaderFinding(
                header=header,
                present=value is not None,
                value=value,
                status=status,
                description=policy["description"],
                recommendation=policy["recommendation"],
                observations=observations,
            )
        )

    counts = {
        status: sum(1 for finding in findings if finding.status == status)
        for status in ("present", "review", "weak", "missing")
    }
    total = len(findings)
    score = round(
        (
            counts["present"]
            + (counts["review"] * 0.5)
            + (counts["weak"] * 0.25)
        )
        / total
        * 100
    )

    return {
        "score": score,
        "summary": {
            "strong": counts["present"],
            "review": counts["review"],
            "weak": counts["weak"],
            "missing": counts["missing"],
            "total": total,
        },
        "findings": [asdict(finding) for finding in findings],
    }


def _perform_request(url: str, method: str, timeout: int) -> FetchResult:
    recorder = RedirectRecorder()
    opener = urllib.request.build_opener(recorder)
    request = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT})

    try:
        with opener.open(request, timeout=timeout) as response:
            return FetchResult(
                requested_url=url,
                final_url=response.geturl(),
                request_method=method,
                status_code=response.getcode() or 0,
                headers=dict(response.headers.items()),
                redirects=recorder.redirects,
            )
    except urllib.error.HTTPError as error:
        if method == "HEAD" and error.code in HEAD_FALLBACK_STATUS_CODES:
            return _perform_request(url, "GET", timeout)
        return FetchResult(
            requested_url=url,
            final_url=error.geturl(),
            request_method=method,
            status_code=error.code,
            headers=dict(error.headers.items()) if error.headers else {},
            redirects=recorder.redirects,
        )
    except urllib.error.URLError as error:
        reason = getattr(error, "reason", error)
        raise AuditNetworkError(f"Unable to reach target: {reason}") from error


def fetch_target(url: str, timeout: int = 10) -> FetchResult:
    validate_url(url)
    if timeout <= 0:
        raise ValueError("Timeout must be greater than zero.")
    return _perform_request(url, "HEAD", timeout)


def fetch_headers(url: str, timeout: int = 10) -> dict[str, str]:
    """Backward-compatible helper that returns only final response headers."""

    return fetch_target(url, timeout=timeout).headers


def build_report(fetch_result: FetchResult) -> dict:
    audit = audit_headers(fetch_result.headers)
    warnings: list[str] = []
    if urllib.parse.urlsplit(fetch_result.final_url).scheme == "http":
        warnings.append("The final response uses HTTP; browser security headers cannot compensate for missing transport security.")
    if fetch_result.status_code >= 400:
        warnings.append(f"Headers were audited from an HTTP {fetch_result.status_code} response.")

    return {
        "schema_version": SCHEMA_VERSION,
        "target": {
            "requested_url": fetch_result.requested_url,
            "final_url": fetch_result.final_url,
            "request_method": fetch_result.request_method,
            "status_code": fetch_result.status_code,
            "redirects": [asdict(hop) for hop in fetch_result.redirects],
        },
        **audit,
        "warnings": warnings,
        "limitations": [
            "The tool evaluates selected response headers and is not a vulnerability scanner.",
            "Header presence does not prove that the application enforces a secure policy in every route or response.",
            "CSP analysis is a deterministic baseline and requires application-specific review.",
        ],
    }


def determine_exit_code(report: dict, fail_under: int) -> int:
    if not 0 <= fail_under <= 100:
        raise ValueError("--fail-under must be between 0 and 100.")
    return 1 if report["score"] < fail_under else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit common HTTP security headers for an authorized site.")
    parser.add_argument("url")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--fail-under", type=int, default=0, metavar="SCORE", help="Exit with code 1 when the score is below SCORE (0-100).")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        fetch_result = fetch_target(args.url, timeout=args.timeout)
        report = build_report(fetch_result)
        exit_code = determine_exit_code(report, args.fail_under)
    except (ValueError, AuditNetworkError) as error:
        print(json.dumps({"error": str(error), "schema_version": SCHEMA_VERSION}), file=sys.stderr)
        return 2

    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
