import argparse
import json
import urllib.request


REQUIRED_HEADERS = {
    "strict-transport-security": "Enforces HTTPS for future connections.",
    "content-security-policy": "Limits where browser-loaded content can come from.",
    "x-frame-options": "Reduces clickjacking risk.",
    "x-content-type-options": "Prevents MIME type sniffing.",
    "referrer-policy": "Controls referrer information sent by the browser.",
    "permissions-policy": "Restricts access to browser features.",
}


def audit_headers(headers: dict[str, str]) -> dict:
    normalized = {key.lower(): value for key, value in headers.items()}
    results = {}

    for header, description in REQUIRED_HEADERS.items():
        value = normalized.get(header)
        results[header] = {
            "present": value is not None,
            "value": value,
            "description": description,
        }

    score = sum(1 for result in results.values() if result["present"])
    return {
        "score": score,
        "total": len(REQUIRED_HEADERS),
        "results": results,
    }


def fetch_headers(url: str) -> dict[str, str]:
    request = urllib.request.Request(url, headers={"User-Agent": "security-header-auditor/1.0"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return dict(response.headers.items())


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit basic HTTP security headers for an authorized site.")
    parser.add_argument("url")
    args = parser.parse_args()

    headers = fetch_headers(args.url)
    print(json.dumps(audit_headers(headers), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
