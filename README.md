# Security Header Auditor

Security Header Auditor is a deterministic Python command-line utility for reviewing selected HTTP response security headers on websites you own or are explicitly authorized to assess.

It is intended for web-security hygiene checks, CI quality gates, and defensive learning. It is not a vulnerability scanner and does not prove that an application is secure.

## Headers Checked

- Strict-Transport-Security
- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

## Current Capabilities

- Validates HTTP and HTTPS URLs and rejects embedded credentials.
- Starts with a `HEAD` request to avoid downloading response bodies.
- Falls back to `GET` when the target rejects `HEAD` with HTTP 405 or 501.
- Records the complete followed redirect chain and final response URL.
- Audits headers returned with successful and HTTP error responses.
- Performs baseline CSP directive analysis, including risky script sources and missing object, base, or framing controls.
- Produces schema-versioned JSON with findings, observations, warnings, and limitations.
- Supports a CI threshold through `--fail-under`.
- Uses only the Python standard library.

## Usage

```bash
python security_header_auditor.py https://example.com --pretty
python security_header_auditor.py https://example.com --fail-under 70 --pretty
```

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Audit completed and the score met `--fail-under`. |
| `1` | Audit completed, but the score was below `--fail-under`. |
| `2` | Invalid input, invalid configuration, or a network failure prevented the audit. |

## Report Structure

The JSON report includes:

- Requested URL, final URL, request method, and HTTP status.
- Ordered redirect hops.
- Score and finding counts.
- Per-header status, recommendation, and evidence observations.
- Transport and response-status warnings.
- Explicit analysis limitations.

## CSP Baseline

The CSP review is intentionally conservative. It checks for:

- A `default-src` or `script-src` control.
- Broad or unsafe script source tokens such as `*`, `data:`, `'unsafe-inline'`, and `'unsafe-eval'`.
- `object-src 'none'`.
- A defined `base-uri`.
- A defined `frame-ancestors` directive.

This is not a full browser-policy parser. A policy must still be reviewed against the application's actual resource requirements.

## Run Tests

```bash
python -m unittest -v
```

The test suite covers policy scoring, CSP parsing, redirect recording, `HEAD`-to-`GET` fallback behavior, input validation, JSON serialization, CLI behavior, and CI exit-code thresholds.

## Continuous Integration

GitHub Actions runs the complete test suite on Python 3.10, 3.11, and 3.12 for every push and pull request.

## Safety and Limitations

- Run the tool only against systems you own or have explicit permission to assess.
- Do not use it as a broad internet scanner.
- Header presence does not prove correct enforcement on every application route.
- CSP findings are deterministic baseline observations, not an exploitability conclusion.
- The tool does not inspect HTML, JavaScript, cookies, TLS configuration, application logic, or server vulnerabilities.
