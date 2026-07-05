# Security Header Auditor

Check whether a website returns common HTTP security headers.

This is a defensive learning project for basic web security hygiene. Only run it against websites you own or have permission to assess.

## Headers Checked

- Strict-Transport-Security
- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

## Usage

```bash
python security_header_auditor.py https://example.com
```

## Run Tests

```bash
python -m unittest test_security_header_auditor.py
```

## Safety Note

This tool performs a simple HTTP GET request. It is not a vulnerability scanner and should not be used against systems without authorization.
