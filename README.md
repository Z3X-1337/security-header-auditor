# Security Header Auditor

Security Header Auditor checks common HTTP security headers for websites you own or are explicitly authorized to assess.

It is a defensive learning tool for web security hygiene, not a vulnerability scanner.

## Headers Checked

- Strict-Transport-Security
- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

## Features

- Validates URL input before making requests.
- Uses a HEAD request first to reduce unnecessary response body transfer.
- Falls back safely when servers return headers with HTTP error responses.
- Scores strong, review, weak, and missing header states.
- Provides a recommendation for every checked header.
- Uses only the Python standard library.

## Usage

```bash
python security_header_auditor.py https://example.com --pretty
```

## Example Finding

```json
{
  "header": "x-content-type-options",
  "present": true,
  "recommendation": "Set to nosniff.",
  "status": "present",
  "value": "nosniff"
}
```

## Run Tests

```bash
python -m unittest -v
```

## Continuous Integration

The repository includes a GitHub Actions workflow that runs the test suite on every push and pull request.

## Safety

Only run this tool against systems you own or have explicit permission to test. Do not use it as a broad internet scanner.
