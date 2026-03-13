import requests

REQUIRED_HEADERS = {
    "X-Frame-Options": ["DENY", "SAMEORIGIN"],
    "Content-Security-Policy": ["default-src"],
    "Strict-Transport-Security": ["max-age"]
}


def analyze_headers(base_url: str):
    issues = []
    try:
        resp = requests.get(base_url, timeout=5)
    except Exception as exc:
        issues.append(
            {
                "type": "HEADERS_ERROR",
                "severity": "HIGH",
                "detail": f"Failed to fetch {base_url}: {exc}"
            }
        )
        return issues

    for header, expected_values in REQUIRED_HEADERS.items():
        value = resp.headers.get(header)
        if value is None:
            issues.append(
                {
                    "type": "HEADER_MISSING",
                    "severity": "HIGH",
                    "header": header
                }
            )
        elif not any(v in value for v in expected_values):
            issues.append(
                {
                    "type": "HEADER_WEAK",
                    "severity": "MEDIUM",
                    "header": header,
                    "value": value
                }
            )

    return issues
