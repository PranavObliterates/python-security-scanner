"""Rate-limited, private-network-only web crawler and passive DAST scanner."""
import ipaddress
import json
import logging
import os
import socket
import time
from collections import deque
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

import requests

from ..models.finding import Finding, Severity, VulnerabilityType
from ..models.scan_result import ScanResult
from .response_analyzer import (
    check_cookie_security,
    check_response_hardening,
    check_security_headers,
)

MAX_BODY_BYTES = 1_000_000
MAX_REDIRECTS = 4
CANARY = "pysecure-canary-9f31"
logger = logging.getLogger(__name__)


class ScopeError(ValueError):
    """Raised when a URL is outside the scanner's permitted private scope."""


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: List[str] = []
        self.forms: List[Dict[str, object]] = []
        self._form: Optional[Dict[str, object]] = None

    def handle_starttag(self, tag: str, attrs: list) -> None:
        attributes = dict(attrs)
        if tag.lower() == "a" and attributes.get("href"):
            self.links.append(attributes["href"])
        elif tag.lower() == "form":
            self._form = {
                "action": attributes.get("action", ""),
                "method": attributes.get("method", "get").lower(),
                "fields": [],
            }
        elif tag.lower() in ("input", "textarea", "select") and self._form is not None:
            name = attributes.get("name")
            if name:
                self._form["fields"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


class _HiddenInputParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.values: Dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag.lower() != "input":
            return
        attributes = dict(attrs)
        if attributes.get("type", "").lower() == "hidden" and attributes.get("name"):
            self.values[attributes["name"]] = attributes.get("value", "")


def _validate_private_url(url: str) -> Tuple[str, str, int]:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ScopeError("Only absolute HTTP(S) URLs are accepted.")
    if parsed.username or parsed.password:
        raise ScopeError("Credentials in target URLs are not permitted.")
    host = parsed.hostname.rstrip(".").lower()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        addresses = {ipaddress.ip_address(host)}
    except ValueError:
        if host != "localhost":
            raise ScopeError("Use localhost or a literal private IP address; DNS hostnames are not accepted.")
        try:
            addresses = {
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            }
        except OSError as exc:
            raise ScopeError(f"Could not resolve target host: {exc}") from exc
    if not addresses or any(
        not (address.is_loopback or address.is_private)
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        for address in addresses
    ):
        raise ScopeError("Remote scanning is restricted to localhost/private IP targets.")
    return parsed.scheme, host, port


def _origin(url: str) -> Tuple[str, str, int]:
    return _validate_private_url(url)


def _safe_join(base: str, candidate: str) -> Optional[str]:
    joined = urljoin(base, candidate)
    try:
        if _origin(joined) != _origin(base):
            return None
    except ScopeError:
        return None
    parsed = urlparse(joined)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))


def _read_auth_config(path: Optional[str]) -> dict:
    if not path:
        return {}
    with open(path, encoding="utf-8") as handle:
        config = json.load(handle)
    if not isinstance(config, dict):
        raise ValueError("Authentication configuration must be a JSON object.")
    return config


def _resolve_env(value):
    if isinstance(value, dict) and set(value) == {"env"}:
        env_name = value["env"]
        if not isinstance(env_name, str) or not os.environ.get(env_name):
            raise ValueError(f"Required authentication environment variable is unset: {env_name}")
        return os.environ[env_name]
    return value


def _auth_session(
    base_url: str, config: dict, timeout: float, delay: float
) -> Optional[requests.Session]:
    login = config.get("login")
    if not login:
        return None
    if not isinstance(login, dict):
        raise ValueError("Authentication 'login' must be an object.")
    method = str(login.get("method", "POST")).upper()
    if method not in ("POST", "PUT"):
        raise ValueError("Authentication login method must be POST or PUT.")
    login_url = _safe_join(base_url, str(login.get("path", "")))
    if not login_url:
        raise ValueError("Authentication path must remain within the target origin.")
    session = requests.Session()
    session.trust_env = False
    fields = login.get("form", {})
    if not isinstance(fields, dict):
        raise ValueError("Authentication 'form' must be an object.")
    values = {key: _resolve_env(value) for key, value in fields.items()}
    last_request = [0.0]

    def wait_for_slot() -> None:
        remaining = delay - (time.monotonic() - last_request[0])
        if remaining > 0:
            time.sleep(remaining)
        last_request[0] = time.monotonic()

    csrf = login.get("csrf")
    if csrf:
        if not isinstance(csrf, dict) or not csrf.get("path") or not csrf.get("field"):
            raise ValueError("Authentication csrf requires path and field values.")
        csrf_url = _safe_join(base_url, str(csrf["path"]))
        if not csrf_url:
            raise ValueError("Authentication CSRF path must remain within the target origin.")
        wait_for_slot()
        csrf_response = session.get(
            csrf_url, timeout=timeout, allow_redirects=False, stream=True
        )
        try:
            if csrf_response.status_code >= 400:
                raise ValueError(f"Authentication CSRF page returned HTTP {csrf_response.status_code}.")
            content = bytearray()
            for chunk in csrf_response.iter_content(16_384):
                content.extend(chunk)
                if len(content) > MAX_BODY_BYTES:
                    raise ValueError("Authentication CSRF page exceeded the 1 MB inspection limit.")
        finally:
            csrf_response.close()
        parser = _HiddenInputParser()
        parser.feed(bytes(content).decode("utf-8", errors="replace"))
        csrf_value = parser.values.get(str(csrf["field"]))
        if csrf_value is None:
            raise ValueError(f"Authentication CSRF field was not found: {csrf['field']}")
        values[str(csrf["field"])] = csrf_value
    wait_for_slot()
    response = session.request(
        method,
        login_url,
        data=values,
        timeout=timeout,
        allow_redirects=False,
        stream=True,
    )
    try:
        if response.status_code >= 400:
            raise ValueError(f"Authentication request returned HTTP {response.status_code}.")
        total = 0
        for chunk in response.iter_content(16_384):
            total += len(chunk)
            if total > MAX_BODY_BYTES:
                raise ValueError("Authentication response exceeded the 1 MB inspection limit.")
    finally:
        response.close()
    return session


def _remote_finding(
    vuln_type: VulnerabilityType,
    severity: Severity,
    url: str,
    rule_id: str,
    cwe: str,
    explanation: str,
    snippet: str,
    recommendation: str,
    status: str = "confirmed",
) -> Finding:
    return Finding(
        vuln_type=vuln_type,
        severity=severity,
        endpoint=url,
        file="HTTP response",
        line=0,
        code_snippet=snippet[:240],
        explanation=explanation,
        fix_recommendation=recommendation,
        source="DAST",
        status=status,
        rule_id=rule_id,
        cwe=cwe,
    )


def _request_limited(
    session: requests.Session,
    url: str,
    timeout: float,
    delay: float,
    last_request: List[float],
    request_limit: int = MAX_REDIRECTS + 1,
) -> Tuple[Optional[requests.Response], Optional[str], int]:
    current_url = url
    requests_used = 0
    for _ in range(min(MAX_REDIRECTS + 1, request_limit)):
        current = time.monotonic()
        wait = delay - (current - last_request[0])
        if wait > 0:
            time.sleep(wait)
        last_request[0] = time.monotonic()
        _validate_private_url(current_url)
        parsed_url = urlparse(current_url)
        log_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        request_started = time.monotonic()
        logger.debug("Requesting %s", log_url)
        response = session.get(
            current_url,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
        )
        requests_used += 1
        logger.debug(
            "Received HTTP %d from %s in %.3fs",
            response.status_code,
            log_url,
            time.monotonic() - request_started,
        )
        if response.is_redirect:
            location = response.headers.get("Location")
            response.close()
            if not location:
                return None, "Redirect response did not include a Location header.", requests_used
            next_url = _safe_join(current_url, location)
            if not next_url:
                return None, "Redirect left the original target origin; it was blocked.", requests_used
            current_url = next_url
            continue
        chunks = []
        size = 0
        for chunk in response.iter_content(16_384):
            size += len(chunk)
            if size > MAX_BODY_BYTES:
                response.close()
                return None, "Response exceeded the configured 1 MB inspection limit.", requests_used
            chunks.append(chunk)
        response._content = b"".join(chunks)
        response._content_consumed = True
        logger.debug("Read %d response bytes from %s", size, log_url)
        return response, None, requests_used
    warning = "Request budget exhausted while following redirects." if request_limit <= requests_used else "Redirect limit exceeded."
    return None, warning, requests_used


def scan_remote_url(
    target_url: str,
    max_pages: int = 50,
    max_depth: int = 3,
    max_requests: int = 150,
    delay: float = 0.25,
    timeout: float = 5.0,
    active: bool = False,
    auth_config_path: Optional[str] = None,
    browser: bool = False,
) -> ScanResult:
    """Crawl and passively assess one explicitly provided private-network origin."""
    if not 1 <= max_pages <= 500:
        raise ValueError("max_pages must be between 1 and 500.")
    if not 0 <= max_depth <= 8:
        raise ValueError("max_depth must be between 0 and 8.")
    if not 1 <= max_requests <= 1000:
        raise ValueError("max_requests must be between 1 and 1000.")
    if not 0.1 <= delay <= 60:
        raise ValueError("delay must be between 0.1 and 60 seconds.")
    if not 0.1 <= timeout <= 30:
        raise ValueError("timeout must be between 0.1 and 30 seconds.")
    started = time.monotonic()
    origin = _origin(target_url)
    start = target_url if urlparse(target_url).path else target_url.rstrip("/") + "/"
    parsed_start = urlparse(start)
    root = urlunparse((parsed_start.scheme, parsed_start.netloc, parsed_start.path or "/", "", "", ""))
    auth_config = _read_auth_config(auth_config_path)
    login_config = auth_config.get("login", {})
    if login_config and not isinstance(login_config, dict):
        raise ValueError("Authentication 'login' must be an object.")
    if login_config and (1 + int(bool(login_config.get("csrf")))) > max_requests:
        raise ValueError("Request budget is too small for the configured authentication workflow.")
    anonymous = requests.Session()
    anonymous.trust_env = False
    authenticated = _auth_session(root, auth_config, timeout, delay)
    queue = deque([(root, 0)])
    visited: Set[str] = set()
    findings: List[Finding] = []
    forms: List[Dict[str, object]] = []
    last_request = [0.0]
    requests_made = int(authenticated is not None) + int(bool(auth_config.get("login", {}).get("csrf")))
    result = ScanResult(app_name=f"remote:{origin[1]}")
    logger.debug(
        "Starting private-target scan of %s (page limit=%d, depth=%d, request budget=%d)",
        root,
        max_pages,
        max_depth,
        max_requests,
    )
    queued = {root}

    while queue and len(visited) < max_pages and requests_made < max_requests:
        url, depth = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        response, warning, used = _request_limited(
            anonymous, url, timeout, delay, last_request, max_requests - requests_made
        )
        requests_made += used
        result.routes_tested += 1
        if warning:
            result.warnings.append(f"{url}: {warning}")
            continue
        if response is None:
            continue

        headers = dict(response.headers)
        findings.extend(check_security_headers(headers, url))
        findings.extend(check_cookie_security(headers, url))
        findings.extend(check_response_hardening(headers, url))
        body = response.content.decode(response.encoding or "utf-8", errors="replace")
        if response.status_code >= 500:
            findings.append(_remote_finding(
                VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                Severity.LOW,
                url,
                "PYSEC-DAST-002",
                "CWE-209",
                f"A benign GET returned HTTP {response.status_code}. Review error handling for information disclosure.",
                body[:240],
                "Return a generic error page and keep diagnostics in server-side logs.",
                status="potential",
            ))

        content_type = response.headers.get("Content-Type", "").lower()
        if "html" in content_type or "<html" in body[:512].lower():
            parser = _PageParser()
            parser.feed(body)
            for form in parser.forms:
                action = _safe_join(url, str(form.get("action", "")))
                forms.append({
                    "page": url,
                    "action": action or str(form.get("action", "")),
                    "method": form.get("method", "get"),
                    "fields": form.get("fields", []),
                })
            for link in parser.links:
                child = _safe_join(url, link)
                if (
                    child
                    and child not in visited
                    and child not in queued
                    and depth < max_depth
                    and len(queue) + len(visited) < max_pages
                ):
                    queue.append((child, depth + 1))
                    queued.add(child)

            if active and requests_made < max_requests:
                canary_url = url + ("&" if "?" in url else "?") + "pysecure_probe=" + CANARY
                canary_response, canary_warning, used = _request_limited(
                    anonymous, canary_url, timeout, delay, last_request,
                    max_requests - requests_made,
                )
                requests_made += used
                if canary_warning:
                    result.warnings.append(f"{canary_url}: {canary_warning}")
                elif canary_response is not None and CANARY in canary_response.text:
                    findings.append(_remote_finding(
                        VulnerabilityType.XSS,
                        Severity.MEDIUM,
                        url,
                        "PYSEC-DAST-001",
                        "CWE-79",
                        "A harmless unique canary was reflected in the HTML response. This is a potential output-encoding issue, not proof of executable script.",
                        f"Reflected canary {CANARY}",
                        "Contextually encode untrusted data and review the response context.",
                        status="potential",
                    ))

    result.routes_scanned = len(visited)
    result.forms_discovered = forms

    _run_authorization_checks(
        target_url, auth_config, authenticated, timeout, delay, last_request,
        max_requests - requests_made, findings, result,
    )

    if browser:
        _run_browser_crawl(
            root, timeout, delay, max_requests - requests_made, max_pages, max_depth, result,
            findings, authenticated,
        )

    result.findings = _deduplicate(findings)
    result.scan_duration_seconds = time.monotonic() - started
    logger.debug(
        "Remote scan completed: %d pages, %d forms, %d/%d requests, %d findings, %.3fs",
        result.routes_scanned,
        len(result.forms_discovered),
        requests_made,
        max_requests,
        len(result.findings),
        result.scan_duration_seconds,
    )
    return result


def _run_authorization_checks(
    base_url: str,
    config: dict,
    authenticated: Optional[requests.Session],
    timeout: float,
    delay: float,
    last_request: List[float],
    budget: int,
    findings: List[Finding],
    result: ScanResult,
) -> None:
    rules = config.get("authorization", [])
    if not rules:
        return
    if authenticated is None:
        result.warnings.append("Authorization rules configured but no authenticated login workflow was provided.")
        return
    anonymous = requests.Session()
    anonymous.trust_env = False
    for rule in rules:
        if budget <= 0:
            result.warnings.append("Authorization checks stopped at the request budget.")
            return
        path = str(rule.get("path", ""))
        url = _safe_join(base_url, path)
        if not url:
            result.warnings.append(f"Skipped out-of-scope authorization path: {path}")
            continue
        blocked = set(rule.get("unauthenticated_statuses", [401, 403, 302]))
        expected = set(rule.get("authenticated_statuses", [200]))
        anon_response, warning, used = _request_limited(
            anonymous, url, timeout, delay, last_request, budget
        )
        budget -= used
        if warning or anon_response is None:
            result.warnings.append(f"Authorization check failed for {path}: {warning}")
            continue
        auth_response, warning, used = _request_limited(
            authenticated, url, timeout, delay, last_request, budget
        )
        budget -= used
        if warning or auth_response is None:
            result.warnings.append(f"Authenticated authorization check failed for {path}: {warning}")
            continue
        result.routes_tested += 2
        if anon_response.status_code not in blocked and auth_response.status_code in expected:
            findings.append(_remote_finding(
                VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                Severity.HIGH,
                url,
                "PYSEC-AUTHZ-001",
                "CWE-862",
                "An explicitly protected route was accessible without authentication while the authenticated workflow succeeded.",
                f"anonymous={anon_response.status_code}, authenticated={auth_response.status_code}",
                "Enforce authorization on the server for this resource and verify the user's role before returning data.",
            ))


def _run_browser_crawl(
    root: str,
    timeout: float,
    delay: float,
    budget: int,
    page_limit: int,
    max_depth: int,
    result: ScanResult,
    findings: List[Finding],
    authenticated: Optional[requests.Session],
) -> None:
    if budget <= 0:
        result.warnings.append("Browser scan skipped: request budget exhausted.")
        return
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        result.warnings.append("Browser scan requested but Playwright is not installed; install pysecure-scanner[browser].")
        return
    visited = set()
    with sync_playwright() as playwright:
        browser = None
        try:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(service_workers="block")
            page = context.new_page()
            request_count = 0
            last_request = [0.0]
            context = page.context
            if authenticated is not None:
                cookies = []
                for cookie in authenticated.cookies:
                    browser_cookie = {
                        "name": cookie.name,
                        "value": cookie.value,
                        "domain": cookie.domain or urlparse(root).hostname,
                        "path": cookie.path or "/",
                        "secure": bool(cookie.secure),
                        "httpOnly": bool(cookie.has_nonstandard_attr("HttpOnly")),
                    }
                    if cookie.expires is not None:
                        browser_cookie["expires"] = cookie.expires
                    cookies.append(browser_cookie)
                if cookies:
                    context.add_cookies(cookies)

            page.add_init_script(
                """(() => {
                    const marker = 'pysecure-canary-9f31';
                    window.__pysecureSinkHits = [];
                    const record = (value, sink) => {
                        if (String(value).includes(marker)) window.__pysecureSinkHits.push(sink);
                    };
                    const descriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
                    if (descriptor && descriptor.set) {
                        Object.defineProperty(Element.prototype, 'innerHTML', {
                            get: descriptor.get,
                            set(value) { record(value, 'innerHTML'); return descriptor.set.call(this, value); }
                        });
                    }
                    const adjacent = Element.prototype.insertAdjacentHTML;
                    Element.prototype.insertAdjacentHTML = function(position, value) {
                        record(value, 'insertAdjacentHTML');
                        return adjacent.call(this, position, value);
                    };
                    const write = document.write.bind(document);
                    document.write = (...values) => { values.forEach(value => record(value, 'document.write')); return write(...values); };
                })();"""
            )

            def restrict_route(route) -> None:
                nonlocal request_count
                try:
                    if request_count >= budget:
                        route.abort()
                    elif _origin(route.request.url) == _origin(root):
                        request_count += 1
                        wait = delay - (time.monotonic() - last_request[0])
                        if wait > 0:
                            time.sleep(wait)
                        last_request[0] = time.monotonic()
                        route.continue_()
                    else:
                        route.abort()
                except ScopeError:
                    route.abort()

            page.route("**/*", restrict_route)
            root_probe = root + ("&" if "?" in root else "?") + "pysecure_browser=" + CANARY
            page.goto(root_probe, wait_until="domcontentloaded", timeout=int(timeout * 1000))
            visited.add(root)
            _collect_browser_forms(page, root, result)
            _collect_dom_sink_hits(page, root, findings)
            initial_links = page.locator("a[href]").evaluate_all(
                "(nodes) => nodes.map(node => node.href)"
            )
            queue = deque((link, 1) for link in initial_links) if max_depth > 0 else deque()
            while queue and len(visited) < page_limit and request_count < budget:
                link, depth = queue.popleft()
                safe_link = _safe_join(root, link)
                page_url = urlunparse((*urlparse(safe_link)[:4], "", "")) if safe_link else ""
                if not safe_link or page_url in visited:
                    continue
                try:
                    probe_url = safe_link + ("&" if "?" in safe_link else "?") + "pysecure_browser=" + CANARY
                    page.goto(probe_url, wait_until="domcontentloaded", timeout=int(timeout * 1000))
                    visited.add(page_url)
                    _collect_browser_forms(page, safe_link, result)
                    _collect_dom_sink_hits(page, safe_link, findings)
                    if depth < max_depth and len(queue) + len(visited) < page_limit:
                        child_links = page.locator("a[href]").evaluate_all(
                            "(nodes) => nodes.map(node => node.href)"
                        )
                        queue.extend((child, depth + 1) for child in child_links)
                except Exception as exc:
                    result.warnings.append(f"Browser navigation failed for {safe_link}: {exc}")
            result.browser_pages_tested = len(visited)
            if request_count >= budget:
                result.warnings.append("Browser request budget reached; additional browser requests were blocked.")
        except Exception as exc:
            result.warnings.append(f"Browser scan failed: {exc}")
        finally:
            if browser is not None:
                browser.close()


def _collect_browser_forms(page, page_url: str, result: ScanResult) -> None:
    discovered = page.locator("form").evaluate_all(
        """forms => forms.map(form => ({
            action: form.action,
            method: (form.method || 'get').toLowerCase(),
            fields: Array.from(form.querySelectorAll('input,textarea,select'))
                .map(field => field.name).filter(Boolean)
        }))"""
    )
    existing = {
        (form.get("page"), form.get("action"), form.get("method"), tuple(form.get("fields", [])))
        for form in result.forms_discovered
    }
    for form in discovered:
        key = (page_url, form["action"], form["method"], tuple(form["fields"]))
        if key not in existing:
            result.forms_discovered.append({"page": page_url, **form})
            existing.add(key)


def _collect_dom_sink_hits(page, page_url: str, findings: List[Finding]) -> None:
    sinks = page.evaluate("window.__pysecureSinkHits || []")
    for sink in sinks:
        findings.append(_remote_finding(
            VulnerabilityType.XSS,
            Severity.MEDIUM,
            page_url,
            "PYSEC-DAST-003",
            "CWE-79",
            "The browser observed a query canary passed into a DOM HTML sink. This is a potential DOM XSS issue and was not tested with executable markup.",
            f"Canary reached {sink}",
            "Avoid HTML parsing sinks for untrusted data; use textContent and context-appropriate output encoding.",
            status="potential",
        ))


def _deduplicate(findings: List[Finding]) -> List[Finding]:
    seen = set()
    unique = []
    for finding in findings:
        key = (finding.rule_id, finding.endpoint, finding.code_snippet)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique
