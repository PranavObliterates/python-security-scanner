import json
import os
from urllib.parse import urljoin

import requests


class DynamicTester:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()

    def _load_payloads(self, filename: str):
        path = os.path.join(
            os.path.dirname(__file__),
            "payloads",
            filename
        )
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _probe(self, endpoint: str, payload: str):
        url = urljoin(self.base_url + "/", endpoint.lstrip("/"))
        try:
            resp = self.session.get(
                url,
                params={"id": payload, "q": payload, "name": payload},
                timeout=5
            )
        except Exception as exc:
            return {
                "endpoint": endpoint,
                "payload": payload,
                "error": str(exc),
                "vulnerable": False
            }
        text = resp.text.lower()
        reflected = payload.lower() in text
        server_error = resp.status_code >= 500
        return {
            "endpoint": endpoint,
            "payload": payload,
            "status_code": resp.status_code,
            "vulnerable": reflected or server_error
        }

    def run_sql_tests(self, endpoints=None):
        if endpoints is None:
            endpoints = ["/user", "/search", "/profile"]
        payloads = self._load_payloads("sql_payloads.json")
        results = []
        for ep in endpoints:
            for payload in payloads:
                results.append(self._probe(ep, payload))
        return [r for r in results if r.get("vulnerable")]

    def run_xss_tests(self, endpoints=None):
        if endpoints is None:
            endpoints = ["/search", "/profile"]
        payloads = self._load_payloads("xss_payloads.json")
        results = []
        for ep in endpoints:
            for payload in payloads:
                results.append(self._probe(ep, payload))
        return [r for r in results if r.get("vulnerable")]
