"""
Vulnerable Django App — single-file Django application with known security holes.

This app is used for testing the security scanner against Django.
It contains: SQL injection, XSS, debug mode, weak secret, no CSRF middleware.

Usage:
    from examples.vulnerable_django_app import application
    from security_scanner import scan_app
    result = scan_app(application, framework="django")
"""
import os
import sqlite3
import django
from django.conf import settings
from django.http import HttpResponse
from django.urls import path

# ─── Django Settings (inline for single-file app) ──────────────────────────────
if not settings.configured:
    settings.configure(
        DEBUG=True,                     # VULN: Debug mode
        SECRET_KEY="password123",       # VULN: Weak secret
        ROOT_URLCONF=__name__,
        ALLOWED_HOSTS=["*"],
        MIDDLEWARE=[                    # VULN: No CsrfViewMiddleware, No SecurityMiddleware
            "django.middleware.common.CommonMiddleware",
        ],
        DATABASES={
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": ":memory:",
            }
        },
    )
    django.setup()


# ─── Views ──────────────────────────────────────────────────────────────────────

def index(request):
    return HttpResponse("<h1>Home — Vulnerable Django App</h1>")


def get_user(request):
    """VULNERABLE: SQL injection via f-string."""
    user_id = request.GET.get("id", "1")
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER, name TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'alice')")
    conn.execute("INSERT INTO users VALUES (2, 'bob')")
    query = f"SELECT * FROM users WHERE id = {user_id}"
    try:
        result = conn.execute(query).fetchall()
    except Exception as e:
        return HttpResponse(str(e), status=500)
    conn.close()
    return HttpResponse(str(result))


def search(request):
    """VULNERABLE: Reflected XSS."""
    term = request.GET.get("q", "")
    return HttpResponse(f"<h1>Results for: {term}</h1>")


def profile(request):
    """VULNERABLE: XSS via direct HTML."""
    name = request.GET.get("name", "User")
    return HttpResponse(f"<h1>Hello {name}!</h1>")


def admin_panel(request):
    """VULNERABLE: Hardcoded secret."""
    api_key = "sk-live-abcdef123456"
    return HttpResponse(f"Admin API key: {api_key}")


# ─── URL Patterns ───────────────────────────────────────────────────────────────

urlpatterns = [
    path("", index, name="index"),
    path("user/", get_user, name="get_user"),
    path("search/", search, name="search"),
    path("profile/", profile, name="profile"),
    path("admin/", admin_panel, name="admin_panel"),
]


# ─── WSGI Application ──────────────────────────────────────────────────────────

from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
