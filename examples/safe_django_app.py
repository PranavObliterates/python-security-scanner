"""
Safe Django App — single-file Django application following security best practices.

This app is used for testing the security scanner against Django.
It should produce zero code-level vulnerability findings.

Usage:
    from examples.safe_django_app import application
    from security_scanner import scan_app
    result = scan_app(application, framework="django")
"""
import os
import sqlite3
import django
from django.conf import settings
from django.http import HttpResponse
from django.urls import path
from django.utils.html import escape

# ─── Django Settings (inline for single-file app) ──────────────────────────────
if not settings.configured:
    settings.configure(
        DEBUG=False,                        # SAFE: Debug off
        SECRET_KEY=os.environ.get(         # SAFE: From env (with long fallback)
            "DJANGO_SECRET_KEY",
            "a-very-long-random-secret-key-for-testing-only-do-not-use-in-prod-1234567890"
        ),
        ROOT_URLCONF=__name__,
        ALLOWED_HOSTS=["*"],
        MIDDLEWARE=[                        # SAFE: Both security middlewares present
            "django.middleware.security.SecurityMiddleware",
            "django.middleware.common.CommonMiddleware",
            "django.middleware.csrf.CsrfViewMiddleware",
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
    return HttpResponse("<h1>Home — Safe Django App</h1>")


def get_user(request):
    """SAFE: Parameterized query."""
    user_id = request.GET.get("id", "1")
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER, name TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'alice')")
    result = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchall()
    conn.close()
    return HttpResponse(str(result))


def search(request):
    """SAFE: Escaped output."""
    term = request.GET.get("q", "")
    return HttpResponse(f"<h1>Results for: {escape(term)}</h1>")


# ─── URL Patterns ───────────────────────────────────────────────────────────────

urlpatterns = [
    path("", index, name="index"),
    path("user/", get_user, name="get_user"),
    path("search/", search, name="search"),
]


# ─── WSGI Application ──────────────────────────────────────────────────────────

from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
