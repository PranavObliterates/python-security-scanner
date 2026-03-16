"""Discovers all routes registered in a web application."""
import inspect
from dataclasses import dataclass
from typing import List, Callable, Optional


@dataclass
class RouteInfo:
    """Information about a single route/endpoint."""
    path: str
    methods: List[str]
    view_function: Callable
    view_function_name: str
    file_path: Optional[str] = None
    source_code: Optional[str] = None


def discover_flask_routes(app) -> List[RouteInfo]:
    """Extract all routes from a Flask application.

    Uses Flask's url_map to iterate over all registered rules,
    retrieves the view function for each, and extracts its source code.
    """
    routes = []
    for rule in app.url_map.iter_rules():
        # Skip static file serving endpoint
        if rule.endpoint == "static":
            continue

        view_func = app.view_functions.get(rule.endpoint)
        if view_func is None:
            continue

        # Get source code and file info
        try:
            source = inspect.getsource(view_func)
            file_path = inspect.getfile(view_func)
        except (OSError, TypeError):
            source = None
            file_path = None

        routes.append(RouteInfo(
            path=rule.rule,
            methods=sorted(rule.methods - {"HEAD", "OPTIONS"}),
            view_function=view_func,
            view_function_name=view_func.__name__,
            file_path=file_path,
            source_code=source,
        ))

    return routes


def discover_django_routes(urlconf=None) -> List[RouteInfo]:
    """Extract all routes from a Django application.

    Walks Django's URL resolver tree to find all URL patterns,
    retrieves the view function for each, and extracts its source code.

    Args:
        urlconf: Optional Django URL configuration module. If None,
                 uses the ROOT_URLCONF from Django settings.
    """
    from django.urls import URLPattern, URLResolver, get_resolver

    routes = []
    resolver = get_resolver(urlconf)

    def _walk_patterns(patterns, prefix=""):
        for pattern in patterns:
            if isinstance(pattern, URLResolver):
                new_prefix = prefix + str(pattern.pattern)
                _walk_patterns(pattern.url_patterns, new_prefix)
            elif isinstance(pattern, URLPattern):
                path = "/" + prefix + str(pattern.pattern)
                # Normalize path: remove trailing $, clean double slashes
                path = path.replace("//", "/").rstrip("$")
                if not path:
                    path = "/"

                view_func = pattern.callback

                # Unwrap class-based views
                if hasattr(view_func, "view_class"):
                    actual_func = view_func.view_class
                else:
                    actual_func = view_func

                # Get source code and file info
                try:
                    source = inspect.getsource(actual_func)
                    file_path = inspect.getfile(actual_func)
                except (OSError, TypeError):
                    source = None
                    file_path = None

                # Determine HTTP methods
                if hasattr(view_func, "view_class"):
                    methods = [m.upper() for m in view_func.view_class.http_method_names
                               if hasattr(view_func.view_class, m)]
                else:
                    methods = ["GET", "POST"]

                func_name = getattr(actual_func, "__name__", str(actual_func))

                routes.append(RouteInfo(
                    path=path,
                    methods=sorted(set(methods) - {"HEAD", "OPTIONS"}),
                    view_function=view_func,
                    view_function_name=func_name,
                    file_path=file_path,
                    source_code=source,
                ))

    _walk_patterns(resolver.url_patterns)
    return routes

