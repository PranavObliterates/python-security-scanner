from django.http import HttpResponse
from django.db import connection
from django.template import Template, Context
import base64
import pickle

def index(request):
    return HttpResponse("<h1>Vuln-Django Home</h1>")

def get_user(request):
    """VULNERABLE: Direct SQL Injection in raw query."""
    user_id = request.GET.get('id', '1')
    
    with connection.cursor() as cursor:
        # Intentionally vulnerable string concatenation
        query = "SELECT id, username FROM auth_user WHERE id = " + user_id
        try:
            cursor.execute(query)
            row = cursor.fetchone()
        except Exception as e:
            return HttpResponse(str(e), status=500)
            
    if row:
        return HttpResponse(f"User: {row[1]}")
    return HttpResponse("User not found.")

def search(request):
    """VULNERABLE: Reflected XSS."""
    term = request.GET.get('q', '')
    # Intentionally reflecting user input without escaping
    return HttpResponse(f"<h1>Search results for: {term}</h1>")

def ssti_demo(request):
    tmpl = request.GET.get("tmpl", "Hello")
    template = Template(tmpl)
    context = Context({})
    return HttpResponse(template.render(context))

def pickle_demo(request):
    data = request.GET.get("data", "")
    if data:
        try:
            obj = pickle.loads(base64.b64decode(data))
            return HttpResponse(str(obj))
        except Exception as e:
            return HttpResponse(str(e), status=500)
    return HttpResponse("No object")
