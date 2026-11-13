"""Tests for newly added OWASP Top 10 analyzers."""
from security_scanner.analyzers.command_injection import CommandInjectionAnalyzer
from security_scanner.analyzers.path_traversal import PathTraversalAnalyzer
from security_scanner.analyzers.ssrf import SSRFAnalyzer
from security_scanner.analyzers.weak_crypto import WeakCryptoAnalyzer
from security_scanner.analyzers.open_redirect import OpenRedirectAnalyzer
from security_scanner.models.finding import VulnerabilityType


def test_command_injection_detected():
    code = '''
cmd = request.args.get("ip")
os.system(f"ping -c 1 {cmd}")
'''
    analyzer = CommandInjectionAnalyzer("/ping", "test.py", code)
    findings = analyzer.analyze()
    assert len(findings) == 1
    assert findings[0].vuln_type == VulnerabilityType.COMMAND_INJECTION


def test_command_injection_safe_not_flagged():
    code = '''
subprocess.run(["ls", "-la"], shell=False)
'''
    analyzer = CommandInjectionAnalyzer("/list", "test.py", code)
    findings = analyzer.analyze()
    assert len(findings) == 0


def test_path_traversal_detected():
    code = '''
file_name = request.args.get("file")
with open(f"uploads/{file_name}", "r") as f:
    content = f.read()
'''
    analyzer = PathTraversalAnalyzer("/download", "test.py", code)
    findings = analyzer.analyze()
    assert len(findings) == 1
    assert findings[0].vuln_type == VulnerabilityType.PATH_TRAVERSAL


def test_ssrf_detected():
    code = '''
webhook_url = request.args.get("url")
requests.get(webhook_url)
'''
    analyzer = SSRFAnalyzer("/webhook", "test.py", code)
    findings = analyzer.analyze()
    assert len(findings) == 1
    assert findings[0].vuln_type == VulnerabilityType.SSRF


def test_weak_crypto_detected():
    code = '''
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()
'''
    analyzer = WeakCryptoAnalyzer("/hash", "test.py", code)
    findings = analyzer.analyze()
    assert len(findings) == 1
    assert findings[0].vuln_type == VulnerabilityType.WEAK_CRYPTO


def test_open_redirect_detected():
    code = '''
next_url = request.args.get("next")
return redirect(next_url)
'''
    analyzer = OpenRedirectAnalyzer("/login", "test.py", code)
    findings = analyzer.analyze()
    assert len(findings) == 1
    assert findings[0].vuln_type == VulnerabilityType.OPEN_REDIRECT


def test_ssrf_dict_get_not_flagged():
    """Ensure regular dict.get() calls with user-controlled keys do NOT trigger SSRF."""
    code = '''
key = request.args.get("key")
item = lookup_dict.get(key)
'''
    analyzer = SSRFAnalyzer("/lookup", "test.py", code)
    findings = analyzer.analyze()
    assert len(findings) == 0


def test_ssrf_url_concat_detected():
    """Ensure URL concatenation passed to requests.get triggers SSRF."""
    code = '''
target = request.args.get("target")
requests.get("https://" + target)
'''
    analyzer = SSRFAnalyzer("/proxy", "test.py", code)
    findings = analyzer.analyze()
    assert len(findings) == 1
    assert findings[0].vuln_type == VulnerabilityType.SSRF


def test_path_traversal_os_path_join_detected():
    """Ensure os.path.join with user input in open() triggers PATH_TRAVERSAL."""
    code = '''
filename = request.args.get("file")
with open(os.path.join("/var/data", filename)) as f:
    data = f.read()
'''
    analyzer = PathTraversalAnalyzer("/read", "test.py", code)
    findings = analyzer.analyze()
    assert len(findings) == 1
    assert findings[0].vuln_type == VulnerabilityType.PATH_TRAVERSAL


def test_path_traversal_secure_filename_not_flagged():
    """Ensure secure_filename() sanitization is recognized as safe."""
    code = '''
from werkzeug.utils import secure_filename
filename = request.args.get("file")
safe_name = secure_filename(filename)
with open(os.path.join("/var/data", safe_name)) as f:
    data = f.read()
'''
    analyzer = PathTraversalAnalyzer("/read", "test.py", code)
    findings = analyzer.analyze()
    assert len(findings) == 0


def test_command_injection_indirect_variable_detected():
    """Ensure building command strings in a variable before execution is detected."""
    code = '''
host = request.args.get("host")
command = f"ping -c 1 {host}"
os.system(command)
'''
    analyzer = CommandInjectionAnalyzer("/ping", "test.py", code)
    findings = analyzer.analyze()
    assert len(findings) == 1
    assert findings[0].vuln_type == VulnerabilityType.COMMAND_INJECTION


def test_command_injection_percent_format_detected():
    """Ensure % formatting in shell command is detected."""
    code = '''
host = request.args.get("host")
os.system("ping -c 1 %s" % host)
'''
    analyzer = CommandInjectionAnalyzer("/ping", "test.py", code)
    findings = analyzer.analyze()
    assert len(findings) == 1
    assert findings[0].vuln_type == VulnerabilityType.COMMAND_INJECTION


def test_weak_crypto_hashlib_new_detected():
    """Ensure hashlib.new('md5') is detected."""
    code = '''
import hashlib
h = hashlib.new("md5")
'''
    analyzer = WeakCryptoAnalyzer("/hash", "test.py", code)
    findings = analyzer.analyze()
    assert len(findings) == 1
    assert findings[0].vuln_type == VulnerabilityType.WEAK_CRYPTO


def test_command_injection_direct_call_detected():
    """Ensure direct request.args.get() passed to os.system is detected."""
    code = '''
os.system(request.args.get("cmd"))
'''
    analyzer = CommandInjectionAnalyzer("/run", "test.py", code)
    findings = analyzer.analyze()
    assert len(findings) == 1
    assert findings[0].vuln_type == VulnerabilityType.COMMAND_INJECTION


def test_command_injection_method_transformation_detected():
    """Ensure method chaining (e.g. .strip()) retains taint."""
    code = '''
user_input = request.args.get("ip")
cleaned = user_input.strip()
os.system(cleaned)
'''
    analyzer = CommandInjectionAnalyzer("/ping", "test.py", code)
    findings = analyzer.analyze()
    assert len(findings) == 1
    assert findings[0].vuln_type == VulnerabilityType.COMMAND_INJECTION


def test_command_injection_dict_wrapping_detected():
    """Ensure tainted variables inside dictionaries propagate taint."""
    code = '''
user_input = request.args.get("ip")
data = {"target": user_input}
cmd = data["target"]
os.system(cmd)
'''
    analyzer = CommandInjectionAnalyzer("/ping", "test.py", code)
    findings = analyzer.analyze()
    assert len(findings) == 1
    assert findings[0].vuln_type == VulnerabilityType.COMMAND_INJECTION


def test_path_traversal_direct_call_detected():
    """Ensure direct open(request.args.get('file')) is detected."""
    code = '''
with open(request.args.get("file")) as f:
    data = f.read()
'''
    analyzer = PathTraversalAnalyzer("/read", "test.py", code)
    findings = analyzer.analyze()
    assert len(findings) == 1
    assert findings[0].vuln_type == VulnerabilityType.PATH_TRAVERSAL


def test_path_traversal_stripped_var_detected():
    """Ensure stripped filename retains path traversal taint."""
    code = '''
user_input = request.args.get("file")
filename = user_input.strip()
with open(filename) as f:
    data = f.read()
'''
    analyzer = PathTraversalAnalyzer("/read", "test.py", code)
    findings = analyzer.analyze()
    assert len(findings) == 1
    assert findings[0].vuln_type == VulnerabilityType.PATH_TRAVERSAL


def test_ssrf_intermediate_variable_detected():
    """Ensure intermediate f-string or concat URL assignment triggers SSRF."""
    code = '''
target = request.args.get("target")
url = f"https://{target}"
requests.get(url)
'''
    analyzer = SSRFAnalyzer("/proxy", "test.py", code)
    findings = analyzer.analyze()
    assert len(findings) == 1
    assert findings[0].vuln_type == VulnerabilityType.SSRF


def test_ssrf_direct_call_detected():
    """Ensure direct requests.get(request.args.get('url')) triggers SSRF."""
    code = '''
requests.get(request.args.get("url"))
'''
    analyzer = SSRFAnalyzer("/proxy", "test.py", code)
    findings = analyzer.analyze()
    assert len(findings) == 1
    assert findings[0].vuln_type == VulnerabilityType.SSRF


def test_open_redirect_subscript_detected():
    """Ensure redirect(request.args['next']) triggers OPEN_REDIRECT."""
    code = '''
return redirect(request.args["next"])
'''
    analyzer = OpenRedirectAnalyzer("/redirect", "test.py", code)
    findings = analyzer.analyze()
    assert len(findings) == 1
    assert findings[0].vuln_type == VulnerabilityType.OPEN_REDIRECT


