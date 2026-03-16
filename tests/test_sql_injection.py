"""Tests for the SQL Injection analyzer."""
from security_scanner.analyzers.sql_injection import SQLInjectionAnalyzer
from security_scanner.models.finding import VulnerabilityType 


class TestSQLInjectionAnalyzer:

    def test_detects_fstring_sqli(self):
        """Should detect f-string SQL injection with user input."""
        source = '''
user_id = request.args.get("id")
query = f"SELECT * FROM users WHERE id = {user_id}"
'''
        analyzer = SQLInjectionAnalyzer("/user", "test.py", source)
        findings = analyzer.analyze()
        assert len(findings) >= 1
        assert findings[0].vuln_type == VulnerabilityType.SQL_INJECTION

    def test_detects_concat_sqli(self):
        """Should detect string concatenation SQL injection."""
        source = '''
username = request.form.get("username")
query = "SELECT * FROM users WHERE name = '" + username + "'"
'''
        analyzer = SQLInjectionAnalyzer("/login", "test.py", source)
        findings = analyzer.analyze()
        assert len(findings) >= 1
        assert findings[0].vuln_type == VulnerabilityType.SQL_INJECTION

    def test_ignores_parameterized_query(self):
        """Should NOT flag parameterized queries."""
        source = '''
user_id = request.args.get("id")
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
'''
        analyzer = SQLInjectionAnalyzer("/user", "test.py", source)
        findings = analyzer.analyze()
        assert len(findings) == 0

    def test_ignores_no_user_input(self):
        """Should NOT flag f-strings without user input variables."""
        source = '''
import datetime
date = datetime.datetime.now().strftime("%Y-%m-%d")
query = f"SELECT * FROM logs WHERE date = '{date}'"
'''
        analyzer = SQLInjectionAnalyzer("/logs", "test.py", source)
        findings = analyzer.analyze()
        assert len(findings) == 0

    def test_ignores_plain_sql(self):
        """Should NOT flag plain SQL without interpolation."""
        source = '''
query = "SELECT * FROM users WHERE active = 1"
cursor.execute(query)
'''
        analyzer = SQLInjectionAnalyzer("/users", "test.py", source)
        findings = analyzer.analyze()
        assert len(findings) == 0

    def test_finding_has_correct_fields(self):
        """Finding should have all required fields filled."""
        source = '''
user_id = request.args.get("id")
query = f"SELECT * FROM users WHERE id = {user_id}"
'''
        analyzer = SQLInjectionAnalyzer("/user", "test.py", source)
        findings = analyzer.analyze()
        assert len(findings) >= 1
        f = findings[0]
        assert f.severity.value == "CRITICAL"
        assert f.endpoint == "/user"
        assert f.explanation != ""
        assert f.fix_recommendation != ""
        assert f.reference != ""
