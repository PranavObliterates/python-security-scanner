"""
Script to run the security scanner against the complete test suite.
Calculates 'Pass/Fail' for each app and prints a summary.
"""
import os
import sys
import importlib.util
from security_scanner import scan_app

SUITE_DIR = os.path.join("examples", "test_suite")

def load_app_from_file(filepath):
    """Dynamically load the 'app' object from a python file."""
    # Convert to absolute path for reliability
    abs_path = os.path.abspath(filepath)
    spec = importlib.util.spec_from_file_location("test_app", abs_path)
    if spec is None:
        raise ImportError(f"Could not load spec for {filepath}")
    
    module = importlib.util.module_from_spec(spec)
    if spec.loader is None:
        raise ImportError(f"No loader found for {filepath}")
        
    spec.loader.exec_module(module)
    return getattr(module, "app", None)

def run_suite():
    categories = ["single_vulns", "multi_vulns", "safe_apps", "edge_cases"]
    total_apps = 0
    passed_apps = 0
    
    print("\n" + "="*70)
    print("  SECURITY SCANNER TEST SUITE RUN")
    print("="*70 + "\n")

    for cat in categories:
        cat_dir = os.path.join(SUITE_DIR, cat)
        print(f"--- Category: {cat.upper()} ---")
        
        files = [f for f in os.listdir(cat_dir) if f.endswith(".py")]
        for filename in files:
            filepath = os.path.join(cat_dir, filename)
            try:
                app = load_app_from_file(filepath)
            except Exception as e:
                print(f"  [!] Failed to load {filename}: {e}")
                continue
            
            if not app:
                print(f"  [!] Skipped {filename}: No 'app' object found.")
                continue
            
            total_apps += 1
            result = scan_app(app, dynamic=False)
            
            # Count specific categories of findings
            code_findings = [f for f in result.findings if f.vuln_type.value in ("SQL_INJECTION", "XSS")]
            secret_findings = [f for f in result.findings if f.vuln_type.value == "HARDCODED_SECRET"]
            config_findings = [f for f in result.findings if f.vuln_type.value in ("CSRF_MISSING", "DEBUG_MODE")]
            
            # Intelligent Success Criteria
            success = False
            if filename == "vuln_sqli.py":
                success = any(f.vuln_type.value == "SQL_INJECTION" for f in result.findings)
            elif filename == "vuln_xss.py":
                success = any(f.vuln_type.value == "XSS" for f in result.findings)
            elif filename == "vuln_secret.py":
                success = any(f.vuln_type.value == "HARDCODED_SECRET" for f in result.findings)
            elif filename == "vuln_debug.py":
                success = any(f.vuln_type.value == "DEBUG_MODE" for f in result.findings)
            elif filename == "vuln_csrf.py":
                success = any(f.vuln_type.value == "CSRF_MISSING" for f in result.findings)
            elif cat == "multi_vulns":
                success = (len(code_findings) + len(secret_findings) > 1)
            elif cat == "safe_apps":
                success = (len(code_findings) == 0 and len(secret_findings) == 0)
            elif cat == "edge_cases":
                # Edge cases test code analyzers only — config warnings are OK
                success = (len(code_findings) == 0 and len(secret_findings) == 0)
                
            status = "[PASS]" if success else "[FAIL]"
            if success: passed_apps += 1
            
            total = len(result.findings)
            print(f"  {status} {filename:<25} Total: {total:<2} (Code:{len(code_findings)} Sec:{len(secret_findings)} Cfg:{len(config_findings)})")
        print()

    print("="*70)
    print(f"  FINAL RESULT: {passed_apps}/{total_apps} apps passed correctly")
    print(f"  SUITE SCORE:  {(passed_apps/total_apps)*100:.1f}%")
    print("="*70 + "\n")

if __name__ == "__main__":
    run_suite()
