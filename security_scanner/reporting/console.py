"""Console (terminal) report output — sorted by severity, concise but detailed."""
import sys
from ..models.scan_result import ScanResult
from ..models.finding import Severity

# Severity sort order (most critical first)
SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "\033[91m",  # Red
    Severity.HIGH: "\033[93m",      # Yellow
    Severity.MEDIUM: "\033[94m",    # Blue
    Severity.LOW: "\033[96m",       # Cyan
    Severity.INFO: "\033[97m",      # White
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

SEVERITY_ICONS = {
    "CRITICAL": "!!",
    "HIGH": " !",
    "MEDIUM": " ~",
    "LOW": " .",
    "INFO": " i",
}


def _safe_print(text: str) -> None:
    """Print text safely, handling encoding errors on Windows."""
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", errors="replace").decode("ascii"))


def print_report(result: ScanResult) -> None:
    """Print a sorted, concise but detailed security report to the console."""
    line = "=" * 62

    _safe_print(f"\n{BOLD}  SECURITY SCAN REPORT  --  {result.app_name}{RESET}")
    _safe_print(line)
    _safe_print(f"  Routes: {result.routes_scanned}   |   "
                f"Issues: {len(result.findings)}   |   "
                f"Time: {result.scan_duration_seconds:.3f}s")
    _safe_print(line)

    if not result.findings:
        _safe_print(f"\n  {BOLD}[OK]{RESET} No security issues found! Great job.")
        _safe_print(line)
        return

    # Sort findings: severity first, then by source (SAST before DAST), then endpoint
    sorted_findings = sorted(
        result.findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 99),
            0 if f.source == "SAST" else 1,
            f.endpoint,
        ),
    )

    # Group and print by severity
    current_severity = None
    idx = 0

    for finding in sorted_findings:
        idx += 1
        color = SEVERITY_COLORS.get(finding.severity, "")
        icon = SEVERITY_ICONS.get(finding.severity.value, " ?")
        source_tag = f"[{finding.source}]" if finding.source else ""

        # Print severity group header when severity changes
        if finding.severity != current_severity:
            current_severity = finding.severity
            count = sum(1 for f in sorted_findings if f.severity == current_severity)
            _safe_print(f"\n  {color}{BOLD}--- {current_severity.value} ({count}) ---{RESET}")

        # Concise single-line header
        _safe_print(
            f"\n  [{icon}] {color}{finding.vuln_type.value}{RESET}  "
            f"{DIM}{source_tag}{RESET}"
        )

        # Location (concise — just basename of file)
        file_short = finding.file.split("\\")[-1].split("/")[-1]
        if finding.line > 0:
            _safe_print(f"      at {finding.endpoint} (line {finding.line})  ->  {file_short}")
        else:
            _safe_print(f"      at {finding.endpoint}  ->  {file_short}")

        # Code snippet (truncated if too long)
        snippet = finding.code_snippet
        if len(snippet) > 80:
            snippet = snippet[:77] + "..."
        _safe_print(f"      code: {snippet}")

        # Why (concise — first sentence only for display)
        why = finding.explanation
        if len(why) > 120:
            why = why[:117] + "..."
        _safe_print(f"      why:  {why}")

        # Fix (single line)
        fix = finding.fix_recommendation
        if len(fix) > 100:
            fix = fix[:97] + "..."
        _safe_print(f"      fix:  {fix}")

        # Before/After (only if available, concise)
        if finding.fix_before and finding.fix_after:
            before = finding.fix_before.replace("\n", " | ")
            after = finding.fix_after.replace("\n", " | ")
            if len(before) > 70:
                before = before[:67] + "..."
            if len(after) > 70:
                after = after[:67] + "..."
            _safe_print(f"        - {DIM}{before}{RESET}")
            _safe_print(f"        + {after}")

        # Reference (compact)
        if finding.reference:
            _safe_print(f"      ref:  {DIM}{finding.reference}{RESET}")

    # Summary bar
    _safe_print(f"\n{line}")
    _safe_print(f"  TOTAL: {len(result.findings)} issues  |  {result.summary()}")
    _safe_print(line)
