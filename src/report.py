"""
Output formatting for redact-verify.

Generates JSON and text reports from verification results.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple

from src.core import VerifyResult, ExitCode


# ANSI color codes
class Colors:
    """ANSI escape codes for terminal colors."""
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    
    @classmethod
    def enabled(cls) -> bool:
        """Check if colors should be enabled."""
        # Disable if NO_COLOR env var is set or not a TTY
        if os.environ.get("NO_COLOR"):
            return False
        if not sys.stdout.isatty():
            return False
        # Enable ANSI on Windows 10+
        if sys.platform == "win32":
            os.system("")  # Enables ANSI escape sequences on Windows
        return True


def format_json(results: List[Tuple[Path, VerifyResult]]) -> str:
    """
    Format verification results as JSON.

    Args:
        results: List of (file_path, result) tuples.

    Returns:
        JSON string representation.
    """
    output = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(results),
            "passed": sum(1 for _, r in results if r.passed),
            "failed": sum(1 for _, r in results if r.failed),
            "errors": sum(1 for _, r in results if r.errored),
        },
        "files": [],
    }

    for file_path, result in results:
        file_report = {
            "path": str(file_path),
            "status": _exit_code_to_status(result.exit_code),
            "exit_code": result.exit_code.value,
            "surfaces_checked": result.surfaces_checked,
            "ocr_performed": result.ocr_performed,
        }

        if result.error:
            file_report["error"] = result.error

        if result.matches:
            file_report["matches"] = [
                {
                    "pattern": m.pattern,
                    "matched_text": m.text,
                    "source": m.source,
                    "page": m.page,
                    "location": m.location,
                }
                for m in result.matches
            ]

        output["files"].append(file_report)

    return json.dumps(output, indent=2)


def format_text(results: List[Tuple[Path, VerifyResult]]) -> str:
    """
    Format verification results as human-readable text with colors.

    Args:
        results: List of (file_path, result) tuples.

    Returns:
        Text string representation.
    """
    lines: List[str] = []
    use_color = Colors.enabled()

    for file_path, result in results:
        status = _exit_code_to_status(result.exit_code).upper()
        
        # Color-coded status
        if use_color:
            if result.passed:
                status_str = f"{Colors.GREEN}{Colors.BOLD}[PASS]{Colors.RESET}"
            elif result.failed:
                status_str = f"{Colors.RED}{Colors.BOLD}[FAIL]{Colors.RESET}"
            else:
                status_str = f"{Colors.YELLOW}{Colors.BOLD}[ERROR]{Colors.RESET}"
        else:
            status_str = f"[{status}]"
        
        lines.append(f"{status_str} {file_path.name}")

        if result.error:
            lines.append(f"  Error: {result.error}")

        if result.matches:
            lines.append(f"  {len(result.matches)} match(es):")
            for match in result.matches:
                page_info = f" (page {match.page})" if match.page is not None else ""
                lines.append(
                    f"    - '{match.pattern}' in {match.source}{page_info}"
                )

    # Summary
    if len(results) > 1:
        passed = sum(1 for _, r in results if r.passed)
        failed = sum(1 for _, r in results if r.failed)
        errors = sum(1 for _, r in results if r.errored)
        lines.append("")
        
        if use_color:
            summary = (
                f"{Colors.GREEN}{passed} passed{Colors.RESET}, "
                f"{Colors.RED}{failed} failed{Colors.RESET}, "
                f"{Colors.YELLOW}{errors} errors{Colors.RESET}"
            )
        else:
            summary = f"{passed} passed, {failed} failed, {errors} errors"
        
        lines.append(summary)

    return "\n".join(lines)


def _exit_code_to_status(code: ExitCode) -> str:
    """Convert exit code to status string."""
    return {
        ExitCode.PASS: "pass",
        ExitCode.FAIL: "fail",
        ExitCode.ERROR: "error",
    }.get(code, "unknown")

