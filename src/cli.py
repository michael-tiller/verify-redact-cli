"""
Command-line interface for redact-verify.

Handles argument parsing, glob expansion, and orchestrates verification.
"""

import argparse
import glob
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional

from src import __version__
from src.core import verify, ExitCode
from src.denylist import load_denylist
from src.report import format_json, format_text


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog="redact-verify",
        description=(
            "Verify that redacted PDFs contain no recoverable sensitive information. "
            "Analyzes text surfaces, metadata, annotations, and optionally performs OCR."
        ),
        epilog="Exit codes: 0=pass, 1=leakage detected, 2=malformed document",
    )

    parser.add_argument(
        "files",
        nargs="+",
        help="PDF file(s) to verify. Supports glob patterns.",
    )

    parser.add_argument(
        "--deny",
        action="append",
        dest="deny_strings",
        metavar="TEXT",
        help="Denylist string that must not appear (repeatable).",
    )

    parser.add_argument(
        "--denyfile",
        type=Path,
        metavar="PATH",
        help="Path to denylist file (one string or regex pattern per line).",
    )

    parser.add_argument(
        "--strict",
        action="store_true",
        help="Enable OCR and structural checks.",
    )

    parser.add_argument(
        "--ocr",
        choices=["off", "auto", "always"],
        default="off",
        metavar="MODE",
        help="OCR mode: off, auto, always (default: off).",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output JSON report to stdout.",
    )

    parser.add_argument(
        "--jobs",
        "-j",
        type=int,
        default=1,
        metavar="N",
        help="Number of parallel workers for batch mode (default: 1).",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return parser


def expand_globs(patterns: List[str]) -> List[Path]:
    """Expand glob patterns into a list of file paths."""
    files: List[Path] = []
    for pattern in patterns:
        # Check if it's a glob pattern
        if any(c in pattern for c in ["*", "?", "["]):
            matches = glob.glob(pattern, recursive=True)
            files.extend(Path(m) for m in matches)
        else:
            files.append(Path(pattern))
    return files


def verify_single_file(
    file_path: Path,
    patterns: List,
    strict: bool,
    ocr_mode: str,
) -> tuple:
    """Verify a single file and return (path, result)."""
    result = verify(
        pdf_path=file_path,
        denylist_patterns=patterns,
        strict=strict,
        ocr_mode=ocr_mode,
    )
    return (file_path, result)


def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point for the CLI."""
    parser = create_parser()
    args = parser.parse_args(argv)

    # Expand file globs
    files = expand_globs(args.files)

    if not files:
        print("Error: No files found matching the provided patterns.", file=sys.stderr)
        return ExitCode.ERROR.value

    # Validate files exist
    missing = [f for f in files if not f.exists()]
    if missing:
        for f in missing:
            print(f"Error: File not found: {f}", file=sys.stderr)
        return ExitCode.ERROR.value

    # Load denylist patterns
    patterns = load_denylist(
        strings=args.deny_strings,
        file_path=args.denyfile,
    )

    # OCR mode - explicit opt-in only (requires Tesseract)
    ocr_mode = args.ocr

    # Run verification
    results = []
    worst_exit = ExitCode.PASS

    if args.jobs > 1 and len(files) > 1:
        # Parallel execution
        with ProcessPoolExecutor(max_workers=args.jobs) as executor:
            futures = {
                executor.submit(
                    verify_single_file, f, patterns, args.strict, ocr_mode
                ): f
                for f in files
            }
            for future in as_completed(futures):
                file_path, result = future.result()
                results.append((file_path, result))
                if result.exit_code.value > worst_exit.value:
                    worst_exit = result.exit_code
    else:
        # Sequential execution
        for file_path in files:
            result = verify(
                pdf_path=file_path,
                denylist_patterns=patterns,
                strict=args.strict,
                ocr_mode=ocr_mode,
            )
            results.append((file_path, result))
            if result.exit_code.value > worst_exit.value:
                worst_exit = result.exit_code

    # Output results
    if args.json_output:
        print(format_json(results))
    else:
        output = format_text(results)
        if output:
            print(output)

    return worst_exit.value


if __name__ == "__main__":
    sys.exit(main())

