"""
Core verification orchestrator for redact-verify.

Coordinates extraction, denylist matching, and result generation.
"""

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import List, Optional

from src.extractors import extract_all, ExtractionError, Corpus
from src.denylist import check_corpus, DenylistPattern, Match


class ExitCode(IntEnum):
    """Exit codes for verification results."""
    PASS = 0      # No leakage detected
    FAIL = 1      # Leakage found
    ERROR = 2     # Malformed or unreadable document


@dataclass
class VerifyResult:
    """Result of a verification operation."""
    exit_code: ExitCode
    matches: List[Match] = field(default_factory=list)
    error: Optional[str] = None
    surfaces_checked: List[str] = field(default_factory=list)
    ocr_performed: bool = False

    @property
    def passed(self) -> bool:
        """Return True if verification passed (no leakage)."""
        return self.exit_code == ExitCode.PASS

    @property
    def failed(self) -> bool:
        """Return True if verification failed (leakage found)."""
        return self.exit_code == ExitCode.FAIL

    @property
    def errored(self) -> bool:
        """Return True if an error occurred."""
        return self.exit_code == ExitCode.ERROR


def verify(
    pdf_path: Path,
    denylist_patterns: Optional[List[DenylistPattern]] = None,
    strict: bool = False,
    ocr_mode: str = "off",
) -> VerifyResult:
    """
    Verify that a PDF contains no recoverable sensitive information.

    Args:
        pdf_path: Path to the PDF file to verify.
        denylist_patterns: List of patterns to search for.
        strict: Enable structural checks and OCR.
        ocr_mode: OCR behavior - "off", "auto", or "always".

    Returns:
        VerifyResult with exit code, matches, and metadata.
    """
    if denylist_patterns is None:
        denylist_patterns = []

    # Extract all text surfaces from the PDF
    try:
        corpus = extract_all(
            pdf_path=pdf_path,
            strict=strict,
            ocr_mode=ocr_mode,
        )
    except ExtractionError as e:
        return VerifyResult(
            exit_code=ExitCode.ERROR,
            error=str(e),
        )
    except Exception as e:
        return VerifyResult(
            exit_code=ExitCode.ERROR,
            error=f"Unexpected error reading PDF: {e}",
        )

    # If no denylist patterns provided, we can only do structural checks
    # For now, pass if document is readable and no patterns to check
    if not denylist_patterns:
        return VerifyResult(
            exit_code=ExitCode.PASS,
            surfaces_checked=corpus.surfaces_extracted,
            ocr_performed=corpus.ocr_performed,
        )

    # Check corpus against denylist
    # SECURITY INVARIANT: ALL sources are checked - there are no "safe" sources.
    # If a denylisted string appears in ANY fragment (raw_stream, embedded, 
    # ocg_layer, content, annotation, metadata, xobject, ocr, etc.), 
    # verification MUST fail. Presence matters, not render state.
    matches = check_corpus(corpus, denylist_patterns)

    if matches:
        return VerifyResult(
            exit_code=ExitCode.FAIL,
            matches=matches,
            surfaces_checked=corpus.surfaces_extracted,
            ocr_performed=corpus.ocr_performed,
        )

    return VerifyResult(
        exit_code=ExitCode.PASS,
        surfaces_checked=corpus.surfaces_extracted,
        ocr_performed=corpus.ocr_performed,
    )

