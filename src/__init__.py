"""
redact-verify: A defensive CLI tool for verifying PDF redaction integrity.

This tool analyzes redacted PDFs to ensure no recoverable sensitive information
remains accessible through text extraction, metadata, layers, annotations, or OCR.
"""

__version__ = "0.1.0"
__author__ = "Michael Tiller"

from src.core import verify, VerifyResult, ExitCode

__all__ = ["verify", "VerifyResult", "ExitCode", "__version__"]

