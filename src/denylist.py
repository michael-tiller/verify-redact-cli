"""
Denylist pattern loading and matching for redact-verify.

Supports literal strings and regex patterns.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Pattern, Union

from src.extractors import Corpus, TextFragment


@dataclass
class DenylistPattern:
    """A pattern to match against extracted text."""
    pattern: Pattern[str]
    original: str
    is_regex: bool

    @classmethod
    def from_string(cls, s: str, as_regex: bool = False) -> "DenylistPattern":
        """Create a pattern from a string."""
        if as_regex:
            try:
                compiled = re.compile(s, re.IGNORECASE | re.MULTILINE)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern '{s}': {e}") from e
            return cls(pattern=compiled, original=s, is_regex=True)
        else:
            # Escape special chars for literal matching
            # CRITICAL: Allow flexible whitespace to catch text split across fragments
            # Security invariant: Fragmentation does not make sensitive data safe
            escaped = re.escape(s)
            # Replace escaped spaces with flexible whitespace pattern
            # This allows matching "John Smith" even if split as "John" + "Smith"
            escaped = escaped.replace(r'\ ', r'\s+')
            compiled = re.compile(escaped, re.IGNORECASE)
            return cls(pattern=compiled, original=s, is_regex=False)


@dataclass
class Match:
    """A match found in the corpus."""
    pattern: str
    text: str
    source: str
    page: Optional[int] = None
    location: Optional[str] = None

    def __str__(self) -> str:
        loc = f"page {self.page}" if self.page is not None else self.location or "unknown"
        return f"'{self.pattern}' found in {self.source} at {loc}"


def load_denylist(
    strings: Optional[List[str]] = None,
    file_path: Optional[Path] = None,
) -> List[DenylistPattern]:
    """
    Load denylist patterns from strings and/or file.

    Args:
        strings: List of literal strings to deny.
        file_path: Path to file with patterns (one per line).
                   Lines starting with 'regex:' are treated as regex.

    Returns:
        List of compiled DenylistPattern objects.
    """
    patterns: List[DenylistPattern] = []

    # Load inline strings as literal patterns
    if strings:
        for s in strings:
            if s and s.strip():
                patterns.append(DenylistPattern.from_string(s.strip()))

    # Load patterns from file
    if file_path:
        if not file_path.exists():
            raise FileNotFoundError(f"Denylist file not found: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue

                # Check for regex prefix
                if line.startswith("regex:"):
                    regex_str = line[6:].strip()
                    if regex_str:
                        try:
                            patterns.append(
                                DenylistPattern.from_string(regex_str, as_regex=True)
                            )
                        except ValueError as e:
                            raise ValueError(
                                f"Invalid regex on line {line_num}: {e}"
                            ) from e
                else:
                    patterns.append(DenylistPattern.from_string(line))

    return patterns


def check_corpus(
    corpus: Corpus,
    patterns: List[DenylistPattern],
) -> List[Match]:
    """
    Check corpus against denylist patterns.

    Security invariant: ALL sources are checked. There are no "safe" sources.
    If a denylisted string appears in ANY fragment (raw_stream, embedded, 
    ocg_layer, etc.), the document fails verification.
    
    Also checks the concatenated full text to catch patterns that span
    multiple fragments (e.g., text split across streams).

    Args:
        corpus: Extracted text corpus from PDF.
        patterns: List of patterns to search for.

    Returns:
        List of matches found.
    """
    matches: List[Match] = []
    seen_matches: set = set()  # Avoid duplicate matches

    # Check ALL fragments regardless of source
    # No source is exempt from denylist checking
    for fragment in corpus.fragments:
        if not fragment.text:
            continue

        # Check each pattern against this fragment
        for dp in patterns:
            if dp.pattern.search(fragment.text):
                # Find the actual matched text
                match_obj = dp.pattern.search(fragment.text)
                matched_text = match_obj.group(0) if match_obj else dp.original
                
                # Create a unique key for this match to avoid duplicates
                match_key = (dp.original, fragment.source, fragment.page, matched_text)
                if match_key not in seen_matches:
                    seen_matches.add(match_key)
                    matches.append(Match(
                        pattern=dp.original,
                        text=matched_text,
                        source=fragment.source,
                        page=fragment.page,
                        location=fragment.location,
                    ))

    # CRITICAL: Always check the concatenated full text to catch patterns that span fragments
    # This is essential for catching text split across streams, fragments, or encoding boundaries
    # Security invariant: Fragmentation does not make sensitive data safe
    full_text = corpus.full_text
    if full_text:
        for dp in patterns:
            if dp.pattern.search(full_text):
                match_obj = dp.pattern.search(full_text)
                matched_text = match_obj.group(0) if match_obj else dp.original
                
                # Only add if we haven't already found this match in a fragment
                # This prevents double-reporting, but ensures we catch split text
                match_key = (dp.original, "full_text", None, matched_text)
                if match_key not in seen_matches:
                    seen_matches.add(match_key)
                    # Try to find which source(s) contributed to this match
                    # by checking which fragments contain parts of the matched text
                    source = "multiple_sources"
                    contributing_sources = set()
                    for fragment in corpus.fragments:
                        if fragment.text:
                            # Check if this fragment contributes to the match
                            # (contains any part of the matched text)
                            fragment_lower = fragment.text.lower()
                            matched_lower = matched_text.lower()
                            # Check if fragment contains any significant substring of the match
                            if len(matched_lower) > 3:
                                # Check for overlapping substrings
                                for i in range(len(matched_lower) - 2):
                                    substr = matched_lower[i:i+3]
                                    if substr in fragment_lower:
                                        contributing_sources.add(fragment.source)
                                        source = fragment.source  # Use first contributing source
                                        break
                    
                    if len(contributing_sources) > 1:
                        source = f"multiple_sources({','.join(sorted(contributing_sources))})"
                    
                    matches.append(Match(
                        pattern=dp.original,
                        text=matched_text,
                        source=source,
                        page=None,
                        location="spanning_multiple_fragments",
                    ))

    return matches

