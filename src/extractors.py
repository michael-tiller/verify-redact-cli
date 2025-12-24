"""
PDF text extraction for redact-verify.

Extracts text from all recoverable surfaces:
- Content streams (main text)
- Annotations
- Form fields
- Metadata
- Layers / XObjects (including hidden OCG layers)
- Embedded objects (including unrendered XObjects)
- OCR (optional)

Security invariants:
- OCG content is ALWAYS extractable regardless of visibility state
- XObjects are extractable whether rendered or not
- Presence of recoverable semantic text matters, not render state
- Visual-only obfuscation (vector paths, outlines) is not recoverable text

Note: Some PDFs may contain visual-only "hidden" content (e.g., LibreOffice
converts text to paths in layers). These are correctly identified as PASS
because they contain no recoverable text, only visual deception.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

import fitz  # PyMuPDF


class ExtractionError(Exception):
    """Raised when PDF extraction fails."""
    pass


@dataclass
class TextFragment:
    """A fragment of extracted text with source metadata."""
    text: str
    source: str  # e.g., "content", "annotation", "metadata"
    page: Optional[int] = None
    location: Optional[str] = None  # Additional location info


@dataclass
class Corpus:
    """Collection of all extracted text from a PDF."""
    fragments: List[TextFragment] = field(default_factory=list)
    surfaces_extracted: List[str] = field(default_factory=list)
    ocr_performed: bool = False

    @property
    def full_text(self) -> str:
        """
        Return all text as a single normalized string.
        
        CRITICAL: Uses space separator, not newline, to ensure patterns
        spanning fragments can be matched. Fragmentation does not make
        sensitive data safe.
        """
        return " ".join(f.text for f in self.fragments if f.text)

    def get_by_source(self, source: str) -> List[TextFragment]:
        """Get all fragments from a specific source."""
        return [f for f in self.fragments if f.source == source]


def extract_all(
    pdf_path: Path,
    strict: bool = False,
    ocr_mode: str = "off",
) -> Corpus:
    """
    Extract all text-bearing surfaces from a PDF.

    Args:
        pdf_path: Path to the PDF file.
        strict: Enable additional structural checks.
        ocr_mode: "off", "auto", or "always".

    Returns:
        Corpus containing all extracted text fragments.

    Raises:
        ExtractionError: If the PDF cannot be read.
    """
    try:
        doc = fitz.open(str(pdf_path))
    except Exception as e:
        raise ExtractionError(f"Failed to open PDF: {e}") from e

    corpus = Corpus()

    try:
        # Extract from each surface type
        _extract_content_streams(doc, corpus)
        _extract_annotations(doc, corpus)
        _extract_form_fields(doc, corpus)
        _extract_metadata(doc, corpus)
        _extract_xobjects_full(doc, corpus)  # Full XObject enumeration
        _extract_ocg_layers(doc, corpus)      # Hidden layer extraction
        _extract_embedded_full(doc, corpus)   # Full embedded content
        _extract_all_streams(doc, corpus)     # Brute-force all streams

        # OCR extraction - only runs when explicitly requested
        # Catches: visual-only text (rasterized), custom font encodings
        # Requires: pip install pytesseract Pillow + Tesseract binary
        if ocr_mode in ("auto", "always"):
            _extract_ocr(doc, corpus)

    finally:
        doc.close()

    return corpus


def _extract_content_streams(doc: fitz.Document, corpus: Corpus) -> None:
    """Extract text from page content streams."""
    corpus.surfaces_extracted.append("content_streams")

    for page_num, page in enumerate(doc):
        # Get text using standard method
        text = page.get_text("text")
        if text and text.strip():
            corpus.fragments.append(TextFragment(
                text=text.strip(),
                source="content",
                page=page_num,
            ))
        
        # Also extract directly from content streams to catch hidden layer content
        # that might not be returned by get_text()
        try:
            # Get raw content stream
            xref = page.xref
            page_dict = doc.xref_object(xref, compressed=False)
            import re
            # Find all content stream references
            content_refs = re.findall(r"/Contents\s+(\d+)\s+0\s+R", page_dict)
            # Also check for array format
            array_match = re.search(r"/Contents\s*\[\s*((?:\d+\s+0\s+R\s*)+)\]", page_dict)
            if array_match:
                array_refs = re.findall(r"(\d+)\s+0\s+R", array_match.group(1))
                content_refs.extend(array_refs)
            
            for ref_str in content_refs:
                content_xref = int(ref_str)
                try:
                    stream = doc.xref_stream(content_xref)
                    if stream:
                        text = stream.decode("utf-8", errors="ignore")
                        extracted = _extract_text_from_content_stream(text)
                        if extracted and extracted.strip():
                            corpus.fragments.append(TextFragment(
                                text=extracted.strip(),
                                source="content",
                                page=page_num,
                                location=f"content_stream_xref:{content_xref}",
                            ))
                except Exception:
                    continue
        except Exception:
            pass


def _extract_annotations(doc: fitz.Document, corpus: Corpus) -> None:
    """Extract text from annotations."""
    corpus.surfaces_extracted.append("annotations")

    for page_num, page in enumerate(doc):
        for annot in page.annots() or []:
            # Get annotation content
            content = annot.info.get("content", "")
            if content:
                corpus.fragments.append(TextFragment(
                    text=content,
                    source="annotation",
                    page=page_num,
                    location=f"annot:{annot.type[1]}",
                ))

            # Get annotation title/subject
            title = annot.info.get("title", "")
            if title:
                corpus.fragments.append(TextFragment(
                    text=title,
                    source="annotation",
                    page=page_num,
                    location=f"annot_title:{annot.type[1]}",
                ))

            subject = annot.info.get("subject", "")
            if subject:
                corpus.fragments.append(TextFragment(
                    text=subject,
                    source="annotation",
                    page=page_num,
                    location=f"annot_subject:{annot.type[1]}",
                ))


def _extract_form_fields(doc: fitz.Document, corpus: Corpus) -> None:
    """Extract text from form fields."""
    corpus.surfaces_extracted.append("form_fields")

    for page_num, page in enumerate(doc):
        widgets = page.widgets()
        if widgets:
            for widget in widgets:
                field_value = widget.field_value
                if field_value:
                    corpus.fragments.append(TextFragment(
                        text=str(field_value),
                        source="form_field",
                        page=page_num,
                        location=f"field:{widget.field_name}",
                    ))


def _extract_metadata(doc: fitz.Document, corpus: Corpus) -> None:
    """Extract document metadata."""
    corpus.surfaces_extracted.append("metadata")

    metadata = doc.metadata
    if metadata:
        for key, value in metadata.items():
            if value and isinstance(value, str) and value.strip():
                corpus.fragments.append(TextFragment(
                    text=value.strip(),
                    source="metadata",
                    location=f"meta:{key}",
                ))


def _extract_xobjects_full(doc: fitz.Document, corpus: Corpus) -> None:
    """
    Extract text from ALL XObjects in the document.
    
    Security invariant: Rendered or not does not matter. Presence matters.
    This traverses all XObjects in resource dictionaries, not just those
    invoked by the content stream.
    """
    corpus.surfaces_extracted.append("xobjects")
    
    seen_xrefs: Set[int] = set()
    
    for page_num, page in enumerate(doc):
        # Method 1: Extract via text dict (catches rendered XObjects)
        text_dict = page.get_text("dict", flags=fitz.TEXT_PRESERVE_WHITESPACE)
        for block in text_dict.get("blocks", []):
            if block.get("type") == 0:  # Text block
                for line in block.get("lines", []):
                    for span in line.get("spans", []):
                        text = span.get("text", "")
                        if text and text.strip():
                            corpus.fragments.append(TextFragment(
                                text=text.strip(),
                                source="xobject",
                                page=page_num,
                            ))
        
        # Method 2: Enumerate ALL XObjects in page resources (including unrendered)
        _extract_page_xobjects_recursive(doc, page, page_num, corpus, seen_xrefs)
    
    # Method 3: Walk entire PDF object tree for orphaned XObjects
    _extract_orphaned_xobjects(doc, corpus, seen_xrefs)


def _extract_page_xobjects_recursive(
    doc: fitz.Document,
    page: fitz.Page,
    page_num: int,
    corpus: Corpus,
    seen_xrefs: Set[int],
) -> None:
    """Recursively extract text from all XObjects in page resources."""
    try:
        # Get the page's resource dictionary
        resources = page.get_resources()
        if not resources:
            return
            
        # Resources is a list of tuples: (type, xref, name, ...)
        for res in resources:
            if len(res) < 2:
                continue
            res_type, xref = res[0], res[1]
            
            if xref in seen_xrefs:
                continue
            seen_xrefs.add(xref)
            
            # Extract text from Form XObjects
            if res_type == "XObject":
                _extract_xobject_by_xref(doc, xref, page_num, corpus, seen_xrefs)
                
    except Exception:
        # Fallback: some PDFs may have malformed resources
        pass


def _extract_xobject_by_xref(
    doc: fitz.Document,
    xref: int,
    page_num: Optional[int],
    corpus: Corpus,
    seen_xrefs: Set[int],
) -> None:
    """Extract text content from an XObject by its xref."""
    try:
        # Get the XObject dictionary to check dimensions
        xobj_dict = doc.xref_object(xref, compressed=False)
        
        # Check if this is an image XObject with 0x0 dimensions (hidden embedded image)
        is_zero_size_image = False
        if "/Subtype /Image" in xobj_dict or "/Subtype/Image" in xobj_dict:
            # Extract width and height
            import re
            width_match = re.search(r"/Width\s+(\d+)", xobj_dict)
            height_match = re.search(r"/Height\s+(\d+)", xobj_dict)
            if width_match and height_match:
                width = int(width_match.group(1))
                height = int(height_match.group(1))
                if width == 0 or height == 0:
                    is_zero_size_image = True
                    # Mark this as a 0x0 embedded image for special handling
                    location_suffix = f"0x0_image_xref:{xref}"
                else:
                    location_suffix = f"image_xref:{xref}"
            else:
                location_suffix = f"xref:{xref}"
        else:
            location_suffix = f"xref:{xref}"
        
        # Get the XObject stream
        xobj_stream = doc.xref_stream(xref)
        if xobj_stream:
            # For 0x0 images, we still want to extract any text/metadata
            # For Form XObjects, extract text from content stream
            # CRITICAL: Also check ALL image XObjects for embedded text/metadata
            is_image = "/Subtype /Image" in xobj_dict or "/Subtype/Image" in xobj_dict
            is_form = "/Subtype /Form" in xobj_dict or "/Subtype/Form" in xobj_dict
            
            if is_form or is_zero_size_image or is_image:
                # Try to decode as text and extract from content stream
                try:
                    text = xobj_stream.decode("utf-8", errors="ignore")
                    # Look for text operators in the content stream
                    extracted = _extract_text_from_content_stream(text)
                    if extracted:
                        source = "embedded" if (is_zero_size_image or is_image) else "xobject"
                        corpus.fragments.append(TextFragment(
                            text=extracted,
                            source=source,
                            page=page_num,
                            location=location_suffix,
                        ))
                except Exception:
                    pass
                
                # For images (especially 0x0), check for embedded text in binary data/metadata
                if is_zero_size_image or is_image:
                    # Try to extract readable strings from binary image data
                    readable = _extract_strings_from_binary(xobj_stream, min_length=3)
                    if readable:
                        corpus.fragments.append(TextFragment(
                            text=readable,
                            source="embedded",
                            page=page_num,
                            location=location_suffix,
                        ))
        
        # Also check the XObject's own resources for nested XObjects
        if "/Resources" in xobj_dict:
            # Parse nested resources - this catches deeply nested content
            _extract_nested_resources(doc, xobj_dict, page_num, corpus, seen_xrefs)
            
    except Exception:
        pass


def _extract_nested_resources(
    doc: fitz.Document,
    obj_str: str,
    page_num: Optional[int],
    corpus: Corpus,
    seen_xrefs: Set[int],
) -> None:
    """Extract XObjects from nested resource dictionaries."""
    import re
    
    # Find all xref references in the object string
    xref_pattern = re.compile(r"(\d+)\s+0\s+R")
    for match in xref_pattern.finditer(obj_str):
        xref = int(match.group(1))
        if xref not in seen_xrefs:
            seen_xrefs.add(xref)
            _extract_xobject_by_xref(doc, xref, page_num, corpus, seen_xrefs)


def _extract_orphaned_xobjects(
    doc: fitz.Document,
    corpus: Corpus,
    seen_xrefs: Set[int],
) -> None:
    """
    Find and extract XObjects that aren't referenced by any page.
    
    CRITICAL: Must check ALL XObjects including images, as 0x0 images
    can contain hidden text that should be detected.
    """
    try:
        # Walk through all objects in the PDF
        xref_count = doc.xref_length()
        
        for xref in range(1, xref_count):
            if xref in seen_xrefs:
                continue
                
            try:
                obj_str = doc.xref_object(xref, compressed=False)
                
                # Check if this is a Form XObject
                if "/Subtype /Form" in obj_str or "/Subtype/Form" in obj_str:
                    seen_xrefs.add(xref)
                    _extract_xobject_by_xref(doc, xref, None, corpus, seen_xrefs)
                
                # CRITICAL: Check ALL Image XObjects (including 0x0 hidden images)
                # Even if not referenced, they may contain hidden text
                if "/Subtype /Image" in obj_str or "/Subtype/Image" in obj_str:
                    seen_xrefs.add(xref)
                    _extract_xobject_by_xref(doc, xref, None, corpus, seen_xrefs)
                    
            except Exception:
                continue
                
    except Exception:
        pass


def _extract_text_from_content_stream(stream: str) -> str:
    """
    Extract text from a PDF content stream.
    
    Looks for text-showing operators: Tj, TJ, ', "
    Also handles hex strings and other text encodings.
    """
    import re
    
    texts: List[str] = []
    
    # Match text in parentheses before Tj operator
    tj_pattern = re.compile(r"\(([^)]*)\)\s*Tj", re.DOTALL)
    for match in tj_pattern.finditer(stream):
        text = match.group(1)
        # Unescape PDF string escapes
        text = _unescape_pdf_string(text)
        if text.strip():
            texts.append(text.strip())
    
    # Match TJ arrays (array of strings and positioning)
    tj_array_pattern = re.compile(r"\[((?:[^]]+))\]\s*TJ", re.DOTALL)
    for match in tj_array_pattern.finditer(stream):
        array_content = match.group(1)
        # Extract strings from the array
        string_pattern = re.compile(r"\(([^)]*)\)")
        for str_match in string_pattern.finditer(array_content):
            text = _unescape_pdf_string(str_match.group(1))
            if text.strip():
                texts.append(text.strip())
    
    # Match hex strings: <hex> Tj or <hex> TJ
    hex_pattern = re.compile(r"<([0-9A-Fa-f\s]+)>\s*T[^a-zA-Z]", re.DOTALL)
    for match in hex_pattern.finditer(stream):
        hex_str = match.group(1).replace(" ", "").replace("\n", "").replace("\r", "")
        try:
            # Decode hex string to text
            text = bytes.fromhex(hex_str).decode("utf-8", errors="ignore")
            if text.strip():
                texts.append(text.strip())
        except Exception:
            pass
    
    # Also look for any parenthesized strings that might be text (broader search)
    # This catches text that might not be directly before Tj/TJ operators
    all_strings_pattern = re.compile(r"\(([^)]{3,})\)", re.DOTALL)
    for match in all_strings_pattern.finditer(stream):
        text = match.group(1)
        # Only include if it looks like readable text (not just numbers/symbols)
        if any(c.isalpha() for c in text):
            text = _unescape_pdf_string(text)
            if text.strip() and len(text.strip()) >= 3:
                texts.append(text.strip())
    
    return " ".join(texts)


def _unescape_pdf_string(s: str) -> str:
    """Unescape PDF string escape sequences."""
    replacements = [
        ("\\n", "\n"),
        ("\\r", "\r"),
        ("\\t", "\t"),
        ("\\(", "("),
        ("\\)", ")"),
        ("\\\\", "\\"),
    ]
    for old, new in replacements:
        s = s.replace(old, new)
    return s


def _extract_ocg_layers(doc: fitz.Document, corpus: Corpus) -> None:
    """
    Extract text from Optional Content Groups (hidden layers).
    
    Security invariant: OCG content is ALWAYS extractable regardless of 
    visibility state (/State /OFF is irrelevant for security).
    
    This function directly parses the PDF structure to find content in
    layers marked as hidden (/State /OFF).
    """
    corpus.surfaces_extracted.append("ocg_layers")
    
    try:
        # Get OCG configuration
        oc_config = doc.get_oc()
        if not oc_config:
            return
        
        # Store original layer states
        original_states = {}
        try:
            layer_config = doc.layer_ui_configs()
            if layer_config:
                for layer in layer_config:
                    layer_num = layer.get("number", 0)
                    original_states[layer_num] = layer.get("on", True)
        except Exception:
            pass
        
        # Enable ALL layers to extract hidden content
        # CRITICAL: Some PDFs may not expose layers via layer_ui_configs(),
        # but still have OCG content. We must enable all possible layers.
        try:
            layer_config = doc.layer_ui_configs()
            if layer_config:
                for layer in layer_config:
                    layer_num = layer.get("number", 0)
                    doc.set_layer_ui_config(layer_num, on=True)
        except Exception:
            pass
        
        # Also try to enable layers via OCGs API if available
        try:
            ocgs = doc.get_ocgs()
            if ocgs:
                # Enable all OCGs
                for ocg_xref in ocgs:
                    try:
                        # Try to enable this OCG
                        doc.set_ocg_state(ocg_xref, True)
                    except Exception:
                        pass
        except Exception:
            pass
        
        # Now extract text with all layers visible
        # CRITICAL: Text from hidden layers is still recoverable content
        # Security-wise, layer visibility is irrelevant - treat as content
        for page_num, page in enumerate(doc):
            # Get text with all layers enabled
            # This catches text that's only visible when layers are enabled,
            # even if it's not in standard text-showing operators
            text = page.get_text("text")
            if text and text.strip():
                corpus.fragments.append(TextFragment(
                    text=text.strip(),
                    source="content",  # Not "ocg_layer" - security invariant: visibility doesn't matter
                    page=page_num,
                    location="ocg_all_layers_enabled",
                ))
            
            # Also try get_text("dict") to catch text in spans/blocks that might be layer-specific
            try:
                text_dict = page.get_text("dict", flags=fitz.TEXT_PRESERVE_WHITESPACE)
                for block in text_dict.get("blocks", []):
                    if block.get("type") == 0:  # Text block
                        block_text = ""
                        for line in block.get("lines", []):
                            for span in line.get("spans", []):
                                span_text = span.get("text", "")
                                if span_text:
                                    block_text += span_text + " "
                        if block_text.strip():
                            corpus.fragments.append(TextFragment(
                                text=block_text.strip(),
                                source="content",  # Security invariant: layer content is still content
                                page=page_num,
                                location="ocg_dict_extraction",
                            ))
            except Exception:
                pass
            
            # Also get raw content stream to catch any layer-specific content
            _extract_ocg_content_streams(doc, page, page_num, corpus)
        
        # Directly parse PDF structure for hidden layers
        _extract_hidden_ocg_from_structure(doc, corpus)
        
        # Restore original layer states
        try:
            for layer_num, was_on in original_states.items():
                doc.set_layer_ui_config(layer_num, on=was_on)
        except Exception:
            pass
            
    except Exception:
        # OCG extraction failed, try alternative method
        _extract_ocg_fallback(doc, corpus)


def _extract_ocg_content_streams(
    doc: fitz.Document,
    page: fitz.Page,
    page_num: int,
    corpus: Corpus,
) -> None:
    """Extract text from OCG-associated content streams directly."""
    try:
        # Get the page's content stream(s)
        xref = page.xref
        page_dict = doc.xref_object(xref, compressed=False)
        
        # Look for /Contents reference
        if "/Contents" in page_dict:
            import re
            # Find content stream xrefs
            content_refs = re.findall(r"(\d+)\s+0\s+R", page_dict)
            
            for ref_str in content_refs:
                content_xref = int(ref_str)
                try:
                    stream = doc.xref_stream(content_xref)
                    if stream:
                        text = stream.decode("utf-8", errors="ignore")
                        
                        # Look for BDC/EMC marked content (OCG markers)
                        if "/OC" in text or "BDC" in text:
                            extracted = _extract_text_from_content_stream(text)
                            if extracted:
                                corpus.fragments.append(TextFragment(
                                    text=extracted,
                                    source="content",  # Security invariant: layer visibility doesn't matter
                                    page=page_num,
                                    location=f"ocg_content_xref:{content_xref}",
                                ))
                except Exception:
                    continue
                    
    except Exception:
        pass


def _extract_hidden_ocg_from_structure(doc: fitz.Document, corpus: Corpus) -> None:
    """
    Directly parse PDF structure to find content in hidden OCG layers.
    
    Looks for OCGs with /State /OFF and extracts their associated content.
    
    CRITICAL: Some PDFs (like LibreOffice-generated) may not expose layers
    via the layer_ui_configs() API, but still have OCG content that must be extracted.
    This function parses the raw PDF structure to find and extract such content.
    """
    import re
    
    try:
        # Walk through all objects to find OCG dictionaries
        for xref in range(1, doc.xref_length()):
            try:
                obj_str = doc.xref_object(xref, compressed=False)
                
                # Look for OCG dictionaries - check for /Type /OCG or /OCGs references
                # Also check for /Usage dictionaries which indicate optional content
                is_ocg = False
                is_hidden = False
                
                if "/Type /OCG" in obj_str or "/Type/OCG" in obj_str:
                    is_ocg = True
                    # Check if it's marked as hidden
                    if "/State /OFF" in obj_str or "/State/OFF" in obj_str:
                        is_hidden = True
                
                # Also check for /OCGs array references and /Usage patterns
                # LibreOffice may use different structures
                if "/OCGs" in obj_str or "/Usage" in obj_str:
                    # This might be OCG-related content
                    is_ocg = True
                
                if is_ocg:
                    # Extract content associated with this OCG
                    # Even if not explicitly marked as hidden, extract it
                    # Security invariant: all OCG content is extractable
                    _extract_ocg_content_by_reference(doc, xref, corpus)
                    
                    # Also try to extract text directly from the OCG object if it contains content
                    try:
                        stream = doc.xref_stream(xref)
                        if stream:
                            text = stream.decode("utf-8", errors="ignore")
                            extracted = _extract_text_from_content_stream(text)
                            if extracted:
                                corpus.fragments.append(TextFragment(
                                    text=extracted,
                                    source="content",  # Security invariant: OCG content is still content
                                    location=f"ocg_object_xref:{xref}",
                                ))
                    except Exception:
                        pass
                    
            except Exception:
                continue
                
    except Exception:
        pass


def _extract_ocg_content_by_reference(
    doc: fitz.Document,
    ocg_xref: int,
    corpus: Corpus,
) -> None:
    """Extract content from streams that reference a specific OCG."""
    import re
    
    try:
        # Search for content streams that reference this OCG
        # Look for BDC/EMC operators with /OC references
        for page_num, page in enumerate(doc):
            try:
                # Get page content stream xrefs
                page_xref = page.xref
                page_dict = doc.xref_object(page_xref, compressed=False)
                
                # Find content stream references - handle both array and single reference
                # Pattern: /Contents [xref1 0 R xref2 0 R] or /Contents xref 0 R
                content_refs = []
                # Array format: /Contents [(\d+) 0 R ...]
                array_matches = re.findall(r"/Contents\s*\[\s*(\d+)\s+0\s+R", page_dict)
                content_refs.extend(array_matches)
                # Single reference: /Contents (\d+) 0 R
                single_matches = re.findall(r"/Contents\s+(\d+)\s+0\s+R(?!\s*\[)", page_dict)
                content_refs.extend(single_matches)
                
                # Check each content stream
                for ref_str in content_refs:
                    content_xref = int(ref_str)
                    try:
                        stream = doc.xref_stream(content_xref)
                        if stream:
                            text = stream.decode("utf-8", errors="ignore")
                            # Check if this stream references our hidden OCG
                            # Look for: /OC xref 0 R or BDC ... /OC xref 0 R
                            ocg_ref_pattern = rf"/OC\s+{ocg_xref}\s+0\s+R"
                            if re.search(ocg_ref_pattern, text) or f"{ocg_xref} 0 R" in text:
                                # Extract text from this content stream
                                extracted = _extract_text_from_content_stream(text)
                                if extracted:
                                    corpus.fragments.append(TextFragment(
                                        text=extracted,
                                        source="content",  # Security invariant: hidden layers are still content
                                        page=page_num,
                                        location=f"hidden_ocg_xref:{ocg_xref}",
                                    ))
                    except Exception:
                        continue
                        
            except Exception:
                continue
                
    except Exception:
        pass


def _extract_ocg_fallback(doc: fitz.Document, corpus: Corpus) -> None:
    """Fallback OCG extraction by walking the catalog."""
    try:
        # Access the PDF catalog
        catalog_xref = 0
        for i in range(1, doc.xref_length()):
            try:
                obj = doc.xref_object(i, compressed=False)
                if "/Type /Catalog" in obj or "/Type/Catalog" in obj:
                    catalog_xref = i
                    break
            except Exception:
                continue
        
        if catalog_xref == 0:
            return
            
        catalog = doc.xref_object(catalog_xref, compressed=False)
        
        # Look for OCProperties
        if "/OCProperties" not in catalog:
            return
            
        # Extract xrefs from OCProperties
        import re
        oc_section_match = re.search(r"/OCProperties\s*<<([^>]+)>>", catalog)
        if oc_section_match:
            oc_content = oc_section_match.group(1)
            xref_refs = re.findall(r"(\d+)\s+0\s+R", oc_content)
            
            seen: Set[int] = set()
            for xref_str in xref_refs:
                xref = int(xref_str)
                if xref in seen:
                    continue
                seen.add(xref)
                
                try:
                    stream = doc.xref_stream(xref)
                    if stream:
                        text = stream.decode("utf-8", errors="ignore")
                        extracted = _extract_text_from_content_stream(text)
                        if extracted:
                            corpus.fragments.append(TextFragment(
                                text=extracted,
                                source="content",  # Security invariant: hidden layers are still content
                                location=f"ocg_ocprops_xref:{xref}",
                            ))
                except Exception:
                    continue
                    
    except Exception:
        pass


def _extract_embedded_full(doc: fitz.Document, corpus: Corpus) -> None:
    """
    Extract ALL content from embedded files.
    
    Includes filenames, descriptions, and actual file contents.
    """
    corpus.surfaces_extracted.append("embedded")

    try:
        embedded_count = doc.embfile_count()
        for i in range(embedded_count):
            info = doc.embfile_info(i)
            
            # Extract filename
            if info.get("name"):
                corpus.fragments.append(TextFragment(
                    text=info["name"],
                    source="embedded",
                    location=f"embfile_name:{i}",
                ))
            
            # Extract description
            if info.get("desc"):
                corpus.fragments.append(TextFragment(
                    text=info["desc"],
                    source="embedded",
                    location=f"embfile_desc:{i}",
                ))
            
            # Extract actual file contents
            try:
                content = doc.embfile_get(i)
                if content:
                    # Try to decode as text
                    try:
                        text = content.decode("utf-8", errors="ignore")
                        if text.strip():
                            corpus.fragments.append(TextFragment(
                                text=text.strip(),
                                source="embedded",
                                location=f"embfile_content:{i}",
                            ))
                    except Exception:
                        # Binary content, try to find readable strings
                        text = _extract_strings_from_binary(content)
                        if text:
                            corpus.fragments.append(TextFragment(
                                text=text,
                                source="embedded",
                                location=f"embfile_content:{i}",
                            ))
            except Exception:
                pass
                
    except Exception:
        pass
    
    # Also check for embedded files via raw PDF structure
    _extract_embedded_via_xref(doc, corpus)


def _extract_embedded_via_xref(doc: fitz.Document, corpus: Corpus) -> None:
    """Find embedded files by walking the PDF structure."""
    try:
        seen: Set[int] = set()
        
        for xref in range(1, doc.xref_length()):
            if xref in seen:
                continue
                
            try:
                obj = doc.xref_object(xref, compressed=False)
                
                # Look for EmbeddedFile streams
                if "/Type /EmbeddedFile" in obj or "/Type/EmbeddedFile" in obj:
                    seen.add(xref)
                    
                    try:
                        stream = doc.xref_stream(xref)
                        if stream:
                            text = stream.decode("utf-8", errors="ignore")
                            if text.strip():
                                corpus.fragments.append(TextFragment(
                                    text=text.strip(),
                                    source="embedded",
                                    location=f"embstream_xref:{xref}",
                                ))
                    except Exception:
                        pass
                        
                # Look for FileSpec objects
                if "/Type /Filespec" in obj or "/Type/Filespec" in obj:
                    seen.add(xref)
                    
                    # Extract filename
                    import re
                    fname_match = re.search(r"/F\s*\(([^)]+)\)", obj)
                    if fname_match:
                        corpus.fragments.append(TextFragment(
                            text=fname_match.group(1),
                            source="embedded",
                            location=f"filespec_xref:{xref}",
                        ))
                        
            except Exception:
                continue
                
    except Exception:
        pass


def _extract_strings_from_binary(data: bytes, min_length: int = 4) -> str:
    """Extract readable strings from binary data."""
    import re
    
    # Decode as latin-1 to handle all byte values
    text = data.decode("latin-1", errors="ignore")
    
    # Find sequences of printable characters
    pattern = re.compile(r"[\x20-\x7e]{" + str(min_length) + r",}")
    matches = pattern.findall(text)
    
    result = " ".join(matches) if matches else ""
    
    # Also try to find text that might be interspersed with null bytes or other separators
    # This catches cases where text is embedded in binary with padding
    # Look for sequences of letters/numbers separated by non-printable chars
    if not result or len(result) < min_length:
        # Try finding text patterns even with null bytes
        # Match: at least min_length consecutive letters/numbers, allowing some non-printable in between
        flexible_pattern = re.compile(
            rb"([A-Za-z0-9\s\-]{"
            + str(min_length).encode()
            + rb",})",
            re.IGNORECASE
        )
        binary_matches = flexible_pattern.findall(data)
        if binary_matches:
            decoded_matches = []
            for match in binary_matches:
                try:
                    decoded = match.decode("utf-8", errors="ignore").strip()
                    # Filter out matches that are mostly non-printable
                    if decoded and any(c.isalnum() for c in decoded) and len(decoded) >= min_length:
                        decoded_matches.append(decoded)
                except Exception:
                    pass
            if decoded_matches:
                result = " ".join(decoded_matches) if not result else result + " " + " ".join(decoded_matches)
    
    return result


def _extract_all_streams(doc: fitz.Document, corpus: Corpus) -> None:
    """
    Brute-force extraction: scan ALL streams in the PDF for readable text.
    
    This catches content hidden in any PDF structure:
    - Hidden layers (OCG) that aren't properly enumerated
    - Embedded content not using standard APIs
    - Orphaned or unreferenced content
    - 0x0 embedded images with text
    - Any other sneaky hiding places
    
    Security invariant: If bytes exist in the PDF, we will find them.
    """
    corpus.surfaces_extracted.append("all_streams")
    
    seen_texts: Set[str] = set()  # Deduplicate
    
    for xref in range(1, doc.xref_length()):
        try:
            # Get the object dictionary first to check type
            obj_str = doc.xref_object(xref, compressed=False)
            if not obj_str:
                continue
            
            # Check if this is an image XObject with 0x0 dimensions
            is_zero_size_image = False
            if "/Subtype /Image" in obj_str or "/Subtype/Image" in obj_str:
                import re
                width_match = re.search(r"/Width\s+(\d+)", obj_str)
                height_match = re.search(r"/Height\s+(\d+)", obj_str)
                if width_match and height_match:
                    width = int(width_match.group(1))
                    height = int(height_match.group(1))
                    if width == 0 or height == 0:
                        is_zero_size_image = True
            
            # Get the raw stream bytes
            stream = doc.xref_stream(xref)
            if not stream:
                # Still check object dictionary for inline strings even if no stream
                try:
                    import re
                    # Extract parenthesized strings from PDF object
                    paren_strings = re.findall(r"\(([^)]{2,})\)", obj_str)
                    for s in paren_strings:
                        unescaped = _unescape_pdf_string(s)
                        if unescaped and len(unescaped) >= 3:
                            normalized = " ".join(unescaped.split())
                            if normalized and normalized not in seen_texts:
                                seen_texts.add(normalized)
                                source = "embedded" if is_zero_size_image else "raw_stream"
                                corpus.fragments.append(TextFragment(
                                    text=normalized,
                                    source=source,
                                    location=f"xref:{xref}",
                                ))
                except Exception:
                    pass
                continue
            
            # Try multiple decodings
            texts_found = []
            
            # For Form XObjects and 0x0 images, extract text from content stream
            if "/Subtype /Form" in obj_str or "/Subtype/Form" in obj_str or is_zero_size_image:
                try:
                    text = stream.decode("utf-8", errors="ignore")
                    extracted = _extract_text_from_content_stream(text)
                    if extracted:
                        texts_found.append(extracted)
                except Exception:
                    pass
            
            # UTF-8 decode
            try:
                text = stream.decode("utf-8", errors="ignore")
                if text:
                    texts_found.append(text)
            except Exception:
                pass
            
            # Latin-1 decode (catches more byte sequences)
            try:
                text = stream.decode("latin-1", errors="ignore")
                if text:
                    texts_found.append(text)
            except Exception:
                pass
            
            # Extract readable ASCII strings from binary
            # CRITICAL: Use lower min_length to catch shorter sensitive strings
            # Some sensitive data might be short (e.g., "SSN", "456-B-987")
            readable = _extract_strings_from_binary(stream, min_length=3)
            if readable:
                texts_found.append(readable)
            
            # Also check the object dictionary for inline strings
            try:
                import re
                # Extract parenthesized strings from PDF object
                paren_strings = re.findall(r"\(([^)]{2,})\)", obj_str)
                for s in paren_strings:
                    unescaped = _unescape_pdf_string(s)
                    if unescaped and len(unescaped) >= 3:
                        texts_found.append(unescaped)
            except Exception:
                pass
            
            # Add unique text fragments
            # CRITICAL: All extracted text must be checked against denylist
            # No source is exempt - raw_stream, embedded, etc. all must be verified
            for text in texts_found:
                if not text:
                    continue
                
                # Normalize whitespace but preserve the text for matching
                # Don't over-normalize - we need to match denylist patterns
                normalized = " ".join(text.split())
                
                # Only filter by minimum length, not by source type
                # Even very short fragments might contain sensitive data when combined
                if normalized and len(normalized) >= 3:
                    # Check if we've seen this exact text before (deduplication)
                    if normalized not in seen_texts:
                        seen_texts.add(normalized)
                        source = "embedded" if is_zero_size_image else "raw_stream"
                        corpus.fragments.append(TextFragment(
                            text=normalized,
                            source=source,
                            location=f"xref:{xref}",
                        ))
                    
        except Exception:
            continue


def _extract_ocr(doc: fitz.Document, corpus: Corpus) -> None:
    """
    Perform OCR on page images to extract text.
    
    This catches:
    - Visual-only / rasterized text
    - Text with custom font encodings that don't extract as searchable text
    
    Requires: pytesseract, Pillow, and Tesseract OCR binary installed.
    """
    corpus.surfaces_extracted.append("ocr")

    try:
        import pytesseract
        from PIL import Image
        import io
    except ImportError:
        import sys
        print(
            "WARNING: OCR requested but pytesseract/Pillow not installed. "
            "Install with: pip install pytesseract Pillow",
            file=sys.stderr
        )
        return
    
    # Try default Windows installation paths if not on PATH
    import shutil
    if not shutil.which("tesseract"):
        default_paths = [
            r"C:\Program Files\Tesseract-OCR\tesseract.exe",
            r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        ]
        for path in default_paths:
            if Path(path).exists():
                pytesseract.pytesseract.tesseract_cmd = path
                break
    
    # Verify Tesseract is available
    try:
        pytesseract.get_tesseract_version()
    except Exception:
        import sys
        print(
            "WARNING: Tesseract OCR not found. "
            "Install from: https://github.com/UB-Mannheim/tesseract/wiki",
            file=sys.stderr
        )
        return

    corpus.ocr_performed = True
    
    # Enable all layers before rendering
    try:
        layer_config = doc.layer_ui_configs()
        if layer_config:
            for layer in layer_config:
                layer_num = layer.get("number", 0)
                doc.set_layer_ui_config(layer_num, on=True)
    except Exception:
        pass

    for page_num, page in enumerate(doc):
        # Render page to image at high resolution for better OCR
        mat = fitz.Matrix(2.0, 2.0)  # 2x zoom
        pix = page.get_pixmap(matrix=mat)

        # Convert to PIL Image
        img_data = pix.tobytes("png")
        img = Image.open(io.BytesIO(img_data))

        # Run OCR
        try:
            ocr_text = pytesseract.image_to_string(img)
            if ocr_text and ocr_text.strip():
                corpus.fragments.append(TextFragment(
                    text=ocr_text.strip(),
                    source="ocr",
                    page=page_num,
                ))
        except Exception:
            # OCR failed for this page, continue
            pass

