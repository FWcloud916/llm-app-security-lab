"""Deterministically extract model-visible text from synthetic document fixtures."""

from __future__ import annotations

import platform
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from importlib.metadata import version
from io import BytesIO
from typing import Any

from pypdf import PdfReader

SUPPORTED_FORMATS = {"email", "html", "pdf"}
PDF_METADATA_FIELDS = {"author", "subject", "title"}
FORMAT_SUFFIXES = {"email": ".eml", "html": ".html", "pdf": ".pdf"}


class _HtmlBodyTextParser(HTMLParser):
    """Collect text nodes while excluding comments, scripts, and styles."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._excluded_depth = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        if tag in {"script", "style"}:
            self._excluded_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self._excluded_depth:
            self._excluded_depth -= 1

    def handle_data(self, data: str) -> None:
        stripped = data.strip()
        if self._excluded_depth == 0 and stripped:
            self.parts.append(stripped)


def validate_document_spec(spec: object) -> dict[str, Any]:
    """Validate one fail-closed document extractor declaration."""
    if not isinstance(spec, dict):
        raise ValueError("planned document must be an object")
    allowed = {"format", "include_attachment_filenames", "include_metadata", "path"}
    unknown = set(spec) - allowed
    if unknown:
        raise ValueError(f"planned document has unknown fields: {', '.join(sorted(unknown))}")

    path = spec.get("path")
    document_format = spec.get("format")
    if not isinstance(path, str) or not path:
        raise ValueError("planned document needs a fixture path")
    if document_format not in SUPPORTED_FORMATS:
        raise ValueError("planned document format must be email, html, or pdf")
    if not path.endswith(FORMAT_SUFFIXES[document_format]):
        raise ValueError("planned document path suffix does not match its format")

    include_filenames = spec.get("include_attachment_filenames", False)
    if not isinstance(include_filenames, bool):
        raise ValueError("include_attachment_filenames must be boolean")
    if include_filenames and document_format != "email":
        raise ValueError("attachment filenames are supported only for email documents")

    include_metadata = spec.get("include_metadata", [])
    if (
        not isinstance(include_metadata, list)
        or not all(isinstance(item, str) for item in include_metadata)
        or len(set(include_metadata)) != len(include_metadata)
    ):
        raise ValueError("include_metadata must be a unique list of field names")
    if include_metadata and document_format != "pdf":
        raise ValueError("metadata fields are supported only for PDF documents")
    unknown_metadata = set(include_metadata) - PDF_METADATA_FIELDS
    if unknown_metadata:
        raise ValueError(f"unsupported PDF metadata fields: {', '.join(sorted(unknown_metadata))}")
    return spec


def _extract_html(raw: bytes) -> tuple[str, dict[str, Any]]:
    parser = _HtmlBodyTextParser()
    parser.feed(raw.decode("utf-8"))
    parser.close()
    return "\n".join(parser.parts), {
        "name": "python-html.parser-body-text",
        "version": platform.python_version(),
        "comments_included": False,
        "script_and_style_included": False,
    }


def _extract_pdf(raw: bytes, metadata_fields: list[str]) -> tuple[str, dict[str, Any]]:
    reader = PdfReader(BytesIO(raw))
    parts = [text.strip() for page in reader.pages if (text := page.extract_text()).strip()]
    metadata = reader.metadata
    for field in metadata_fields:
        value = getattr(metadata, field, None) if metadata is not None else None
        if value:
            parts.append(f"[pdf_{field}]\n{value}")
    return "\n".join(parts), {
        "name": "pypdf.PdfReader",
        "version": version("pypdf"),
        "metadata_fields_included": metadata_fields,
        "text_extraction_mode": "plain",
    }


def _extract_email(raw: bytes, include_filenames: bool) -> tuple[str, dict[str, Any]]:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    body = message.get_body(preferencelist=("html", "plain"))
    if body is None:
        raise ValueError("synthetic email has no supported body")
    body_content = body.get_content()
    if not isinstance(body_content, str):
        raise TypeError("synthetic email body must decode to text")
    if body.get_content_type() == "text/html":
        text, _ = _extract_html(body_content.encode("utf-8"))
    else:
        text = body_content.strip()

    parts = [text] if text else []
    if include_filenames:
        filenames = [part.get_filename() for part in message.iter_attachments()]
        parts.extend(f"[attachment_filename]\n{name}" for name in filenames if name)
    return "\n".join(parts), {
        "name": "python-email+html.parser-body-text",
        "version": platform.python_version(),
        "attachment_filenames_included": include_filenames,
        "body_preference": ["html", "plain"],
    }


def extract_document(raw: bytes, raw_spec: object) -> tuple[str, dict[str, Any]]:
    """Extract text under the exact application policy declared by one scenario."""
    spec = validate_document_spec(raw_spec)
    document_format = spec["format"]
    if document_format == "html":
        return _extract_html(raw)
    if document_format == "pdf":
        return _extract_pdf(raw, spec.get("include_metadata", []))
    return _extract_email(raw, spec.get("include_attachment_filenames", False))
