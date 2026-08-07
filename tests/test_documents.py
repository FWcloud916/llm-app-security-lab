from __future__ import annotations

from base64 import b64decode

from llm_security_lab import lab

DAY_10 = "day-10-hidden-document-paths"
INJECTION = "DAY10_INJECTION_ACCEPTED"


def read(path: str, document_format: str, **options: object) -> dict[str, object]:
    return lab.read_document_fixture(
        {"path": path, "format": document_format, **options},
        DAY_10,
    )


def test_html_extractor_keeps_white_text_but_excludes_comments() -> None:
    white = read("documents/html-white-text.html", "html")
    comment = read("documents/html-comment.html", "html")

    assert INJECTION in white["content"]
    assert INJECTION not in comment["content"]
    assert INJECTION.encode() in b64decode(white["source_base64"])
    assert INJECTION.encode() in b64decode(comment["source_base64"])


def test_pdf_extractor_separates_page_text_from_metadata() -> None:
    white = read("documents/pdf-white-text.pdf", "pdf")
    metadata_body_only = read("documents/pdf-metadata.pdf", "pdf")
    metadata_included = read(
        "documents/pdf-metadata.pdf",
        "pdf",
        include_metadata=["subject"],
    )

    assert INJECTION in white["content"]
    assert INJECTION not in metadata_body_only["content"]
    assert INJECTION in metadata_included["content"]
    assert metadata_body_only["sha256"] == metadata_included["sha256"]
    assert metadata_body_only["extracted_sha256"] != metadata_included["extracted_sha256"]


def test_email_extractor_separates_body_from_attachment_filename() -> None:
    hidden_html = read("documents/email-hidden-html.eml", "email")
    filename_body_only = read("documents/email-attachment-filename.eml", "email")
    filename_included = read(
        "documents/email-attachment-filename.eml",
        "email",
        include_attachment_filenames=True,
    )

    assert INJECTION in hidden_html["content"]
    assert INJECTION not in filename_body_only["content"]
    assert INJECTION in filename_included["content"]
    assert filename_body_only["sha256"] == filename_included["sha256"]
    assert filename_body_only["extracted_sha256"] != filename_included["extracted_sha256"]
