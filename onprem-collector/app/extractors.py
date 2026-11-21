"""Real document & image text extractors for DOCX, XLSX, PDF, plain text, and OCR."""

from __future__ import annotations

import io
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from docx import Document
from openpyxl import load_workbook
from PIL import Image
from pypdf import PdfReader

try:
    import pytesseract
    from pytesseract import TesseractNotFoundError
except ImportError:  # pragma: no cover - pytesseract is in requirements.txt
    pytesseract = None  # type: ignore[assignment]

    class TesseractNotFoundError(Exception):
        """Fallback error when pytesseract is missing."""


PLAIN_TEXT_EXTENSIONS = frozenset({".csv", ".txt", ".json", ".xml", ".log"})
IMAGE_EXTENSIONS = frozenset({".jpg", ".jpeg", ".png", ".tiff", ".tif"})
SUPPORTED_EXTENSIONS = frozenset({".docx", ".xlsx", ".pdf", *PLAIN_TEXT_EXTENSIONS, *IMAGE_EXTENSIONS})


@dataclass
class ExtractedContent:
    """Normalized extraction result returned by extractors."""

    text: str
    file_type: str
    ocr_used: bool
    ocr_available: bool
    error: str | None = None


def is_tesseract_available() -> bool:
    """Check whether pytesseract and a usable tesseract binary are present."""
    if pytesseract is None:
        return False

    configured_cmd = getattr(pytesseract.pytesseract, "tesseract_cmd", "tesseract")
    if configured_cmd and configured_cmd != "tesseract":
        if Path(configured_cmd).is_file():
            return True
    if shutil.which("tesseract"):
        return True

    # Common Windows install location check only if tesseract_cmd was customized via env
    env_cmd = os.getenv("TESSERACT_CMD", "").strip()
    if env_cmd and Path(env_cmd).is_file():
        pytesseract.pytesseract.tesseract_cmd = env_cmd
        return True

    return False


def _decode_plain_text(raw_bytes: bytes) -> str:
    if not raw_bytes:
        return ""
    for encoding in ("utf-8-sig", "utf-8"):
        try:
            return raw_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw_bytes.decode("latin-1", errors="replace")


def _iter_docx_table_texts(tables: Iterable[Any]) -> list[str]:
    parts: list[str] = []
    for table in tables:
        for row in table.rows:
            row_cells: list[str] = []
            for cell in row.cells:
                cell_text = " ".join(p.text.strip() for p in cell.paragraphs if p.text.strip())
                if cell_text:
                    row_cells.append(cell_text)
                if cell.tables:
                    nested = _iter_docx_table_texts(cell.tables)
                    if nested:
                        row_cells.extend(nested)
            if row_cells:
                parts.append(" | ".join(row_cells))
    return parts


def _extract_docx(raw_bytes: bytes) -> str:
    doc = Document(io.BytesIO(raw_bytes))
    chunks: list[str] = []

    for section in doc.sections:
        for container in (section.header, section.footer):
            if container is not None:
                for p in container.paragraphs:
                    if p.text.strip():
                        chunks.append(p.text.strip())
                if container.tables:
                    chunks.extend(_iter_docx_table_texts(container.tables))

    for p in doc.paragraphs:
        if p.text.strip():
            chunks.append(p.text.strip())

    if doc.tables:
        chunks.extend(_iter_docx_table_texts(doc.tables))

    return "\n".join(chunks)


def _extract_xlsx(raw_bytes: bytes) -> str:
    wb = load_workbook(io.BytesIO(raw_bytes), read_only=True, data_only=True)
    chunks: list[str] = []
    try:
        for sheet_name in wb.sheetnames:
            ws = wb[sheet_name]
            chunks.append(f"[Sheet: {sheet_name}]")
            for row in ws.iter_rows(values_only=True):
                vals = [str(cell).strip() for cell in row if cell is not None and str(cell).strip() != ""]
                if vals:
                    chunks.append(" | ".join(vals))
    finally:
        wb.close()
    return "\n".join(chunks)


def _extract_pdf(raw_bytes: bytes) -> str:
    reader = PdfReader(io.BytesIO(raw_bytes))
    if reader.is_encrypted:
        try:
            decrypt_res = reader.decrypt("")
            if decrypt_res == 0:
                raise ValueError("PDF is password-protected and cannot be decrypted")
        except Exception as exc:
            raise ValueError(f"Encrypted PDF cannot be read: {exc}") from exc

    pages_text: list[str] = []
    for page in reader.pages:
        txt = page.extract_text() or ""
        if txt.strip():
            pages_text.append(txt.strip())
    return "\n".join(pages_text)


def _extract_image_ocr(raw_bytes: bytes, ocr_lang: str) -> tuple[str, bool, bool, str | None]:
    ocr_avail = is_tesseract_available()
    if not ocr_avail or pytesseract is None:
        return (
            "",
            False,
            False,
            "Tesseract OCR binary not installed on host; image text extraction skipped.",
        )

    try:
        with Image.open(io.BytesIO(raw_bytes)) as img:
            if img.mode not in ("RGB", "L"):
                img = img.convert("RGB")
            try:
                text = pytesseract.image_to_string(img, lang=ocr_lang)
            except pytesseract.TesseractError:
                # Retry with default English traineddata if Spanish pack is unavailable
                text = pytesseract.image_to_string(img, lang="eng")
        return text.strip(), True, True, None
    except TesseractNotFoundError as exc:
        return "", False, False, f"Tesseract OCR binary missing: {exc}"
    except Exception as exc:
        return "", False, ocr_avail, f"OCR extraction failed: {exc}"


def extract_text_from_bytes(
    raw_bytes: bytes,
    filename: str,
    ocr_lang: str = "spa+eng",
) -> ExtractedContent:
    """
    Extract text from supported office documents, PDFs, structured text files, and images.

    Gracefully returns diagnostic error metadata on missing OCR binaries or corrupt files.
    """
    ext = Path(filename).suffix.lower()
    file_type = ext.lstrip(".") or "unknown"
    ocr_avail = is_tesseract_available()

    if not raw_bytes:
        return ExtractedContent(
            text="",
            file_type=file_type,
            ocr_used=False,
            ocr_available=ocr_avail,
            error=None,
        )

    try:
        if ext in PLAIN_TEXT_EXTENSIONS:
            return ExtractedContent(
                text=_decode_plain_text(raw_bytes),
                file_type=file_type,
                ocr_used=False,
                ocr_available=ocr_avail,
                error=None,
            )

        if ext == ".docx":
            return ExtractedContent(
                text=_extract_docx(raw_bytes),
                file_type="docx",
                ocr_used=False,
                ocr_available=ocr_avail,
                error=None,
            )

        if ext == ".xlsx":
            return ExtractedContent(
                text=_extract_xlsx(raw_bytes),
                file_type="xlsx",
                ocr_used=False,
                ocr_available=ocr_avail,
                error=None,
            )

        if ext == ".pdf":
            return ExtractedContent(
                text=_extract_pdf(raw_bytes),
                file_type="pdf",
                ocr_used=False,
                ocr_available=ocr_avail,
                error=None,
            )

        if ext in IMAGE_EXTENSIONS:
            text, ocr_used, img_ocr_avail, err = _extract_image_ocr(raw_bytes, ocr_lang)
            return ExtractedContent(
                text=text,
                file_type=file_type,
                ocr_used=ocr_used,
                ocr_available=img_ocr_avail,
                error=err,
            )

        return ExtractedContent(
            text="",
            file_type=file_type,
            ocr_used=False,
            ocr_available=ocr_avail,
            error=f"Unsupported file extension '{ext}'",
        )
    except Exception as exc:
        return ExtractedContent(
            text="",
            file_type=file_type,
            ocr_used=False,
            ocr_available=ocr_avail,
            error=f"Extraction failed for {file_type}: {exc}",
        )


def extract_text_from_file(path: str | Path, ocr_lang: str = "spa+eng") -> ExtractedContent:
    """Read a local file and run extract_text_from_bytes."""
    file_path = Path(path)
    raw = file_path.read_bytes()
    return extract_text_from_bytes(raw, file_path.name, ocr_lang=ocr_lang)
