import os
import re
import email
from email import policy
from typing import Dict, Any, List, Tuple
from bs4 import BeautifulSoup
import fitz  # PyMuPDF
import docx
from app.models.schemas import EvidenceItem


class FileEngine:
    """
    Safe file parser for PDF, DOCX, TXT, EML, and HTML files.
    Extracts text, hyperlinks, and structural metadata without executing macros or scripts.
    """

    SUPPORTED_EXTENSIONS = {".pdf", ".docx", ".txt", ".eml", ".html", ".htm", ".png", ".jpg", ".jpeg"}

    def parse_pdf(self, file_path: str) -> Dict[str, Any]:
        """Extract text, links, and metadata from PDF files page-by-page."""
        doc = fitz.open(file_path)
        pages_text = []
        links = []
        total_pages = len(doc)

        for page_num in range(total_pages):
            page = doc[page_num]
            text = page.get_text("text")
            pages_text.append({"page": page_num + 1, "text": text})

            # Extract embedded links
            page_links = page.get_links()
            for link in page_links:
                uri = link.get("uri")
                if uri:
                    links.append({"page": page_num + 1, "url": uri})

        metadata = doc.metadata or {}
        doc.close()

        full_text = "\n\n".join([f"[Page {p['page']}]\n{p['text']}" for p in pages_text])

        return {
            "type": "pdf",
            "total_pages": total_pages,
            "full_text": full_text,
            "pages": pages_text,
            "links": links,
            "metadata": {
                "title": metadata.get("title"),
                "author": metadata.get("author"),
                "creator": metadata.get("creator"),
                "producer": metadata.get("producer")
            }
        }

    def parse_docx(self, file_path: str) -> Dict[str, Any]:
        """Extract paragraphs, tables, and hyperlinks from DOCX files."""
        doc = docx.Document(file_path)
        paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]

        table_data = []
        for table in doc.tables:
            for row in table.rows:
                row_text = [cell.text.strip() for cell in row.cells if cell.text.strip()]
                if row_text:
                    table_data.append(" | ".join(row_text))

        full_text = "\n".join(paragraphs + table_data)

        # Extract URLs via regex
        urls = re.findall(r'https?://[^\s<>"]+', full_text)

        return {
            "type": "docx",
            "full_text": full_text,
            "paragraphs_count": len(paragraphs),
            "tables_count": len(doc.tables),
            "links": [{"url": u} for u in urls],
            "metadata": {
                "author": doc.core_properties.author,
                "title": doc.core_properties.title,
                "last_modified_by": doc.core_properties.last_modified_by
            }
        }

    def parse_eml(self, file_path: str) -> Dict[str, Any]:
        """Parse raw EML email messages into structured components."""
        with open(file_path, "rb") as f:
            msg = email.message_from_binary_file(f, policy=policy.default)

        sender = str(msg.get("From", ""))
        to_addr = str(msg.get("To", ""))
        subject = str(msg.get("Subject", ""))
        date = str(msg.get("Date", ""))
        reply_to = str(msg.get("Reply-To", ""))

        body_text = ""
        html_body = ""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                if "attachment" in content_disposition:
                    attachments.append(part.get_filename())
                elif content_type == "text/plain":
                    body_text += part.get_payload(decode=True).decode(errors="replace")
                elif content_type == "text/html":
                    html_body += part.get_payload(decode=True).decode(errors="replace")
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body_text = payload.decode(errors="replace")

        # If plain text body is empty, extract text from HTML body
        if not body_text.strip() and html_body:
            soup = BeautifulSoup(html_body, "html.parser")
            body_text = soup.get_text(separator="\n")

        full_content = f"From: {sender}\nTo: {to_addr}\nSubject: {subject}\nDate: {date}\n\n{body_text}"
        urls = re.findall(r'https?://[^\s<>"]+', full_content)

        # Check for sender mismatch (e.g. display name says "State Bank of India" but domain is @gmail.com)
        sender_spoofed = False
        if any(b in sender.lower() for b in ["sbi", "hdfc", "bank", "police", "income tax", "support"]):
            if any(free in sender.lower() for free in ["@gmail.com", "@yahoo.com", "@hotmail.com", "@outlook.com"]):
                sender_spoofed = True

        return {
            "type": "eml",
            "from": sender,
            "to": to_addr,
            "subject": subject,
            "date": date,
            "reply_to": reply_to,
            "sender_spoofed": sender_spoofed,
            "full_text": full_content,
            "attachments": [a for a in attachments if a],
            "links": [{"url": u} for u in urls]
        }

    def parse_html(self, file_path_or_content: str, is_content: bool = False) -> Dict[str, Any]:
        """Safely parse HTML document or content string."""
        if is_content:
            raw_html = file_path_or_content
        else:
            with open(file_path_or_content, "r", encoding="utf-8", errors="replace") as f:
                raw_html = f.read()

        soup = BeautifulSoup(raw_html, "html.parser")

        # Strip scripts, styles, objects, and iframes
        for tag in soup(["script", "style", "noscript", "object", "iframe", "embed"]):
            tag.decompose()

        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        visible_text = soup.get_text(separator="\n")
        # Clean excessive newlines
        visible_text = re.sub(r'\n+', '\n', visible_text).strip()

        # Extract links with anchor texts
        links = []
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"].strip()
            anchor_text = a_tag.get_text().strip()
            links.append({"url": href, "visible_text": anchor_text})

        # Check for input forms asking for credentials
        has_password_field = bool(soup.find("input", {"type": re.compile(r"password", re.I)}))
        has_otp_field = bool(soup.find("input", {"name": re.compile(r"otp|pin|cvv", re.I)}))

        return {
            "type": "html",
            "title": title,
            "full_text": f"Title: {title}\n\n{visible_text}",
            "links": links,
            "has_password_field": has_password_field,
            "has_otp_field": has_otp_field
        }

    def parse_txt(self, file_path: str) -> Dict[str, Any]:
        """Parse plain text document."""
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()

        urls = re.findall(r'https?://[^\s<>"]+', text)
        return {
            "type": "txt",
            "full_text": text,
            "links": [{"url": u} for u in urls]
        }
