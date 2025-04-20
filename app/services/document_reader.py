from docx import Document
from PyPDF2 import PdfReader


def extract_text_from_pdf(file_path: str) -> str | None:
    try:
        reader = PdfReader(file_path)
        text: str = ""
        for page in reader.pages:
            extracted = page.extract_text()
            if extracted:
                text += extracted
        return text
    except Exception as e:
        print(f"Error reading PDF: {e}")
        return None


def extract_text_from_docx(file_path: str) -> str | None:
    try:
        document = Document(file_path)
        text: str = ""
        for paragraph in document.paragraphs:
            text += paragraph.text + "\n"
        return text.strip()
    except Exception as e:
        print(f"Error reading DOCX: {e}")
        return None
