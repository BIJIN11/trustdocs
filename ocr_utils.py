# ocr_utils.py
import pytesseract
from PIL import Image

# =============================================================
# CONFIGURATION
# =============================================================
# IMPORTANT: Make sure this path matches your Tesseract installation
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

# =============================================================
# OCR FUNCTION
# =============================================================
def extract_text_from_file(file_stream):
    """
    Takes a file stream (from Flask), opens it as an image,
    and extracts text using Tesseract.
    """
    try:
        # Open image
        img = Image.open(file_stream)
        # Extract text
        text = pytesseract.image_to_string(img)
        return text
    except Exception as e:
        print(f"⚠️ OCR Error inside ocr_utils: {e}")
        return ""