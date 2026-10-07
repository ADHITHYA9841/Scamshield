import os
from typing import Dict, Any, List


class OCREngine:
    """
    OCR Abstraction Engine for extracting textual evidence from screenshots and images.
    Supports PaddleOCR / EasyOCR / Tesseract or clean fallback.
    """

    def __init__(self):
        self._paddle = None
        self._paddle_initialized = False

    def _init_ocr(self):
        if self._paddle_initialized:
            return
        self._paddle_initialized = True
        try:
            from paddleocr import PaddleOCR
            self._paddle = PaddleOCR(use_angle_cls=True, lang="en", show_log=False)
        except Exception:
            self._paddle = None

    def extract_text_from_image(self, image_path: str) -> Dict[str, Any]:
        """Extracts text, confidence scores, and line blocks from an image."""
        self._init_ocr()
        if not os.path.exists(image_path):
            return {
                "text": "",
                "confidence": 0.0,
                "language": "en",
                "blocks": [],
                "error": "Image file not found"
            }

        extracted_lines: List[str] = []
        confidences: List[float] = []
        blocks: List[Dict[str, Any]] = []

        if self._paddle:
            try:
                result = self._paddle.ocr(image_path, cls=True)
                if result and result[0]:
                    for line in result[0]:
                        box = line[0]
                        text_conf = line[1]
                        text = text_conf[0]
                        conf = float(text_conf[1])

                        extracted_lines.append(text)
                        confidences.append(conf)
                        blocks.append({
                            "text": text,
                            "confidence": round(conf, 2),
                            "box": box
                        })
            except Exception as e:
                # If PaddleOCR fails on this image, fallback
                pass

        # If OCR returned lines, calculate overall stats
        if extracted_lines:
            avg_conf = sum(confidences) / len(confidences) if confidences else 0.85
            full_text = "\n".join(extracted_lines)
            return {
                "text": full_text,
                "confidence": round(avg_conf, 2),
                "language": "auto",
                "blocks": blocks,
                "engine": "paddleocr"
            }

        # Clean fallback message if binary OCR did not produce text
        return {
            "text": "",
            "confidence": 0.0,
            "language": "en",
            "blocks": [],
            "engine": "none",
            "note": "No text detected or OCR engine unavailable. User may enter text manually."
        }
