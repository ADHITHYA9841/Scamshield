# ScamShield Development & Testing Guide

## 1. Prerequisites
- Python 3.11+
- Android Studio Iguana / Jellyfish (for Mobile App development) with Android SDK 34
- Google Chrome or Chromium browser (for Extension testing)
- Docker & Docker Compose (optional, for containerized deployment)

---

## 2. Backend Setup & Local Testing

```bash
# 1. Navigate to backend directory
cd backend

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run all pytest unit, integration, and security tests
python -m pytest -v

# 4. Run the comparative benchmark evaluation (350 samples)
python -m app.evaluation.runner

# 5. Start development API server
python main.py
```
API Documentation: `http://localhost:8000/docs`

---

## 3. Chrome Extension Testing
1. Open Chrome -> Go to `chrome://extensions/`.
2. Enable **Developer mode** toggle.
3. Click **Load unpacked** -> Select `extension/`.
4. Test with any live web page or sample phishing URL.

---

## 4. Android Mobile Testing
1. Open `mobile/` in Android Studio.
2. Sync Gradle files.
3. Run on Android Emulator (API 24+).
4. Configure backend to `http://10.0.2.2:8000` in Settings and tap "Test".
