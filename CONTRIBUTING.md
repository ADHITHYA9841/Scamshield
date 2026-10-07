# Contributing to ScamShield

We welcome contributions to ScamShield!

## Guidelines
1. **Fork & Branch**: Create a feature branch (`git checkout -b feature/my-feature`).
2. **Coding Standards**:
   - Backend: Follow PEP8 and ensure type annotations with Pydantic.
   - Android: Follow official Kotlin style guides and Jetpack Compose best practices.
   - Extension: Strict Manifest V3 without inline scripts.
3. **Tests**: Always run pytest before opening a Pull Request:
   ```bash
   cd backend
   python -m pytest -v
   ```
4. **Security First**: Never commit private keys, real customer data, or hardcoded tokens.
