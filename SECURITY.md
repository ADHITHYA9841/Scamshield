# Security Policy

## Reporting Vulnerabilities
If you discover a security vulnerability in ScamShield, please do NOT create a public issue.
Instead, report it responsibly to the project maintainers via email or private security advisory.

## Scope & Defenses
- **SSRF Defense**: Report any bypass in `validate_url_safety`.
- **Parser Sandboxing**: Report any parsing flaw that results in code execution from uploaded PDF, DOCX, or HTML files.
- **Prompt Injection**: Report techniques that successfully trick the LLM into bypassing all security flags.
