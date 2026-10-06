# Security notes
**Defended:** argon2 password hashing; lockout (5 failures) + rate limit; same error for bad email or password; CSRF tokens; Jinja auto-escaping and CSP (XSS); ORM parameterized queries (SQLi); role checks in one decorator plus per-object ownership checks (IDOR); consent-gated doctor access to records; record text encrypted at rest (Fernet); admins cannot read records; hash-chained audit log, visible to patients for their own data; 20 min idle session timeout, HttpOnly + SameSite cookies; no stack traces; secrets in `.env`, never in code.

**Known limits (prototype):** no 2FA; no HTTPS on localhost (set `force_https=True` and secure cookies when deployed); SQLite file not encrypted; slot double-booking is checked in code, not by a DB constraint; no break-glass emergency access; no password reset; dependency versions should be re-checked with `pip-audit`.

**Tests:** `pytest` covers auth redirect, role escalation, IDOR, SQL injection, consent enforcement, lockout and audit-chain tampering.

## Added in update 2
Multi-clinic doctors with fees and a comparison page; triage priority (emergency/urgent/routine) with server-side red-flag escalation and emergency-only reserved slots; doctor's "Today" queue sorted by priority (own patients only, symptoms never shown to admins); symptom-to-specialist guide (guidance only); break-glass emergency access (treating doctor only, reason required, 1 hour, logged in the hash-chained audit log and visible to the patient); admin security dashboard with a rule-based suspicious-access flag (one doctor opening 3+ patients). New tests cover break-glass, emergency-slot abuse, red flags, doctor-queue isolation and admin symptom privacy.
