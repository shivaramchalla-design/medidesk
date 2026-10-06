# MediDesk: technical approach (PS-04)
**Problem:** secure clinic and appointment management with patient, doctor and admin roles, synthetic data only. Security is the main goal.
**Stack:** Python, Flask, SQLite (SQLAlchemy), Flask-Login, Flask-WTF (CSRF), Flask-Limiter, flask-talisman (CSP and headers), argon2, Fernet encryption, pytest. Server-rendered Jinja2 pages, no JS framework (smaller attack surface). Runs locally only; not deployed, as instructed.
**Flow:** browser -> Flask security layer (headers, CSRF, rate limit, login, role check) -> role routes -> SQLAlchemy ORM (parameterized) -> SQLite.
**Data model:** Clinic, User (patient/doctor/admin; doctors have clinic and fee), Appt (priority, symptoms), Record (encrypted text), Consent (time-limited), Audit (hash-chained).
**Security design:** role decorator plus per-object ownership checks (IDOR); consent-gated doctor access to records; admins cannot read records or symptoms; argon2, lockout, rate limiting; encrypted records at rest; hash-chained audit log, visible to patients for their own data; break-glass emergency access (reason, 1 hour, logged); security dashboard with suspicious-access flag.
**Features:** registration/login, profile, booking with triage priority and emergency slots, cancel, history, records, multi-clinic doctor comparison by fee and next free slot, symptom-to-specialist guide, doctor's priority queue, admin management.
**Tests:** 11 pytest tests (auth, role escalation, IDOR, SQL injection, consent, lockout, audit tamper, break-glass, emergency slots, red flags, queue isolation, admin privacy).
**Limits:** no 2FA, no HTTPS on localhost, no password reset, no reschedule, slot double-booking checked in code only. See docs/SECURITY.md.
