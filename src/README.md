# MediDesk (prototype)
Clinic and appointment management with a security-first design. Synthetic data only.

## Run locally
```
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py        # http://127.0.0.1:5000
pytest               # security tests
```
First run creates `.env` (random secrets) and `medidesk.db` with demo data. Delete both to reset.

## Demo accounts
Patient jordan@test.dev / Patient#Demo2026. Doctor rao@medidesk.test (has consent from Jordan) or lee@medidesk.test (no consent) / Doctor#Demo2026. Admin admin@medidesk.test / Admin#Demo2026.

## Features
Patient register/login/profile, booking, cancel, history, records, consent and access log. Doctor schedule, confirm/complete with notes, consent-gated patient records. Admin user management, all appointments, tamper-evident audit log.
