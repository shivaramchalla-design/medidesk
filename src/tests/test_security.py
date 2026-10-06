import os, sys, pytest
os.environ["DATABASE_URL"] = "sqlite://"
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import app as A

@pytest.fixture
def c():
    A.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False); A.limiter.enabled = False
    with A.app.app_context(): A.db.drop_all(); A.init()
    return A.app.test_client()

def login(c, e, p): return c.post("/login", data={"email": e, "password": p}, follow_redirects=True)
PAT, DOC = ("jordan@test.dev", "Patient#Demo2026"), ("lee@medidesk.test", "Doctor#Demo2026")

def test_unauthenticated_redirected(c): assert c.get("/patient").status_code == 302
def test_role_escalation_blocked(c): login(c, *PAT); assert c.get("/admin").status_code == 403 and c.get("/doctor").status_code == 403
def test_idor_cancel_other_patients_appt(c):
    login(c, "riya@test.dev", "Patient#Demo2026"); assert c.post("/cancel/1").status_code == 404   # appt 1 belongs to Jordan
def test_sql_injection_login_fails(c): assert b"incorrect" in login(c, "' OR 1=1 --", "x").data
def test_doctor_needs_consent(c): login(c, *DOC); assert c.get("/doctor/patient/4").status_code == 403   # Dr. Lee has no consent from Jordan
def test_lockout_after_failures(c):
    for _ in range(5): login(c, PAT[0], "wrong")
    assert b"locked" in login(c, *PAT).data
def test_audit_chain_detects_tampering(c):
    login(c, *PAT)
    with A.app.app_context():
        assert A.chain_ok(); a = A.Audit.query.first(); a.action = "forged"; A.db.session.commit(); assert not A.chain_ok()
