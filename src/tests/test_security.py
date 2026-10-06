import os, sys, pytest
from datetime import date, timedelta
os.environ["DATABASE_URL"] = "sqlite://"
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import app as A

@pytest.fixture
def c():
    A.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False); A.limiter.enabled = False
    with A.app.app_context(): A.db.drop_all(); A.init()
    return A.app.test_client()

def login(c, e, p): return c.post("/login", data={"email": e, "password": p}, follow_redirects=True)
def uid(e):
    with A.app.app_context(): return A.User.query.filter_by(email=e).first().id
PAT, DOC, RAO = ("jordan@test.dev", "Patient#Demo2026"), ("lee@medidesk.test", "Doctor#Demo2026"), ("rao@medidesk.test", "Doctor#Demo2026")
day = lambda n: (date.today() + timedelta(days=n)).isoformat()

def test_unauthenticated_redirected(c): assert c.get("/patient").status_code == 302
def test_role_escalation_blocked(c): login(c, *PAT); assert c.get("/admin").status_code == 403 and c.get("/doctor/today").status_code == 403
def test_idor_cancel_other_patients_appt(c): login(c, "riya@test.dev", "Patient#Demo2026"); assert c.post("/cancel/1").status_code == 404
def test_sql_injection_login_fails(c): assert b"incorrect" in login(c, "' OR 1=1 --", "x").data
def test_doctor_needs_consent(c): login(c, *DOC); assert c.get(f"/doctor/patient/{uid(PAT[0])}").status_code == 403
def test_lockout_after_failures(c):
    for _ in range(5): login(c, PAT[0], "wrong")
    assert b"locked" in login(c, *PAT).data
def test_audit_chain_detects_tampering(c):
    login(c, *PAT)
    with A.app.app_context():
        assert A.chain_ok(); a = A.Audit.query.first(); a.action = "forged"; A.db.session.commit(); assert not A.chain_ok()
def test_break_glass_needs_reason_and_is_logged(c):
    login(c, *DOC); j = uid(PAT[0])
    c.post(f"/doctor/breakglass/{j}", data={"reason": "short"}); assert c.get(f"/doctor/patient/{j}").status_code == 403
    c.post(f"/doctor/breakglass/{j}", data={"reason": "Patient collapsed, need history"}); assert c.get(f"/doctor/patient/{j}").status_code == 200
    with A.app.app_context(): assert A.Audit.query.filter(A.Audit.action.like("break_glass%")).count() == 1
def test_routine_cannot_use_emergency_slot(c):
    login(c, *PAT); r = c.post("/book", data={"doctor": uid(RAO[0]), "date": day(3), "time": "17:00", "reason": "checkup", "priority": "routine"}, follow_redirects=True)
    assert b"Check the date" in r.data
def test_red_flag_symptoms_raise_priority(c):
    login(c, *PAT); c.post("/book", data={"doctor": uid(RAO[0]), "date": day(3), "time": "10:00", "reason": "pain", "priority": "routine", "symptoms": "severe chest pain"})
    with A.app.app_context(): assert A.Appt.query.filter_by(date=day(3)).first().priority == "emergency"
def test_doctor_today_shows_only_own_patients(c):
    login(c, *DOC); assert b"Chest tightness" not in c.get("/doctor/today").data
    c.post("/logout"); login(c, *RAO); t = c.get("/doctor/today").data; assert b"Chest tightness" in t and t.index(b"Chest tightness") < t.index(b"Back pain")
def test_admin_cannot_see_symptoms(c):
    login(c, "admin@medidesk.test", "Admin#Demo2026"); assert b"chest pain since morning" not in c.get("/admin/appointments").data
