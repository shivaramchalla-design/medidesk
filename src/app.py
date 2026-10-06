"""MediDesk prototype. Synthetic data only. Run: python app.py -> http://127.0.0.1:5000"""
import os, secrets, hashlib
from datetime import datetime, timedelta, date
from functools import wraps
from dotenv import load_dotenv

# First run: generate secrets into .env (never committed). Secrets are not hard-coded.
if not os.path.exists(".env") or "SECRET_KEY" not in open(".env").read():
    from cryptography.fernet import Fernet as _F
    with open(".env", "a") as f:
        f.write(f"SECRET_KEY={secrets.token_hex(32)}\nFERNET_KEY={_F.generate_key().decode()}\n")
load_dotenv()

from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from markupsafe import Markup

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ["SECRET_KEY"],
    SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///medidesk.db"),
    SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=20),  # idle timeout
)
db = SQLAlchemy(app)
csrf = CSRFProtect(app)                                   # CSRF token on every POST
limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")
Talisman(app, force_https=False, session_cookie_secure=False)  # CSP + security headers (HTTPS off for localhost only)
lm = LoginManager(app); lm.login_view = "login"; lm.session_protection = "strong"
ph = PasswordHasher(); DUMMY = ph.hash("timing-equalizer")
fer = Fernet(os.environ["FERNET_KEY"].encode())           # record text encrypted at rest
app.jinja_env.globals["csrf_field"] = lambda: Markup(f'<input type="hidden" name="csrf_token" value="{generate_csrf()}">')
SLOTS = ["09:00", "10:00", "11:00", "14:00", "15:00", "16:00"]

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(10), nullable=False)   # set by server only, never from a form
    name = db.Column(db.String(80)); email = db.Column(db.String(120), unique=True)
    pw = db.Column(db.String(200)); spec = db.Column(db.String(60))
    age = db.Column(db.Integer); phone = db.Column(db.String(20))
    active = db.Column(db.Boolean, default=True)
    failed = db.Column(db.Integer, default=0); locked_until = db.Column(db.DateTime)

class Appt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    date = db.Column(db.String(10)); time = db.Column(db.String(5)); reason = db.Column(db.String(120))
    status = db.Column(db.String(12), default="pending"); note = db.Column(db.String(300), default="")
    patient = db.relationship("User", foreign_keys=[patient_id]); doctor = db.relationship("User", foreign_keys=[doctor_id])

class Record(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("users.id")); doctor_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    date = db.Column(db.String(10)); title = db.Column(db.String(80)); enc = db.Column(db.Text)
    doctor = db.relationship("User", foreign_keys=[doctor_id])
    @property
    def body(self): return fer.decrypt(self.enc.encode()).decode()

class Consent(db.Model):  # patient grants a doctor time-limited access to records
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("users.id")); doctor_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    expires = db.Column(db.DateTime); doctor = db.relationship("User", foreign_keys=[doctor_id])

class Audit(db.Model):  # hash-chained: editing any row breaks every later hash
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.String(25)); actor = db.Column(db.Integer); action = db.Column(db.String(40))
    target = db.Column(db.String(60)); prev = db.Column(db.String(64)); hash = db.Column(db.String(64))

def _h(prev, ts, actor, action, target): return hashlib.sha256(f"{prev}|{ts}|{actor}|{action}|{target}".encode()).hexdigest()
def audit(action, target="", actor=None):
    last = Audit.query.order_by(Audit.id.desc()).first(); prev = last.hash if last else "0" * 64
    ts = datetime.utcnow().replace(microsecond=0).isoformat()
    aid = actor if actor is not None else (current_user.id if current_user.is_authenticated else None)
    db.session.add(Audit(ts=ts, actor=aid, action=action, target=target, prev=prev, hash=_h(prev, ts, aid, action, target)))
def chain_ok():
    prev = "0" * 64
    for a in Audit.query.order_by(Audit.id).all():
        if a.prev != prev or a.hash != _h(a.prev, a.ts, a.actor, a.action, a.target): return False
        prev = a.hash
    return True

@lm.user_loader
def load_user(uid):
    u = db.session.get(User, int(uid)); return u if u and u.active else None

def role(*roles):  # single place where role-based access is enforced
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if current_user.role not in roles: abort(403)
            return f(*a, **k)
        return login_required(w)
    return deco

def consent_for(did, pid):
    return Consent.query.filter(Consent.doctor_id == did, Consent.patient_id == pid, Consent.expires > datetime.utcnow()).first()

@app.after_request
def nocache(r): r.headers["Cache-Control"] = "no-store"; return r
@app.errorhandler(403)
def e403(e): return "Forbidden: you do not have access to this.", 403
@app.errorhandler(404)
def e404(e): return "Not found.", 404
@app.errorhandler(500)
def e500(e): return "Something went wrong.", 500   # no stack traces to users

# ---------- auth ----------
@app.route("/")
@login_required
def home():
    return redirect(url_for({"patient": "patient_home", "doctor": "doctor_home", "admin": "admin_home"}[current_user.role]))

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10/minute", methods=["POST"])
def login():
    if request.method == "POST":
        e = request.form.get("email", "").strip().lower(); p = request.form.get("password", "")
        u = User.query.filter_by(email=e).first()
        if u and u.locked_until and u.locked_until > datetime.utcnow():
            audit("login_blocked_locked", e); db.session.commit()
            flash("Account temporarily locked. Try again in a few minutes."); return render_template("auth.html", mode="login")
        ok = False
        try: ph.verify(u.pw if u else DUMMY, p); ok = bool(u)   # always hashes: no user-enumeration timing gap
        except VerifyMismatchError: pass
        if ok and u.active:
            u.failed = 0; login_user(u); from flask import session; session.permanent = True
            audit("login", f"user:{u.id}", actor=u.id); db.session.commit(); return redirect(url_for("home"))
        if u:
            u.failed += 1
            if u.failed >= 5: u.locked_until = datetime.utcnow() + timedelta(minutes=5); u.failed = 0
        audit("login_failed", e[:60]); db.session.commit()
        flash("Email or password is incorrect.")   # same message either way
    return render_template("auth.html", mode="login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        n = request.form.get("name", "").strip(); e = request.form.get("email", "").strip().lower(); p = request.form.get("password", "")
        if not (2 <= len(n) <= 80 and "@" in e and len(e) <= 120 and len(p) >= 8): flash("Enter a name, a valid email and a password of 8+ characters.")
        elif User.query.filter_by(email=e).first(): flash("That email is already registered.")
        else:
            u = User(role="patient", name=n, email=e, pw=ph.hash(p)); db.session.add(u); db.session.flush()
            audit("register", f"user:{u.id}", actor=u.id); db.session.commit(); flash("Account created. Sign in."); return redirect(url_for("login"))
    return render_template("auth.html", mode="register")

@app.route("/logout", methods=["POST"])
@login_required
def logout(): audit("logout"); db.session.commit(); logout_user(); return redirect(url_for("login"))

# ---------- patient ----------
@app.route("/patient")
@role("patient")
def patient_home():
    l = Appt.query.filter_by(patient_id=current_user.id).order_by(Appt.date.desc(), Appt.time.desc()).all()
    return render_template("appts.html", appts=l, title="My appointments and history")

@app.route("/book", methods=["GET", "POST"])
@role("patient")
def book():
    docs = User.query.filter_by(role="doctor", active=True).all()
    if request.method == "POST":
        try:
            d = User.query.filter_by(id=int(request.form["doctor"]), role="doctor", active=True).first_or_404()
            day = date.fromisoformat(request.form["date"]); t = request.form["time"]; r = request.form.get("reason", "").strip()
        except (KeyError, ValueError): abort(400)
        if day < date.today() or t not in SLOTS or not 3 <= len(r) <= 120: flash("Check the date, time and reason.")
        elif Appt.query.filter(Appt.doctor_id == d.id, Appt.date == day.isoformat(), Appt.time == t, Appt.status != "cancelled").first(): flash("That slot is taken.")
        else:
            a = Appt(patient_id=current_user.id, doctor_id=d.id, date=day.isoformat(), time=t, reason=r); db.session.add(a); db.session.flush()
            audit("book", f"appt:{a.id}"); db.session.commit(); flash("Appointment requested."); return redirect(url_for("patient_home"))
    return render_template("book.html", docs=docs, slots=SLOTS, today=date.today().isoformat())

@app.route("/cancel/<int:aid>", methods=["POST"])
@role("patient", "admin")
def cancel(aid):
    q = Appt.query.filter_by(id=aid)
    if current_user.role == "patient": q = q.filter_by(patient_id=current_user.id)   # ownership check (blocks IDOR)
    a = q.first_or_404(); a.status = "cancelled"; audit("cancel", f"appt:{a.id}"); db.session.commit()
    return redirect(url_for("home"))

@app.route("/records")
@role("patient")
def my_records():
    return render_template("records.html", recs=Record.query.filter_by(patient_id=current_user.id).order_by(Record.date.desc()).all())

@app.route("/privacy", methods=["GET", "POST"])
@role("patient")
def privacy():
    if request.method == "POST":
        try:
            d = User.query.filter_by(id=int(request.form["doctor"]), role="doctor", active=True).first_or_404(); days = int(request.form["days"])
        except (KeyError, ValueError): abort(400)
        if not 1 <= days <= 30: abort(400)
        db.session.add(Consent(patient_id=current_user.id, doctor_id=d.id, expires=datetime.utcnow() + timedelta(days=days)))
        audit("consent_grant", f"patient:{current_user.id}"); db.session.commit(); flash("Access granted."); return redirect(url_for("privacy"))
    cons = Consent.query.filter(Consent.patient_id == current_user.id, Consent.expires > datetime.utcnow()).all()
    log = Audit.query.filter(Audit.target == f"patient:{current_user.id}").order_by(Audit.id.desc()).limit(50).all()
    names = {u.id: u.name for u in User.query.all()}
    return render_template("privacy.html", docs=User.query.filter_by(role="doctor", active=True).all(), cons=cons, log=log, names=names)

@app.route("/consent/<int:cid>/revoke", methods=["POST"])
@role("patient")
def revoke(cid):
    c = Consent.query.filter_by(id=cid, patient_id=current_user.id).first_or_404(); db.session.delete(c)
    audit("consent_revoke", f"patient:{current_user.id}"); db.session.commit(); return redirect(url_for("privacy"))

@app.route("/profile", methods=["GET", "POST"])
@role("patient")
def profile():
    if request.method == "POST":
        n = request.form.get("name", "").strip(); ph_ = request.form.get("phone", "").strip()[:20]
        try: age = int(request.form.get("age") or 0)
        except ValueError: abort(400)
        if not (2 <= len(n) <= 80 and 0 <= age <= 120): flash("Check name and age.")
        else: current_user.name, current_user.age, current_user.phone = n, age, ph_; audit("profile_update"); db.session.commit(); flash("Profile saved.")
    return render_template("profile.html")

# ---------- doctor ----------
@app.route("/doctor")
@role("doctor")
def doctor_home():
    l = Appt.query.filter_by(doctor_id=current_user.id).order_by(Appt.date, Appt.time).all()
    return render_template("appts.html", appts=l, title="My schedule")

@app.route("/appt/<int:aid>/status", methods=["POST"])
@role("doctor")
def set_status(aid):
    a = Appt.query.filter_by(id=aid, doctor_id=current_user.id).first_or_404(); to = request.form.get("to")
    ok = {"pending": ("confirmed", "cancelled"), "confirmed": ("completed", "cancelled")}
    if to not in ok.get(a.status, ()): abort(400)
    if to == "completed":
        note = request.form.get("note", "").strip()[:300]
        if not note: flash("Add a visit note to complete."); return redirect(url_for("doctor_home"))
        a.note = note; db.session.add(Record(patient_id=a.patient_id, doctor_id=current_user.id, date=a.date, title=a.reason[:80], enc=fer.encrypt(note.encode()).decode()))
    a.status = to; audit("appt_" + to, f"appt:{a.id}"); db.session.commit(); return redirect(url_for("doctor_home"))

@app.route("/doctor/patients")
@role("doctor")
def doctor_patients():
    ids = {a.patient_id for a in Appt.query.filter_by(doctor_id=current_user.id)}
    rows = [(p, consent_for(current_user.id, p.id)) for p in User.query.filter(User.id.in_(ids)).all()] if ids else []
    return render_template("patients.html", rows=rows)

@app.route("/doctor/patient/<int:pid>", methods=["GET", "POST"])
@role("doctor")
def patient_detail(pid):
    p = User.query.filter_by(id=pid, role="patient").first_or_404()
    if not consent_for(current_user.id, pid):   # no consent, no access; attempt is logged
        audit("access_denied", f"patient:{pid}"); db.session.commit(); abort(403)
    if request.method == "POST":
        t = request.form.get("title", "").strip()[:80]; x = request.form.get("text", "").strip()[:500]
        if t and x: db.session.add(Record(patient_id=pid, doctor_id=current_user.id, date=date.today().isoformat(), title=t, enc=fer.encrypt(x.encode()).decode())); audit("record_add", f"patient:{pid}"); db.session.commit()
        return redirect(url_for("patient_detail", pid=pid))
    audit("view_record", f"patient:{pid}"); db.session.commit()
    return render_template("patient_detail.html", p=p, recs=Record.query.filter_by(patient_id=pid).order_by(Record.date.desc()).all())

# ---------- admin (no access to record contents) ----------
@app.route("/admin", methods=["GET", "POST"])
@role("admin")
def admin_home():
    if request.method == "POST":
        n, s, e, p = (request.form.get(k, "").strip() for k in ("name", "spec", "email", "password"))
        if not (n and s and "@" in e and len(p) >= 8): flash("Fill every field; password needs 8+ characters.")
        elif User.query.filter_by(email=e.lower()).first(): flash("Email already in use.")
        else: db.session.add(User(role="doctor", name=n, spec=s, email=e.lower(), pw=ph.hash(p))); audit("doctor_add", e.lower()); db.session.commit(); flash("Doctor added.")
    return render_template("admin.html", users=User.query.filter(User.role != "admin").order_by(User.role, User.name).all())

@app.route("/admin/user/<int:uid>/toggle", methods=["POST"])
@role("admin")
def toggle(uid):
    u = User.query.filter(User.id == uid, User.role != "admin").first_or_404(); u.active = not u.active
    audit("user_toggle", f"user:{u.id}"); db.session.commit(); return redirect(url_for("admin_home"))

@app.route("/admin/appointments")
@role("admin")
def admin_appts():
    return render_template("appts.html", appts=Appt.query.order_by(Appt.date.desc()).all(), title="All appointments")

@app.route("/admin/audit")
@role("admin")
def admin_audit():
    return render_template("audit.html", log=Audit.query.order_by(Audit.id.desc()).limit(100).all(), ok=chain_ok(),
                           names={u.id: u.name for u in User.query.all()})

def init():
    db.create_all()
    if User.query.first(): return
    def mk(r, n, e, p, **k): u = User(role=r, name=n, email=e, pw=ph.hash(p), **k); db.session.add(u); return u
    mk("admin", "Admin Demo", "admin@medidesk.test", "Admin#Demo2026")
    d1 = mk("doctor", "Dr. Anika Rao", "rao@medidesk.test", "Doctor#Demo2026", spec="General Medicine")
    d2 = mk("doctor", "Dr. Marcus Lee", "lee@medidesk.test", "Doctor#Demo2026", spec="Cardiology")
    p1 = mk("patient", "Jordan Sample", "jordan@test.dev", "Patient#Demo2026", age=34, phone="555-0101")
    p2 = mk("patient", "Riya Testwell", "riya@test.dev", "Patient#Demo2026", age=27, phone="555-0102"); db.session.flush()
    iso = lambda n: (date.today() + timedelta(days=n)).isoformat()
    db.session.add_all([
        Appt(patient_id=p1.id, doctor_id=d1.id, date=iso(-30), time="10:00", reason="Annual check-up", status="completed", note="Vitals normal."),
        Appt(patient_id=p1.id, doctor_id=d2.id, date=iso(2), time="10:00", reason="Follow-up", status="confirmed"),
        Appt(patient_id=p2.id, doctor_id=d1.id, date=iso(1), time="09:00", reason="Flu symptoms"),
        Record(patient_id=p1.id, doctor_id=d1.id, date=iso(-30), title="Annual check-up", enc=fer.encrypt(b"BP 118/76. Advised regular exercise (dummy).").decode()),
        Consent(patient_id=p1.id, doctor_id=d1.id, expires=datetime.utcnow() + timedelta(days=7))])
    db.session.commit()

with app.app_context(): init()
if __name__ == "__main__": app.run(host="127.0.0.1", port=5000, debug=False)
