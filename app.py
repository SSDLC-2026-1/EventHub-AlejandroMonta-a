#Modificado por David Lara y Alejandro Montaña

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hmac
from typing import List, Optional, Dict

from flask import Flask, render_template, request, abort, url_for, redirect, session
from pathlib import Path
import json
from encryption import encrypt_aes, decrypt_aes, hash_password, verify_password, GLOBAL_AES_KEY

from validation import (
    validate_payment_form,
    validate_register_form,
    validate_login_form,
    validate_profile_form
)
from functools import wraps

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.secret_key = "dev-secret-change-me"


MAX_FAILED_ATTEMPTS = 3
LOCKOUT_DURATION_MINUTES = 5
LOGIN_ATTEMPTS: Dict[str, Dict[str, int]] = {}

SESSION_TIMEOUT_SECONDS = 180

PROTECTED_ENDPOINTS = {
    "dashboard",
    "checkout",
    "profile",
    "admin_users",
    "admin_toggle_user",
    "admin_change_role",
}

BASE_DIR = Path(__file__).resolve().parent
EVENTS_PATH = BASE_DIR / "data" / "events.json"
USERS_PATH = BASE_DIR / "data" / "users.json"
ORDERS_PATH = BASE_DIR / "data" / "orders.json"
CATEGORIES = ["All", "Music", "Tech", "Sports", "Business"]
CITIES = ["Any", "New York", "San Francisco", "Berlin", "London", "Oakland", "San Jose"]


@dataclass(frozen=True)
class Event:
    id: int
    title: str
    category: str  
    city: str
    venue: str
    start: datetime
    end: datetime
    price_usd: float
    available_tickets: int
    banner_url: str
    description: str

def _user_with_defaults(u: dict) -> dict:
    u = dict(u)
    u.setdefault("role", "user")      
    u.setdefault("status", "active")  
    u.setdefault("locked_until", "") 
    return u

def get_current_user() -> Optional[dict]:
    email = session.get("user_email")
    if not email:
        return None
    return find_user_by_email(email)


def is_session_expired() -> bool:
    login_ts = session.get("login_at")
    if login_ts is None:
        return True
    try:
        elapsed = int(datetime.now().timestamp()) - int(login_ts)
    except (TypeError, ValueError):
        return True
    return elapsed > SESSION_TIMEOUT_SECONDS


def redirect_login_session_expired():
    session.clear()
    return redirect(url_for("login", expired="1"))


@app.before_request
def enforce_session_timeout_on_protected_routes():
    endpoint = request.endpoint or ""
    if endpoint not in PROTECTED_ENDPOINTS:
        return None

    if not get_current_user():
        return redirect(url_for("login"))

    if is_session_expired():
        return redirect_login_session_expired()

    return None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not get_current_user():
            return redirect(url_for("login"))
        if is_session_expired():
            return redirect_login_session_expired()
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        user = get_current_user()

        if not user:
            return redirect(url_for("login"))

        if is_session_expired():
            return redirect_login_session_expired()

        if user.get("role") != "admin":
            abort(403)

        return f(*args, **kwargs)

    return decorated


@app.errorhandler(403)
def forbidden(e):
    return render_template("error_403.html"), 403

@app.context_processor
def inject_user():
    user = get_current_user()
    return {
        "current_user": user,
        "is_admin": user and user.get("role") == "admin",
        "session_timeout_seconds": SESSION_TIMEOUT_SECONDS,
    }


def load_events() -> List[Event]:
    data = json.loads(EVENTS_PATH.read_text(encoding="utf-8"))
    return [
        Event(
            id=int(e["id"]),
            title=e["title"],
            category=e["category"],
            city=e["city"],
            venue=e["venue"],
            start=datetime.fromisoformat(e["start"]),
            end=datetime.fromisoformat(e["end"]),
            price_usd=float(e["price_usd"]),
            available_tickets=int(e["available_tickets"]),
            banner_url=e.get("banner_url", ""),
            description=e.get("description", ""),
        )
        for e in data
    ]


EVENTS: List[Event] = load_events()


def _parse_date(date_str: str) -> Optional[datetime]:
    """Parsea fecha estilo YYYY-MM-DD. Devuelve None si inválida."""
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return None


def _safe_int(value: str, default: int = 1, min_v: int = 1, max_v: int = 10) -> int:
    """Validación simple de enteros para inputs (cantidad, etc.)."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(min_v, min(max_v, n))

def _card_last4(card_number: str) -> str:
    digits = "".join(ch for ch in (card_number or "") if ch.isdigit())
    return digits[-4:] if len(digits) >= 4 else ""

def _card_masked(card_number: str) -> str:
    last4 = _card_last4(card_number)
    return f"**** **** **** {last4}" if last4 else ""


def filter_events(
    q: str = "",
    city: str = "Any",
    date: Optional[datetime] = None,
    category: str = "All",
    ) -> List[Event]:
    q_norm = (q or "").strip().lower()
    city_norm = (city or "Any").strip()
    category_norm = (category or "All").strip()

    results = load_events()

    if category_norm != "All":
        results = [e for e in results if e.category == category_norm]

    if city_norm != "Any":
        results = [e for e in results if e.city == city_norm]

    if date:
        results = [
            e for e in results
            if e.start.date() == date.date()
        ]

    if q_norm:
        results = [
            e for e in results
            if q_norm in e.title.lower() or q_norm in e.venue.lower()
        ]

    results.sort(key=lambda e: e.start)
    return results


def get_event_or_404(event_id: int) -> Event:
    for e in EVENTS:
        if e.id == event_id:
            return e
    abort(404)


def load_users() -> list[dict]:
    if not USERS_PATH.exists():
        USERS_PATH.parent.mkdir(parents=True, exist_ok=True)
        USERS_PATH.write_text("[]", encoding="utf-8")
    return json.loads(USERS_PATH.read_text(encoding="utf-8"))


def save_users(users: list[dict]) -> None:
    USERS_PATH.write_text(json.dumps(users, indent=2), encoding="utf-8")


def find_user_by_email(email: str) -> Optional[dict]:
    users = load_users()
    email_norm = (email or "").strip().lower()
    for u in users:
        if (u.get("email", "") or "").strip().lower() == email_norm:
            return u
    return None


def user_exists(email: str) -> bool:
    return find_user_by_email(email) is not None

def load_orders() -> list[dict]:
    if not ORDERS_PATH.exists():
        ORDERS_PATH.parent.mkdir(parents=True, exist_ok=True)
        ORDERS_PATH.write_text("[]", encoding="utf-8")
    return json.loads(ORDERS_PATH.read_text(encoding="utf-8"))


def save_orders(orders: list[dict]) -> None:
    ORDERS_PATH.write_text(json.dumps(orders, indent=2), encoding="utf-8")


def next_order_id(orders: list[dict]) -> int:
    return max([o.get("id", 0) for o in orders], default=0) + 1


# -----------------------------
# Rutas
# -----------------------------
@app.get("/")
def index():
    q = request.args.get("q", "")
    city = request.args.get("city", "Any")
    date_str = request.args.get("date", "")
    category = request.args.get("category", "All")

    date = _parse_date(date_str)
    events = filter_events(q=q, city=city, date=date, category=category)

    featured = events[:3] 
    upcoming = events[:6]

    return render_template(
        "index.html",
        q=q,
        city=city,
        date_str=date_str,
        category=category,
        categories=CATEGORIES,
        cities=CITIES,
        featured=featured,
        upcoming=upcoming,
    )


@app.get("/event/<int:event_id>")
def event_detail(event_id: int):
    event = next((e for e in load_events() if e.id == event_id), None)
    if not event:
        abort(404)

    similar = [e for e in EVENTS if e.category == event.category and e.id != event.id][:5]

    return render_template(
        "event_detail.html",
        event=event,
        similar=similar,
    )


@app.post("/event/<int:event_id>/buy")
def buy_ticket(event_id: int):
    event = get_event_or_404(event_id) 
    qty = _safe_int(request.form.get("qty", "1"), default=1, min_v=1, max_v=8)

    if qty > event.available_tickets:
        similar = [e for e in load_events() if e.category == event.category and e.id != event.id][:5]
        return render_template(
            "event_detail.html",
            event=event,
            similar=similar,
            buy_error="Not enough tickets available for that quantity."
        ), 400

    return redirect(url_for("checkout", event_id=event.id, qty=qty))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        registered = request.args.get("registered")
        expired = request.args.get("expired")
        if expired == "1":
            session.clear()
            msg = "Your session has expired. Please sign in again."
        elif registered == "1":
            msg = "Account created successfully. Please sign in."
        else:
            msg = None
        return render_template("login.html", info_message=msg)

    email = request.form.get("email", "")
    password = request.form.get("password", "")

    clean, errors = validate_login_form(email, password)

    if errors:
        return render_template(
            "login.html",
            error="Invalid credentials.",
            form={"email": email}
        ), 400

    email_norm = clean["email"]
    password = clean["password"]

    user = find_user_by_email(email_norm)

    if email_norm not in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[email_norm] = {"intentos": 0, "tiempoBloqueo": 0}

    estado = LOGIN_ATTEMPTS[email_norm]
    now_ts = int(datetime.now().timestamp())

    # Si el bloqueo termina, resetea intentos.
    if estado.get("tiempoBloqueo", 0) > 0 and estado.get("tiempoBloqueo", 0) <= now_ts:
        estado["intentos"] = 0
        estado["tiempoBloqueo"] = 0

    # Verifica si la cuenta esta bloqueada
    if estado.get("tiempoBloqueo", 0) > now_ts:
        remaining_seconds = estado["tiempoBloqueo"] - now_ts
        remaining_minutes = remaining_seconds // 60
        remaining_secs = remaining_seconds % 60
        return render_template(
            "login.html",
            error=f"Security Lockout. Try again in {remaining_minutes}:{remaining_secs}",
            field_errors={"email": " ", "password": " "},
            form={"email": email_norm},
        ), 403

    stored_password = user.get("password") if user else None
    is_valid_password = False

    if isinstance(stored_password, dict):
        is_valid_password = verify_password(password, stored_password)
    else:
        # compatibilidad temporal con usuarios viejos en texto plano
        is_valid_password = hmac.compare_digest(str(stored_password or ""), password)

    if not user or not is_valid_password:
        estado["intentos"] = estado.get("intentos", 0) + 1


        # Si se alcanza el límite, bloquear la cuenta por 5 minutos
        if estado["intentos"] >= MAX_FAILED_ATTEMPTS:
            estado["tiempoBloqueo"] = int(datetime.now().timestamp()) + (LOCKOUT_DURATION_MINUTES * 60)
            return render_template(
            "login.html",
            error=f"Too many failed attempts. Try again in {LOCKOUT_DURATION_MINUTES} minutes.",
            form={"email": email_norm},
        ), 401

        return render_template(
            "login.html",
            error="Invalid credentials.",
            form={"email": email_norm},
        ), 401

    LOGIN_ATTEMPTS[email_norm] = {"intentos": 0, "tiempoBloqueo": 0}

    session["user_email"] = (user.get("email") or "").strip().lower()
    session["login_at"] = int(datetime.now().timestamp())

    return redirect(url_for("dashboard"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template(
            "register.html",
            field_errors={},
            form={}
        )

    full_name = request.form.get("full_name", "")
    email = request.form.get("email", "")
    phone = request.form.get("phone", "")
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    clean, errors = validate_register_form(
        full_name,
        email,
        phone,
        password,
        confirm_password
    )

    if errors:
        return render_template(
            "register.html",
            field_errors=errors,
            form=request.form
        ), 400

    if user_exists(clean["email"]):
        errors["email"] = "Email already registered"
        return render_template(
            "register.html",
            field_errors=errors,
            form=request.form
        ), 400

    users = load_users()
    next_id = (max([u.get("id", 0) for u in users], default=0) + 1)
    phone_cipher, phone_nonce, phone_tag = encrypt_aes(clean["phone"], GLOBAL_AES_KEY)

    users.append({
        "id": next_id,
        "full_name": clean["full_name"],
        "email": clean["email"],
        "phone": {
            "cipher": phone_cipher,
            "nonce": phone_nonce,
            "tag": phone_tag
        },
        "password": hash_password(clean["password"]),
        "role": "user",
        "status": "active",
    })

    save_users(users)

    return redirect(url_for("login", registered="1"))

@app.get("/dashboard")
@login_required
def dashboard():


    paid = request.args.get("paid") == "1"
    user = get_current_user()
    return render_template("dashboard.html", user_name=(user.get("full_name") if user else "User"), paid=paid)

@app.route("/checkout/<int:event_id>", methods=["GET", "POST"])
@login_required
def checkout(event_id: int):


    events = load_events()
    event = next((e for e in events if e.id == event_id), None)
    if not event:
        abort(404)

    qty = _safe_int(request.args.get("qty", "1"), default=1, min_v=1, max_v=8)

    service_fee = 5.00
    subtotal = event.price_usd * qty
    total = subtotal + service_fee

    if request.method == "GET":
        return render_template(
            "checkout.html",
            event=event,
            qty=qty,
            subtotal=subtotal,
            service_fee=service_fee,
            total=total,
            errors={},
            form_data={}
        )

    card_number = request.form.get("card_number", "")
    exp_date = request.form.get("exp_date", "")
    cvv = request.form.get("cvv", "")
    name_on_card = request.form.get("name_on_card", "")
    billing_email = request.form.get("billing_email", "")

    clean, errors = validate_payment_form(
        card_number=card_number,
        exp_date=exp_date,
        cvv=cvv,
        name_on_card=name_on_card,
        billing_email=billing_email
    )
    card_last4 = _card_last4(clean.get("card", ""))
    card_masked = _card_masked(clean.get("card", ""))

    form_data = {
        "exp_date": clean.get("exp_date", ""),
        "name_on_card": clean.get("name_on_card", ""),
        "billing_email": clean.get("billing_email", ""),
        "card_masked": card_masked
    }

    if errors:
        return render_template(
            "checkout.html",
            event=event, qty=qty, subtotal=subtotal,
            service_fee=service_fee, total=total,
            errors=errors, form_data=form_data
        ), 400

    orders = load_orders()
    order_id = next_order_id(orders)

    email_cipher, email_nonce, email_tag = encrypt_aes(clean["billing_email"],GLOBAL_AES_KEY)

    orders.append({
        "id": order_id,
        "user_email": "PLACEHOLDER@EMAIL.COM",
        "event_id": event.id,
        "event_title": event.title,
        "qty": qty,
        "unit_price": event.price_usd,
        "service_fee": service_fee,
        "total": total,
        "status": "PAID",
        "created_at": datetime.utcnow().isoformat(),
        "payment": {
        "name_on_card": clean.get("name_on_card", ""),
        "exp_date": clean.get("exp_date", ""),
        "card_masked": card_masked,

        "billing_email": {
            "cipher": email_cipher,
            "nonce": email_nonce,
            "tag": email_tag
            }
        }
    })

    save_orders(orders)
    
    return redirect(url_for("dashboard", paid="1"))




@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
 

    user = get_current_user()
    if not user:
        session.clear()
        return redirect(url_for("login"))
    
    phone_data = user.get("phone")
    phone_plain = ""
    if isinstance(phone_data, dict):
        phone_plain = decrypt_aes(
            phone_data["cipher"],
            phone_data["nonce"],
            phone_data["tag"],
            GLOBAL_AES_KEY
        )


    form = {
        "full_name": user.get("full_name", ""),
        "email": user.get("email", ""),
        "phone": phone_plain,
    }

    field_errors = {}  
    success_msg = None

    if request.method == "POST":
        full_name = request.form.get("full_name", "")
        phone = request.form.get("phone", "")
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_new_password = request.form.get("confirm_new_password", "")

        clean, errors = validate_profile_form(
            full_name,
            phone,
            current_password,
            new_password,
            confirm_new_password,
            user["email"],
            user["password"]
        )

        if errors:
            return render_template(
                "profile.html",
                form=form,
                field_errors=errors
            ), 400

        users = load_users()
        email_norm = (user.get("email") or "").strip().lower()

        for u in users:
            if (u.get("email") or "").strip().lower() == email_norm:
                u["full_name"] = clean["full_name"]

                phone_cipher, phone_nonce, phone_tag = encrypt_aes(clean["phone"],GLOBAL_AES_KEY)

                u["phone"] = {
                    "cipher": phone_cipher,
                    "nonce": phone_nonce,
                    "tag": phone_tag
                }

                if clean.get("new_password"):
                    u["password"] = hash_password(clean["new_password"])
                break

        save_users(users)

        form["full_name"] = full_name
        form["phone"] = phone
        success_msg = "Profile updated successfully."

    return render_template(
        "profile.html",
        form=form,
        field_errors=field_errors,
        success_message=success_msg,
    )
@app.get("/admin/users")
@admin_required
def admin_users():

    q = (request.args.get("q") or "").strip().lower()
    role = (request.args.get("role") or "all").strip().lower()
    status = (request.args.get("status") or "all").strip().lower()
    lockout = (request.args.get("lockout") or "all").strip().lower()

    users = [_user_with_defaults(u) for u in load_users()]

    # filtros
    if q:
        users = [
            u for u in users
            if q in (u.get("full_name","").lower()) or q in (u.get("email","").lower())
        ]

    if role != "all":
        users = [u for u in users if (u.get("role","user").lower() == role)]

    if status != "all":
        users = [u for u in users if (u.get("status","active").lower() == status)]

    if lockout != "all":
        if lockout == "locked":
            users = [u for u in users if (u.get("locked_until") or "").strip()]
        elif lockout == "not_locked":
            users = [u for u in users if not (u.get("locked_until") or "").strip()]

    users.sort(key=lambda u: (u.get("full_name","").lower(), u.get("id", 0)))

    return render_template(
        "admin_users.html",
        users=users,
        filters={"q": q, "role": role, "status": status, "lockout": lockout},
        total=len(users),
    )

@app.post("/admin/users/<int:user_id>/toggle")
@admin_required
def admin_toggle_user(user_id: int):
    users = load_users()
    for u in users:
        if int(u.get("id", 0)) == user_id:
            u.setdefault("status", "active")
            u["status"] = "disabled" if u["status"] == "active" else "active"
            break
    save_users(users)
    return redirect(url_for("admin_users"))

@app.post("/admin/users/<int:user_id>/role")
@admin_required
def admin_change_role(user_id: int):
    new_role = request.form.get("role", "user")

    users = load_users()
    for u in users:
        if int(u.get("id", 0)) == user_id:
            u["role"] = new_role
            break
    save_users(users)
    return redirect(url_for("admin_users"))

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))
    
if __name__ == "__main__":
    app.run(debug=True)
