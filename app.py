import os
import re
import secrets
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    session, abort, send_from_directory, make_response
)
from flask_sqlalchemy import SQLAlchemy

BASE_DIR = Path(__file__).resolve().parent
PUBLISH_ROOT = BASE_DIR / "published"
UPLOAD_ROOT = BASE_DIR / "uploads"
PUBLISH_ROOT.mkdir(exist_ok=True)
UPLOAD_ROOT.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", f"sqlite:///{BASE_DIR / 'publisher.db'}"
).replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # 8 MB request limit
app.config["MAX_HTML_SIZE"] = 1_000_000
db = SQLAlchemy(app)

ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "svg"}
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    email = db.Column(db.String(254), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Publication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(120), unique=True, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    owner = db.relationship("User", backref=db.backref("publications", lazy=True))


class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    message = db.Column(db.String(500), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user = db.relationship("User", backref=db.backref("ratings", lazy=True))


def current_user():
    user_id = session.get("user_id")
    return db.session.get(User, user_id) if user_id else None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash("Please sign in to continue.", "info")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        admin_username = os.environ.get("ADMIN_USERNAME", "admin")
        if current_user().username != admin_username:
            abort(404)
        return view(*args, **kwargs)
    return wrapped


def safe_slug(title):
    cleaned = re.sub(r"[^a-zA-Z0-9-]+", "-", title.strip().lower()).strip("-")
    return (cleaned[:65] or "page") + "-" + secrets.token_hex(4)


@app.after_request
def security_headers(response):
    # The public page endpoint is intentionally isolated from the account UI with
    # a restrictive policy. For interactive, untrusted user pages, deploy them
    # on a separate domain/origin (see README) rather than relaxing this policy.
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.endpoint == "public_page":
        response.headers["Content-Security-Policy"] = (
            "default-src 'self' data: blob:; img-src 'self' data: blob:; "
            "style-src 'self' 'unsafe-inline'; script-src 'none'; "
            "object-src 'none'; base-uri 'none'; form-action 'none'; "
            "frame-ancestors 'self'"
        )
    else:
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'self'"
        )
    return response


@app.route("/")
def index():
    if current_user():
        return redirect(url_for("home"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user():
        return redirect(url_for("home"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if not USERNAME_RE.fullmatch(username):
            flash("Username must be 3–32 characters and use letters, numbers, dot, dash or underscore.", "error")
        elif "@" not in email or len(email) > 254:
            flash("Enter a valid email address.", "error")
        elif len(password) < 10:
            flash("Use a password with at least 10 characters.", "error")
        elif password != confirm:
            flash("The passwords do not match.", "error")
        elif User.query.filter(db.or_(User.username == username, User.email == email)).first():
            flash("That username or email is already registered.", "error")
        else:
            user = User(username=username, email=email, password_hash=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            session.clear()
            session["user_id"] = user.id
            flash("Account created. Welcome!", "success")
            return redirect(url_for("home"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("home"))
    if request.method == "POST":
        login_name = request.form.get("login", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter(
            db.or_(User.username == login_name, User.email == login_name.lower())
        ).first()
        if user and check_password_hash(user.password_hash, password):
            session.clear()
            session["user_id"] = user.id
            flash("You are signed in.", "success")
            return redirect(url_for("home"))
        flash("Invalid username/email or password.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have signed out.", "info")
    return redirect(url_for("login"))


@app.route("/home")
@login_required
def home():
    user = current_user()
    return render_template("home.html", user=user, publication_count=len(user.publications))


@app.route("/publish", methods=["GET", "POST"])
@login_required
def publish():
    if request.method == "POST":
        title = request.form.get("title", "").strip()[:100]
        mode = request.form.get("mode", "code")
        html_code = request.form.get("html_code", "")
        uploaded_html = request.files.get("html_file")
        if not title:
            flash("Give your page a title.", "error")
            return redirect(url_for("publish"))
        if Publication.query.filter_by(owner_id=current_user().id).count() >= 25:
            flash("You have reached the starter limit of 25 publications.", "error")
            return redirect(url_for("publish"))

        if mode == "upload":
            if not uploaded_html or not uploaded_html.filename.lower().endswith((".html", ".htm")):
                flash("Choose an .html or .htm file to upload.", "error")
                return redirect(url_for("publish"))
            raw = uploaded_html.read(app.config["MAX_HTML_SIZE"] + 1)
            if len(raw) > app.config["MAX_HTML_SIZE"]:
                flash("HTML file is too large (maximum 1 MB).", "error")
                return redirect(url_for("publish"))
            html_code = raw.decode("utf-8", errors="replace")
        else:
            if not html_code.strip():
                flash("Paste your HTML code into the editor.", "error")
                return redirect(url_for("publish"))
            if len(html_code.encode("utf-8")) > app.config["MAX_HTML_SIZE"]:
                flash("HTML code is too large (maximum 1 MB).", "error")
                return redirect(url_for("publish"))

        slug = safe_slug(title)
        page_dir = PUBLISH_ROOT / slug
        page_dir.mkdir(parents=True, exist_ok=False)
        (page_dir / "index.html").write_text(html_code, encoding="utf-8")

        # Optional image uploads. HTML can reference these as assets/<filename>.
        asset_dir = page_dir / "assets"
        image_files = request.files.getlist("images")
        saved_images = 0
        for image_file in image_files[:10]:
            if not image_file or not image_file.filename:
                continue
            filename = secure_filename(image_file.filename)
            ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            if ext not in ALLOWED_IMAGE_EXTENSIONS:
                continue
            asset_dir.mkdir(exist_ok=True)
            data = image_file.read(2 * 1024 * 1024 + 1)
            if len(data) > 2 * 1024 * 1024:
                continue
            (asset_dir / filename).write_bytes(data)
            saved_images += 1

        publication = Publication(title=title, slug=slug, owner_id=current_user().id)
        db.session.add(publication)
        db.session.commit()
        public_url = url_for("public_page", slug=slug, _external=True)
        flash(f"Published successfully: {public_url}", "success")
        return render_template("published.html", publication=publication, public_url=public_url, saved_images=saved_images)
    return render_template("publish.html")


@app.route("/publications")
@login_required
def publications():
    items = Publication.query.filter_by(owner_id=current_user().id).order_by(Publication.created_at.desc()).all()
    return render_template("publications.html", publications=items)


@app.route("/p/<slug>")
def public_page(slug):
    publication = Publication.query.filter_by(slug=slug).first_or_404()
    page_dir = PUBLISH_ROOT / publication.slug
    index_file = page_dir / "index.html"
    if not index_file.is_file():
        abort(404)
    response = make_response(send_from_directory(page_dir, "index.html", mimetype="text/html"))
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' data: blob:; img-src 'self' data: blob:; "
        "style-src 'self' 'unsafe-inline'; script-src 'none'; object-src 'none'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'self'"
    )
    return response


@app.route("/p/<slug>/assets/<path:filename>")
def public_asset(slug, filename):
    publication = Publication.query.filter_by(slug=slug).first_or_404()
    asset_dir = PUBLISH_ROOT / publication.slug / "assets"
    return send_from_directory(asset_dir, filename)


@app.route("/rate", methods=["GET", "POST"])
@login_required
def rate():
    if request.method == "POST":
        try:
            score = int(request.form.get("score", "0"))
        except ValueError:
            score = 0
        message = request.form.get("message", "").strip()[:500]
        if score not in range(1, 6):
            flash("Choose a rating from 1 to 5.", "error")
        else:
            db.session.add(Rating(user_id=current_user().id, score=score, message=message))
            db.session.commit()
            flash("Thank you for rating our service!", "success")
            return redirect(url_for("home"))
    return render_template("rate.html")


@app.route("/admin")
@admin_required
def admin():
    month_ago = datetime.utcnow() - timedelta(days=30)
    total_users = User.query.count()
    new_users = User.query.filter(User.created_at >= month_ago).count()
    users = User.query.order_by(User.created_at.desc()).limit(250).all()
    total_publications = Publication.query.count()
    ratings = Rating.query.order_by(Rating.created_at.desc()).limit(30).all()
    return render_template(
        "admin.html", users=users, total_users=total_users,
        new_users=new_users, total_publications=total_publications,
        ratings=ratings, month_ago=month_ago
    )


@app.cli.command("init-db")
def init_db():
    """Create database tables."""
    with app.app_context():
        db.create_all()
    print("Database tables created.")


with app.app_context():
    db.create_all()

if __name__ == "__main__":
    # Use debug=False for normal use. Do not expose Flask's development server to the internet.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)

