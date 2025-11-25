# =======================
#  FULL SAFE APP.PY
#  EMAIL FAILS WON'T CRASH
# =======================

import os
import secrets
from datetime import datetime

from flask import (
    Flask, render_template, redirect, url_for, flash,
    request, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, DateField, FileField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image, ImageDraw, ImageFont
import smtplib
from email.message import EmailMessage
import qrcode

# ====================================
#  EMAIL SEND OPTIONAL ON SERVER
# ====================================
ENABLE_EMAIL = os.environ.get("ENABLE_EMAIL", "0") == "1"

# -------------------
# Config & Setup
# -------------------

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
CARD_FOLDER = os.path.join(BASE_DIR, "cards")
STATIC_FOLDER = os.path.join(BASE_DIR, "static")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CARD_FOLDER, exist_ok=True)
os.makedirs(STATIC_FOLDER, exist_ok=True)


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{os.path.join(BASE_DIR, 'app.db')}"
    )

    if app.config["SQLALCHEMY_DATABASE_URI"].startswith("postgres://"):
        app.config["SQLALCHEMY_DATABASE_URI"] = app.config["SQLALCHEMY_DATABASE_URI"].replace(
            "postgres://", "postgresql://", 1
        )

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
    app.config["CARD_FOLDER"] = CARD_FOLDER

    db.init_app(app)
    login_manager.init_app(app)

    with app.app_context():
        db.create_all()

    return app


db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "login"


# -------------------
# Models
# -------------------

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    children = db.relationship("Child", backref="parent", lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Child(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    parent_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    full_name = db.Column(db.String(150), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)

    applications = db.relationship("Application", backref="child", lazy=True)
    card = db.relationship("Card", backref="child", uselist=False)


class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    child_id = db.Column(db.Integer, db.ForeignKey("child.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default="pending")
    photo_filename = db.Column(db.String(255), nullable=False)
    id_document_filename = db.Column(db.String(255), nullable=False)
    notes = db.Column(db.Text)


class Card(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    child_id = db.Column(db.Integer, db.ForeignKey("child.id"), nullable=False)
    card_number = db.Column(db.String(50), unique=True, nullable=False)
    issued_at = db.Column(db.DateTime, default=datetime.utcnow)
    card_image_filename = db.Column(db.String(255), nullable=False)


# -------------------
# Login manager
# -------------------

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# -------------------
# Forms
# -------------------

class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    confirm = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class ChildApplicationForm(FlaskForm):
    full_name = StringField("Child's Full Name", validators=[DataRequired()])
    date_of_birth = DateField("Date of Birth", validators=[DataRequired()], format="%Y-%m-%d")
    photo = FileField("Photo (passport style)", validators=[DataRequired()])
    id_document = FileField("ID Document", validators=[DataRequired()])
    consent = BooleanField(
        "I confirm I am the parent/guardian and consent to data processing",
        validators=[DataRequired()],
    )
    submit = SubmitField("Submit Application")


# -------------------
# Helper Functions
# -------------------

def save_uploaded_file(file_storage, folder):
    filename = secure_filename(file_storage.filename)
    random_prefix = secrets.token_hex(8)
    filename = f"{random_prefix}_{filename}"
    path = os.path.join(folder, filename)
    file_storage.save(path)
    return filename


def generate_card_image(child, photo_path, output_folder, card_number):
    card_width, card_height = 1011, 638
    background_color = (240, 240, 240)

    img = Image.new("RGB", (card_width, card_height), background_color)
    draw = ImageDraw.Draw(img)

    try:
        font_large = ImageFont.truetype("arial.ttf", 36)
        font_medium = ImageFont.truetype("arial.ttf", 26)
        font_small = ImageFont.truetype("arial.ttf", 20)
    except IOError:
        font_large = font_medium = font_small = ImageFont.load_default()

    border_color = (0, 0, 0)
    draw.rectangle(
        [4, 4, card_width - 4, card_height - 4],
        outline=border_color,
        width=4,
    )

    photo = Image.open(photo_path).convert("RGB")
    photo = photo.resize((260, 340))
    img.paste(photo, (40, 120))

    # Text block
    text_x = 340
    text_y = 60
    draw.text((40, 30), "RADCLIFFE FOOTBALL CLUB MEMBERSHIP CARD", fill=(10, 10, 10), font=font_large)

    draw.text((text_x, text_y), f"Name: {child.full_name}", fill=(10, 10, 10), font=font_medium)
    text_y += 50
    draw.text((text_x, text_y), f"DOB: {child.date_of_birth.strftime('%d/%m/%Y')}", fill=(10, 10, 10), font=font_medium)
    text_y += 50
    draw.text((text_x, text_y), f"Card No: {card_number}", fill=(10, 10, 10), font=font_medium)
    text_y += 50
    draw.text((text_x, text_y), "Season: 2025/26", fill=(10, 10, 10), font=font_small)
    text_y += 70

    # Badge
    badge_path = os.path.join(STATIC_FOLDER, "radcliffe_fc_badge.png")
    try:
        badge = Image.open(badge_path).convert("RGBA")
        badge = badge.resize((110, 110))
        img.paste(badge, (text_x, text_y), badge)
    except Exception as e:
        print(f"⚠️ Badge load failed: {e}")

    # QR code
    qr = qrcode.QRCode(box_size=4, border=1)
    qr.add_data(card_number)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    qr_img = qr_img.resize((160, 160))
    img.paste(qr_img, (card_width - 200, card_height - 200))

    output_filename = f"card_{card_number}.png"
    img.save(os.path.join(output_folder, output_filename), format="PNG", dpi=(300, 300))

    return output_filename


def send_card_email(to_email, child, card_image_path, card_number):
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    from_email = os.environ.get("FROM_EMAIL", smtp_user)

    if not (smtp_host and smtp_user and smtp_password):
        print("⚠️ SMTP not configured – skipping email")
        return

    msg = EmailMessage()
    msg["Subject"] = "Radcliffe Football Club Membership Card"
    msg["From"] = from_email
    msg["To"] = to_email

    msg.set_content(f"""
Hi,

Your child's membership card has been approved.

Child: {child.full_name}
Card number: {card_number}

Attached is your card.

Radcliffe Football Club
""")

    with open(card_image_path, "rb") as f:
        msg.add_attachment(f.read(), maintype="image", subtype="png", filename=os.path.basename(card_image_path))

    server = smtplib.SMTP(smtp_host, smtp_port)
    server.starttls()
    server.login(smtp_user, smtp_password)
    server.send_message(msg)
    server.quit()


# -------------------
# Routes
# -------------------

app = create_app()


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data.lower()).first():
            flash("Email already registered.", "warning")
            return redirect(url_for("login"))
        user = User(email=form.email.data.lower())
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Account created.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for("dashboard"))
        flash("Invalid login.", "danger")
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    my_children = Child.query.filter_by(parent_id=current_user.id).all()
    return render_template("dashboard.html", children=my_children)


@app.route("/apply", methods=["GET", "POST"])
@login_required
def apply():
    form = ChildApplicationForm()
    if form.validate_on_submit():
        child = Child(
            parent_id=current_user.id,
            full_name=form.full_name.data.strip(),
            date_of_birth=form.date_of_birth.data,
        )
        db.session.add(child)
        db.session.flush()

        photo_filename = save_uploaded_file(form.photo.data, app.config["UPLOAD_FOLDER"])
        id_filename = save_uploaded_file(form.id_document.data, app.config["UPLOAD_FOLDER"])

        application = Application(
            child_id=child.id,
            photo_filename=photo_filename,
            id_document_filename=id_filename,
        )
        db.session.add(application)
        db.session.commit()

        flash("Application submitted!", "success")
        return redirect(url_for("dashboard"))
    return render_template("apply.html", form=form)


# -------------------
# Admin
# -------------------

def admin_required(func):
    from functools import wraps
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Admins only.", "danger")
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


@app.route("/admin/applications")
@login_required
@admin_required
def admin_applications():
    pending = Application.query.filter_by(status="pending").all()
    return render_template("admin_applications.html", applications=pending)

@app.route("/admin/application/<int:app_id>", methods=["GET", "POST"])
@login_required
@admin_required
def admin_application_detail(app_id):
    application = Application.query.get_or_404(app_id)
    child = application.child

    if request.method == "POST":
        action = request.form.get("action")

        if action == "approve":
            application.status = "approved"

            # Generate card
            card_number = f"RJ-{application.id:06d}"
            photo_path = os.path.join(app.config["UPLOAD_FOLDER"], application.photo_filename)
            card_image_filename = generate_card_image(
                child,
                photo_path,
                app.config["CARD_FOLDER"],
                card_number,
            )

            card = Card(
                child_id=child.id,
                card_number=card_number,
                card_image_filename=card_image_filename,
            )
            db.session.add(card)
            db.session.commit()

            # NOTE: Email sending disabled on Render to avoid timeouts
            flash("Application approved and card generated.", "success")
            return redirect(url_for("admin_applications"))

        elif action == "reject":
            application.status = "rejected"
            db.session.commit()
            flash("Application rejected.", "info")
            return redirect(url_for("admin_applications"))

    return render_template("admin_application_detail.html", application=application, child=child)




@app.route("/uploads/<filename>")
@login_required
@admin_required
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/cards/<filename>")
@login_required
def card_file(filename):
    return send_from_directory(app.config["CARD_FOLDER"], filename)


if __name__ == "__main__":
    app.run(debug=True)
