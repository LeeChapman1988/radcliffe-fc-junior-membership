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
from wtforms import StringField, PasswordField, DateField, FileField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image, ImageDraw, ImageFont
import smtplib
from email.message import EmailMessage
import qrcode

# -------------------
# Config & Setup
# -------------------

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
CARD_FOLDER = os.path.join(BASE_DIR, "cards")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CARD_FOLDER, exist_ok=True)


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{os.path.join(BASE_DIR, 'app.db')}"
    )
    if app.config["SQLALCHEMY_DATABASE_URI"].startswith("postgres://"):
        # Render old-style URL fix
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

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Child(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    parent_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    full_name = db.Column(db.String(255), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)

    applications = db.relationship("Application", backref="child", lazy=True)
    card = db.relationship("Card", backref="child", uselist=False)


class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    child_id = db.Column(db.Integer, db.ForeignKey("child.id"), nullable=False)
    photo_filename = db.Column(db.String(255), nullable=False)
    id_document_filename = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), default="pending")  # pending, approved, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Card(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    child_id = db.Column(db.Integer, db.ForeignKey("child.id"), nullable=False)
    card_number = db.Column(db.String(50), unique=True, nullable=False)
    card_image_filename = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
    email = StringField(
        "Email",
        validators=[DataRequired(), Email(), Length(max=255)]
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=6)]
    )
    password2 = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match")]
    )
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField(
        "Email",
        validators=[DataRequired(), Email(), Length(max=255)]
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired()]
    )
    submit = SubmitField("Login")


class ChildApplicationForm(FlaskForm):
    full_name = StringField(
        "Child's Full Name",
        validators=[DataRequired(), Length(max=255)]
    )
    date_of_birth = DateField(
        "Date of Birth",
        validators=[DataRequired()],
        format="%Y-%m-%d"
    )
    photo = FileField("Child Photo", validators=[DataRequired()])
    id_document = FileField("ID / Proof of Age", validators=[DataRequired()])
    submit = SubmitField("Submit Application")

# -------------------
# Helper functions
# -------------------


def save_uploaded_file(file_storage, upload_dir):
    """Save an uploaded file with a randomised secure name, return the filename."""
    filename = secure_filename(file_storage.filename)
    random_prefix = secrets.token_hex(8)
    filename = f"{random_prefix}_{filename}"
    path = os.path.join(upload_dir, filename)
    file_storage.save(path)
    return filename


def generate_card_image(child: Child, photo_path: str, output_dir: str, card_number: str) -> str:
    """
    Generate a driving licence–style membership card as a PNG.

    Physical style approx 86 x 54 mm at 300 DPI → ~1020 x 640.
    We’ll use a slightly smaller canvas but same proportions.
    """
    width, height = 860, 540  # 8.6 x 5.4 cm at 100 px/cm approx

    bg_color = (10, 30, 60)       # dark navy
    accent_color = (255, 215, 0)  # gold
    text_color = (255, 255, 255)  # white
    muted_text = (200, 200, 200)

    # Create base image
    card = Image.new("RGB", (width, height), bg_color)
    draw = ImageDraw.Draw(card)

    # Try to load a TTF font, fall back if not available
    try:
        font_large = ImageFont.truetype("arial.ttf", 36)
        font_medium = ImageFont.truetype("arial.ttf", 26)
        font_small = ImageFont.truetype("arial.ttf", 20)
    except Exception:
        font_large = ImageFont.load_default()
        font_medium = ImageFont.load_default()
        font_small = ImageFont.load_default()

    # Header bar
    header_height = 90
    draw.rectangle([(0, 0), (width, header_height)], fill=accent_color)

    # Title text – updated to Radcliffe FC
    draw.text(
        (40, 20),
        "RADCLIFFE FOOTBALL CLUB MEMBERSHIP CARD",
        fill=bg_color,
        font=font_large
    )

    # Child photo on the left
    try:
        photo = Image.open(photo_path).convert("RGB")
    except Exception:
        # If there's any issue with the uploaded photo, use a blank placeholder
        photo = Image.new("RGB", (300, 400), (80, 80, 80))

    # Crop to square centre
    pw, ph = photo.size
    side = min(pw, ph)
    left = (pw - side) // 2
    top = (ph - side) // 2
    photo_cropped = photo.crop((left, top, left + side, top + side))

    # Resize and paste
    photo_size = 220
    photo_cropped = photo_cropped.resize((photo_size, photo_size))
    photo_x = 40
    photo_y = header_height + 40
    card.paste(photo_cropped, (photo_x, photo_y))

    # Info area on the right
    info_x = photo_x + photo_size + 40
    info_y = header_height + 40

    # Name
    draw.text((info_x, info_y), f"Name: {child.full_name}", fill=text_color, font=font_medium)
    info_y += 50

    # DOB
    dob_str = child.date_of_birth.strftime("%d/%m/%Y")
    draw.text((info_x, info_y), f"DOB: {dob_str}", fill=text_color, font=font_medium)
    info_y += 50

    # Card number
    draw.text((info_x, info_y), f"Card No: {card_number}", fill=text_color, font=font_medium)
    info_y += 50

    # Season
    draw.text((info_x, info_y), "Season: 2025/2026", fill=text_color, font=font_medium)
    info_y += 60

    # QR code with simple URL
    qr_data = f"RJFC:{card_number}"
    qr_img = qrcode.make(qr_data)
    qr_size = 140
    qr_img = qr_img.resize((qr_size, qr_size))
    qr_x = width - qr_size - 40
    qr_y = height - qr_size - 40
    card.paste(qr_img, (qr_x, qr_y))

    # Footer text
    footer_text = "Scan at the turnstile for membership benefits."
    draw.text((40, height - 40), footer_text, fill=muted_text, font=font_small)

    # Save to file
    filename = f"card_{card_number}.png"
    output_path = os.path.join(output_dir, filename)
    card.save(output_path, format="PNG")
    return filename


def send_card_email(to_email: str, child: Child, card_image_path: str, card_number: str) -> None:
    """
    Send an email with the generated card attached.

    Uses environment variables:
      SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, FROM_EMAIL
    """
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    from_email = os.environ.get("FROM_EMAIL", smtp_user)

    if not all([smtp_host, smtp_user, smtp_password, from_email]):
        print("⚠️ SMTP not configured – skipping email send.")
        return

    msg = EmailMessage()
    msg["Subject"] = f"Radcliffe Juniors Membership Card - {child.full_name}"
    msg["From"] = from_email
    msg["To"] = to_email

    body = (
        f"Hi,\n\n"
        f"Your Radcliffe Juniors membership card for {child.full_name} has been approved.\n"
        f"Card Number: {card_number}\n\n"
        f"The card is attached as an image. You can save it to your phone or print it.\n\n"
        f"Thank you.\n"
    )
    msg.set_content(body)

    # Attach image
    with open(card_image_path, "rb") as f:
        img_data = f.read()
    msg.add_attachment(
        img_data,
        maintype="image",
        subtype="png",
        filename=os.path.basename(card_image_path),
    )

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.send_message(msg)
        print(f"✅ Card email sent to {to_email}")

# -------------------
# App instance
# -------------------

app = create_app()

# -------------------
# Routes
# -------------------


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = RegisterForm()
    if form.validate_on_submit():
        existing = User.query.filter_by(email=form.email.data.lower().strip()).first()
        if existing:
            flash("An account with that email already exists.", "danger")
            return redirect(url_for("login"))

        user = User(
            email=form.email.data.lower().strip(),
            is_admin=False,
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower().strip()).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash("Logged in successfully.", "success")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard"))
        else:
            flash("Invalid email or password.", "danger")

    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    # List children + applications + cards for this parent
    my_children = Child.query.filter_by(parent_id=current_user.id).all()
    return render_template("dashboard.html", children=my_children)


@app.route("/apply", methods=["GET", "POST"])
@login_required
def apply():
    form = ChildApplicationForm()
    if form.validate_on_submit():
        # Save child
        child = Child(
            parent_id=current_user.id,
            full_name=form.full_name.data.strip(),
            date_of_birth=form.date_of_birth.data,
        )
        db.session.add(child)
        db.session.flush()  # get child.id

        # Save files
        photo_filename = save_uploaded_file(form.photo.data, app.config["UPLOAD_FOLDER"])
        id_filename = save_uploaded_file(form.id_document.data, app.config["UPLOAD_FOLDER"])

        application = Application(
            child_id=child.id,
            photo_filename=photo_filename,
            id_document_filename=id_filename,
        )
        db.session.add(application)
        db.session.commit()

        flash("Application submitted. You will be notified once approved.", "success")
        return redirect(url_for("dashboard"))

    return render_template("apply.html", form=form)

# -------------------
# Admin routes
# -------------------


def admin_required(func):
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Admin access only.", "danger")
            return redirect(url_for("login"))
        return func(*args, **kwargs)

    return wrapper


@app.route("/admin/applications")
@login_required
@admin_required
def admin_applications():
    applications = Application.query.order_by(Application.created_at.desc()).all()
    return render_template("admin_applications.html", applications=applications)


@app.route("/admin/application/<int:app_id>", methods=["GET", "POST"])
@login_required
@admin_required
def admin_application_detail(app_id):
    application = Application.query.get_or_404(app_id)
    child = application.child

    if request.method == "POST":
        action = request.form.get("action")

        if action == "approve":
            # Only generate once
            if application.status != "approved":
                application.status = "approved"

                # Generate card image
                card_number = f"RJ-{application.id:06d}"
                photo_path = os.path.join(app.config["UPLOAD_FOLDER"], application.photo_filename)
                card_image_filename = generate_card_image(
                    child,
                    photo_path,
                    app.config["CARD_FOLDER"],
                    card_number
                )

                # Store card record
                card = Card(
                    child_id=child.id,
                    card_number=card_number,
                    card_image_filename=card_image_filename,
                )
                db.session.add(card)

                # Send email (best-effort)
                parent_email = child.parent.email
                card_image_path = os.path.join(app.config["CARD_FOLDER"], card_image_filename)
                try:
                    send_card_email(parent_email, child, card_image_path, card_number)
                except Exception as e:
                    print("Error sending card email:", e)

                flash("Application approved and card generated.", "success")
            else:
                flash("Application already approved.", "info")

        elif action == "reject":
            application.status = "rejected"
            flash("Application rejected.", "info")

        db.session.commit()
        return redirect(url_for("admin_applications"))

    return render_template("admin_application_detail.html", application=application, child=child)


@app.route("/uploads/<filename>")
@login_required
@admin_required
def uploaded_file(filename):
    # For admin to view ID docs/photos
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/cards/<filename>")
@login_required
def card_file(filename):
    # Only allow parent of child or admin in a real system.
    # For now, just require login.
    return send_from_directory(app.config["CARD_FOLDER"], filename)


if __name__ == "__main__":
    app.run(debug=True)
