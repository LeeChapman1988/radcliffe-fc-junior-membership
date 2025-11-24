import os
import smtplib
import secrets
from email.message import EmailMessage
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from PIL import Image, ImageDraw, ImageFont

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("secret_key", "fallback_secret")

# DATABASE
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# LOGIN
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

UPLOAD_FOLDER = "uploads"
CARD_FOLDER = "cards"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CARD_FOLDER, exist_ok=True)

# ---------------------- MODELS ----------------------

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password_hash = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    parent_email = db.Column(db.String(150))
    parent_name = db.Column(db.String(150))
    child_name = db.Column(db.String(150))
    photo_filename = db.Column(db.String(300))
    status = db.Column(db.String(50), default="Pending")
    card_number = db.Column(db.String(20), nullable=True)
    card_filename = db.Column(db.String(200), nullable=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------------- CARD GENERATOR ----------------------

def generate_card_image(child_name, card_number, photo_path):

    output_filename = f"card_{card_number}.png"
    output_path = os.path.join(CARD_FOLDER, output_filename)

    card = Image.new("RGB", (1011, 638), "white")
    draw = ImageDraw.Draw(card)

    if os.path.exists(photo_path):
        user_img = Image.open(photo_path).convert("RGB")
        user_img = user_img.resize((300, 400))
        card.paste(user_img, (50, 120))

    badge_path = "static/radcliffe_fc_badge.png"
    if os.path.exists(badge_path):
        badge = Image.open(badge_path).convert("RGBA")
        badge = badge.resize((180, 180))
        card.paste(badge, (800, 40), badge)

    try:
        font_large = ImageFont.truetype("arial.ttf", 48)
        font_medium = ImageFont.truetype("arial.ttf", 38)
        font_small = ImageFont.truetype("arial.ttf", 32)
    except:
        font_large = ImageFont.load_default()
        font_medium = ImageFont.load_default()
        font_small = ImageFont.load_default()

    draw.text((400, 80), "RADCLIFFE FOOTBALL CLUB", fill="black", font=font_large)
    draw.text((400, 180), f"Member: {child_name}", fill="black", font=font_medium)
    draw.text((400, 260), f"Card No: {card_number}", fill="black", font=font_medium)
    draw.text((400, 340), "Season: 2024 / 2025", fill="black", font=font_small)
    draw.text((400, 420), "This card must be shown on request.", fill="black", font=font_small)

    card.save(output_path)
    return output_filename


# ---------------------- EMAIL SENDER ----------------------

def send_card_email(to_email, child_name, card_path, card_number):
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASSWORD")

    msg = EmailMessage()
    msg["Subject"] = f"Radcliffe FC – Membership Card ({card_number})"
    msg["From"] = os.getenv("FROM_EMAIL")
    msg["To"] = to_email

    msg.set_content(
        f"Hello,\n\nYour digital membership card for {child_name} is attached.\n\nRegards,\nRadcliffe FC"
    )

    with open(card_path, "rb") as f:
        msg.add_attachment(
            f.read(),
            maintype="image",
            subtype="png",
            filename=os.path.basename(card_path)
        )

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)


# ---------------------- ROUTES ----------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        if User.query.filter_by(email=email).first():
            flash("Email already exists")
            return redirect(url_for("register"))

        user = User(email=email, is_admin=False)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Account created, please login.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if not user or not user.check_password(password):
            flash("Invalid login")
            return redirect(url_for("login"))

        login_user(user)
        return redirect(url_for("dashboard"))

    # FIX: Do NOT pass a WTForms form → your template will not use form.hidden_tag()
    return render_template("login.html")


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    apps = Application.query.all() if current_user.is_admin else []
    return render_template("dashboard.html", apps=apps)


@app.route("/apply", methods=["GET", "POST"])
@login_required
def apply():
    if request.method == "POST":

        parent_email = request.form["parent_email"]
        parent_name = request.form["parent_name"]
        child_name = request.form["child_name"]

        file = request.files["photo"]
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        app_entry = Application(
            parent_email=parent_email,
            parent_name=parent_name,
            child_name=child_name,
            photo_filename=filename
        )
        db.session.add(app_entry)
        db.session.commit()

        flash("Membership application submitted!")
        return redirect(url_for("dashboard"))

    return render_template("apply.html")


@app.route("/admin/applications")
@login_required
def admin_applications():
    if not current_user.is_admin:
        flash("Not authorised.")
        return redirect(url_for("dashboard"))

    apps = Application.query.order_by(Application.id.desc()).all()
    return render_template("admin_applications.html", apps=apps)


@app.route("/admin/application/<int:app_id>")
@login_required
def admin_application_detail(app_id):
    if not current_user.is_admin:
        flash("Not authorised.")
        return redirect(url_for("dashboard"))

    app_row = Application.query.get_or_404(app_id)
    return render_template("admin_application_detail.html", app=app_row)


@app.route("/admin/application/<int:app_id>/approve", methods=["POST"])
@login_required
def admin_approve(app_id):

    if not current_user.is_admin:
        flash("Not authorised.")
        return redirect(url_for("dashboard"))

    app_row = Application.query.get_or_404(app_id)

    card_number = f"RJ-{str(app_row.id).zfill(6)}"
    app_row.card_number = card_number

    photo_path = os.path.join(UPLOAD_FOLDER, app_row.photo_filename)
    filename = generate_card_image(app_row.child_name, card_number, photo_path)
    app_row.card_filename = filename

    card_path = os.path.join(CARD_FOLDER, filename)
    send_card_email(app_row.parent_email, app_row.child_name, card_path, card_number)

    app_row.status = "Approved"
    db.session.commit()

    flash("Card generated & emailed!")
    return redirect(url_for("admin_applications"))


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


@app.route("/cards/<path:filename>")
def cards_file(filename):
    return send_from_directory(CARD_FOLDER, filename)


@app.route("/make-me-admin-once")
def make_admin_once():
    user = User.query.first()
    if user:
        user.is_admin = True
        db.session.commit()
        return "Admin granted once."
    return "No users."


if __name__ == "__main__":
    app.run(debug=True)
