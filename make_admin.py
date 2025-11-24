from app import app, db, User

def make_admin():
    email = input("Enter the email address to make admin: ").strip().lower()

    with app.app_context():
        user = User.query.filter_by(email=email).first()
        if not user:
            print(f"No user found with email: {email}")
            return

        user.is_admin = True
        db.session.commit()
        print(f"✅ User {email} is now an admin.")

if __name__ == "__main__":
    make_admin()
