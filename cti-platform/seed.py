from app import create_app
from app.extensions import db
from app.models.user import User

app = create_app()

with app.app_context():
    db.create_all()

    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", email="admin@ctiplatform.local",
                     full_name="System Administrator", role="admin")
        admin.set_password("Admin@123")
        db.session.add(admin)
        print("Created admin")
    else:
        print("admin already exists")

    if not User.query.filter_by(username="analyst").first():
        analyst = User(username="analyst", email="analyst@ctiplatform.local",
                        full_name="Threat Analyst", role="analyst")
        analyst.set_password("Analyst@123")
        db.session.add(analyst)
        print("Created analyst")
    else:
        print("analyst already exists")

    db.session.commit()
    print("\nDone. Log in with:")
    print("  admin   / Admin@123")
    print("  analyst / Analyst@123")