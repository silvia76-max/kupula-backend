from datetime import datetime
from app import db, bcrypt

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    auth0_id = db.Column(db.String(120), unique=True, nullable=False)  # "auth0|123..."
    email = db.Column(db.String(120), unique=True, nullable=False)
    nickname = db.Column(db.String(80))
    picture = db.Column(db.String(200))
    updated_at = db.Column(db.DateTime)

    def __repr__(self):
        return f'<User {self.username}>'

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
