"""Users, OAuth clients, authorization codes and tokens (SQLAlchemy; SQLite by default, any DATABASE_URL works)."""

import time
import uuid

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from authlib.integrations.sqla_oauth2 import OAuth2AuthorizationCodeMixin, OAuth2ClientMixin, OAuth2TokenMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
_ph = PasswordHasher()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sub = db.Column(db.String(32), unique=True, nullable=False, default=lambda: uuid.uuid4().hex)  # stable OIDC subject
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255), default="")
    password_hash = db.Column(db.Text, nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.Integer, nullable=False, default=lambda: int(time.time()))

    def get_user_id(self):
        return self.id

    def set_password(self, password):
        self.password_hash = _ph.hash(password)

    def check_password(self, password):
        try:
            ok = _ph.verify(self.password_hash, password)
        except (VerificationError, InvalidHashError):
            return False
        if ok and _ph.check_needs_rehash(self.password_hash):
            self.set_password(password)
            db.session.commit()
        return ok


class Client(db.Model, OAuth2ClientMixin):
    id = db.Column(db.Integer, primary_key=True)


class AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"))
    user = db.relationship("User")
    # auth_time is when the user signed in (it goes into the ID token), so a code's age is measured from issued_at
    issued_at = db.Column(db.Integer, nullable=False, default=lambda: int(time.time()))

    def is_expired(self):
        return self.issued_at + 300 < time.time()


class UsedNonce(db.Model):
    """Nonces of codes already exchanged, kept a day, so a sign-in request can't be replayed after its code is gone."""

    client_id = db.Column(db.String(48), primary_key=True)
    nonce = db.Column(db.String(255), primary_key=True)
    used_at = db.Column(db.Integer, nullable=False, default=lambda: int(time.time()))


class Token(db.Model, OAuth2TokenMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"))
    user = db.relationship("User")
