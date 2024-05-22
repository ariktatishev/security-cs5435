from sqlalchemy import Column, Integer, String

from app.models.base import Base
from app.util.hash import random_salt, hash_pbkdf2

class User(Base):
    __tablename__ = "users"

    username = Column(String, primary_key=True)
    salt = Column(String)
    salted_password = Column(String)
    coins = Column(Integer)

    def get_coins(self):
        return self.coins

    def credit_coins(self, i):
        self.coins += i

    def debit_coins(self, i):
        self.coins -= i

def create_user(db, username, password):
    salt = random_salt()
    salted_password = hash_pbkdf2(password, salt)
    user = User(
        username=username,
        salt=salt,
        salted_password=salted_password,
        coins=100,
    )
    db.add(user)
    return user

def get_user(db, username):
    return db.query(User).filter_by(username=username).first()


