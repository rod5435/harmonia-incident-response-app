from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Indicator(db.Model):
    __tablename__ = 'indicators'

    id = db.Column(db.Integer, primary_key=True)
    indicator_type = db.Column(db.String(50))
    indicator_value = db.Column(db.String(255))
    name = db.Column(db.String(255))
    description = db.Column(db.Text)
    source = db.Column(db.String(100))
    severity_score = db.Column(db.String(20))
    date_added = db.Column(db.String(20))
    timestamp = db.Column(db.String(50))

class UserQuery(db.Model):
    __tablename__ = 'user_queries'

    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.Text)
    answer = db.Column(db.Text)
    timestamp = db.Column(db.String(50))
