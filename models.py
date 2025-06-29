from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

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

class Export(db.Model):
    __tablename__ = 'exports'

    id = db.Column(db.Integer, primary_key=True)
    export_type = db.Column(db.String(50))  # 'pdf', 'excel', 'html', 'data'
    report_type = db.Column(db.String(50))  # 'executive', 'technical', 'comprehensive', 'data'
    format_type = db.Column(db.String(20))  # 'pdf', 'xlsx', 'html', 'json', 'csv'
    days = db.Column(db.Integer)
    filename = db.Column(db.String(255))
    file_size = db.Column(db.Integer)  # in bytes
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)
    parameters = db.Column(db.Text)  # JSON string of additional parameters

class DataUpdate(db.Model):
    __tablename__ = 'data_updates'

    id = db.Column(db.Integer, primary_key=True)
    update_type = db.Column(db.String(50))  # 'etl_pipeline', 'manual_update'
    status = db.Column(db.String(50))  # 'success', 'failed', 'in_progress'
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    records_processed = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text)
    details = db.Column(db.Text)  # JSON string of additional details
