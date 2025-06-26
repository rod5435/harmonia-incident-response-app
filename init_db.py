from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import json
from datetime import datetime
import os
import sqlite3

# Create a minimal Flask app for database initialization
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///incident_response.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Define models here to avoid circular imports
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

def load_sample_data():
    with open('sample_data.json', 'r') as f:
        data = json.load(f)

    for record in data:
        indicator = Indicator(
            indicator_type=record.get('indicator_type'),
            indicator_value=record.get('indicator_value'),
            name=record.get('name'),
            description=record.get('description'),
            source=record.get('source'),
            severity_score=record.get('severity_score'),
            date_added=record.get('date_added'),
            timestamp=record.get('timestamp') or datetime.utcnow().isoformat()
        )
        db.session.add(indicator)
    db.session.commit()
    print(f"Loaded {len(data)} sample indicators.")

def check_database_tables():
    """Check what tables exist in the database"""
    try:
        conn = sqlite3.connect('incident_response.db')
        cursor = conn.cursor()
        
        # Get list of tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        print("\n=== DATABASE TABLES ===")
        if tables:
            for table in tables:
                print(f"✓ Table: {table[0]}")
                
                # Count rows in each table
                cursor.execute(f"SELECT COUNT(*) FROM {table[0]}")
                count = cursor.fetchone()[0]
                print(f"  - Rows: {count}")
        else:
            print("❌ No tables found in database!")
            
        conn.close()
        
    except Exception as e:
        print(f"❌ Error checking database: {e}")

if __name__ == '__main__':
    with app.app_context():
        print("=== DATABASE INITIALIZATION ===")
        
        # Create all tables
        db.create_all()
        print("✓ Database tables created successfully.")
        
        # Check what tables were created
        check_database_tables()
        
        # Load sample data
        load_sample_data()
        
        # Check again after loading data
        print("\n=== AFTER LOADING SAMPLE DATA ===")
        check_database_tables()
        
        print("\n✅ Database initialization complete!") 