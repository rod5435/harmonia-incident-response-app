import sqlite3
import json
from datetime import datetime
import os

def create_database():
    """Create database tables using direct SQLite commands"""
    
    # Remove existing database file if it exists
    if os.path.exists('incident_response.db'):
        os.remove('incident_response.db')
        print("Removed existing database file.")
    
    # Create new database connection
    conn = sqlite3.connect('incident_response.db')
    cursor = conn.cursor()
    
    # Create indicators table
    cursor.execute('''
        CREATE TABLE indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator_type VARCHAR(50),
            indicator_value VARCHAR(255),
            name VARCHAR(255),
            description TEXT,
            source VARCHAR(100),
            severity_score VARCHAR(20),
            date_added VARCHAR(20),
            timestamp VARCHAR(50)
        )
    ''')
    
    # Create user_queries table
    cursor.execute('''
        CREATE TABLE user_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            question TEXT,
            answer TEXT,
            timestamp VARCHAR(50)
        )
    ''')
    
    conn.commit()
    print("✓ Database tables created successfully.")
    
    # Verify tables were created
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    print(f"✓ Found {len(tables)} tables: {[table[0] for table in tables]}")
    
    return conn, cursor

def load_sample_data(cursor, conn):
    """Load sample data from JSON file"""
    try:
        with open('sample_data.json', 'r') as f:
            data = json.load(f)
        
        for record in data:
            cursor.execute('''
                INSERT INTO indicators 
                (indicator_type, indicator_value, name, description, source, severity_score, date_added, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                record.get('indicator_type'),
                record.get('indicator_value'),
                record.get('name'),
                record.get('description'),
                record.get('source'),
                record.get('severity_score'),
                record.get('date_added'),
                record.get('timestamp') or datetime.utcnow().isoformat()
            ))
        
        conn.commit()
        print(f"✓ Loaded {len(data)} sample indicators.")
        
        # Verify data was loaded
        cursor.execute("SELECT COUNT(*) FROM indicators")
        count = cursor.fetchone()[0]
        print(f"✓ Total indicators in database: {count}")
        
    except Exception as e:
        print(f"❌ Error loading sample data: {e}")

def check_database_state():
    """Check the final state of the database"""
    try:
        conn = sqlite3.connect('incident_response.db')
        cursor = conn.cursor()
        
        # Check tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        print("\n=== FINAL DATABASE STATE ===")
        for table in tables:
            print(f"✓ Table: {table[0]}")
            cursor.execute(f"SELECT COUNT(*) FROM {table[0]}")
            count = cursor.fetchone()[0]
            print(f"  - Rows: {count}")
            
            # Show sample data for indicators table
            if table[0] == 'indicators' and count > 0:
                cursor.execute("SELECT id, indicator_type, name FROM indicators LIMIT 3")
                rows = cursor.fetchall()
                print(f"  - Sample data: {rows}")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Error checking database state: {e}")

if __name__ == '__main__':
    print("=== SIMPLE DATABASE INITIALIZATION ===")
    
    # Create database and tables
    conn, cursor = create_database()
    
    # Load sample data
    load_sample_data(cursor, conn)
    
    # Close connection
    conn.close()
    
    # Check final state
    check_database_state()
    
    print("\n✅ Database initialization complete!") 