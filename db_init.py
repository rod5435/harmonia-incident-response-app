from app import create_app
from models import db, Indicator
import json
from datetime import datetime

app = create_app()
app.app_context().push()

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

if __name__ == '__main__':
    db.create_all()
    load_sample_data()
