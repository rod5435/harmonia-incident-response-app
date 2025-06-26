from models import Indicator
from models import db
from sqlalchemy import func
from datetime import datetime, timedelta

def get_indicator_counts():
    return db.session.query(
        Indicator.indicator_type,
        func.count(Indicator.id)
    ).group_by(Indicator.indicator_type).all()

def get_indicators_by_type(indicator_type=None, limit=100):
    query = Indicator.query
    if indicator_type and indicator_type.lower() != 'all':
        query = query.filter_by(indicator_type=indicator_type)
    return query.limit(limit).all()

def get_severity_distribution():
    """Get distribution of indicators by severity score"""
    results = db.session.query(
        Indicator.severity_score,
        func.count(Indicator.id)
    ).group_by(Indicator.severity_score).all()
    
    # Convert to list of lists for JSON serialization
    return [[str(score) if score else 'Unknown', count] for score, count in results]

def get_source_distribution():
    """Get distribution of indicators by source"""
    results = db.session.query(
        Indicator.source,
        func.count(Indicator.id)
    ).group_by(Indicator.source).all()
    
    # Convert to list of lists for JSON serialization
    return [[str(source) if source else 'Unknown', count] for source, count in results]

def get_recent_indicators(days=30):
    """Get indicators added in the last N days"""
    cutoff_date = datetime.now() - timedelta(days=days)
    results = db.session.query(
        func.date(Indicator.date_added).label('date'),
        func.count(Indicator.id)
    ).filter(
        Indicator.date_added >= cutoff_date.strftime('%Y-%m-%d')
    ).group_by(
        func.date(Indicator.date_added)
    ).order_by(
        func.date(Indicator.date_added)
    ).all()
    
    # Convert to list of lists for JSON serialization
    return [[str(date) if date else 'Unknown', count] for date, count in results]

def get_top_techniques(limit=10):
    """Get most common MITRE techniques"""
    results = db.session.query(
        Indicator.name,
        func.count(Indicator.id)
    ).filter(
        Indicator.indicator_type == 'MITRE Technique'
    ).group_by(
        Indicator.name
    ).order_by(
        func.count(Indicator.id).desc()
    ).limit(limit).all()
    
    # Convert to list of lists for JSON serialization
    return [[str(name) if name else 'Unknown', count] for name, count in results]

def get_dashboard_stats():
    """Get comprehensive dashboard statistics"""
    total_indicators = Indicator.query.count()
    mitre_count = Indicator.query.filter_by(indicator_type='MITRE Technique').count()
    cve_count = Indicator.query.filter_by(indicator_type='CVE Vulnerability').count()
    
    # Get recent activity (last 7 days)
    week_ago = datetime.now() - timedelta(days=7)
    recent_count = Indicator.query.filter(
        Indicator.date_added >= week_ago.strftime('%Y-%m-%d')
    ).count()
    
    return {
        'total_indicators': int(total_indicators),
        'mitre_count': int(mitre_count),
        'cve_count': int(cve_count),
        'recent_count': int(recent_count),
        'severity_distribution': get_severity_distribution(),
        'source_distribution': get_source_distribution(),
        'recent_trend': get_recent_indicators(7),
        'top_techniques': get_top_techniques(5)
    }
