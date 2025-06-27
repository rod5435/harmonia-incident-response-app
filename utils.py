from models import Indicator, db, Export
from sqlalchemy import func, or_, and_
from datetime import datetime, timedelta
import json
import os

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

def advanced_search_indicators(
    search_term=None, 
    indicator_type=None, 
    severity_min=None, 
    severity_max=None,
    date_from=None,
    date_to=None,
    source=None,
    page=1,
    per_page=20,
    sort_by='id',
    sort_order='desc'
):
    """
    Advanced search function with multiple filters and pagination
    """
    query = Indicator.query
    
    # Global search across multiple fields
    if search_term and search_term.strip():
        search_filter = or_(
            Indicator.name.ilike(f'%{search_term.strip()}%'),
            Indicator.description.ilike(f'%{search_term.strip()}%'),
            Indicator.indicator_value.ilike(f'%{search_term.strip()}%'),
            Indicator.source.ilike(f'%{search_term.strip()}%')
        )
        query = query.filter(search_filter)
    
    # Filter by indicator type
    if indicator_type and indicator_type.strip() and indicator_type.lower() != 'all':
        query = query.filter_by(indicator_type=indicator_type.strip())
    
    # Filter by severity score range
    if severity_min is not None or severity_max is not None:
        severity_filters = []
        if severity_min is not None and str(severity_min).strip():
            try:
                severity_filters.append(Indicator.severity_score >= str(severity_min))
            except:
                pass
        if severity_max is not None and str(severity_max).strip():
            try:
                severity_filters.append(Indicator.severity_score <= str(severity_max))
            except:
                pass
        if severity_filters:
            query = query.filter(and_(*severity_filters))
    
    # Filter by date range
    if date_from and date_from.strip():
        query = query.filter(Indicator.date_added >= date_from.strip())
    if date_to and date_to.strip():
        query = query.filter(Indicator.date_added <= date_to.strip())
    
    # Filter by source
    if source and source.strip():
        query = query.filter(Indicator.source.ilike(f'%{source.strip()}%'))
    
    # Sorting
    sort_column = getattr(Indicator, sort_by, Indicator.id)
    if sort_order.lower() == 'desc':
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())
    
    # Pagination
    total = query.count()
    pagination = query.paginate(
        page=page, 
        per_page=per_page, 
        error_out=False
    )
    
    # Convert Indicator objects to dictionaries for JSON serialization
    items = []
    for indicator in pagination.items:
        items.append({
            'id': indicator.id,
            'name': indicator.name,
            'type': indicator.indicator_type,
            'description': indicator.description,
            'severity_score': indicator.severity_score,
            'source': indicator.source,
            'date_added': indicator.date_added,
            'indicator_value': indicator.indicator_value
        })
    
    return {
        'items': items,
        'total': total,
        'pages': pagination.pages,
        'current_page': page,
        'per_page': per_page,
        'has_prev': pagination.has_prev,
        'has_next': pagination.has_next,
        'prev_num': pagination.prev_num,
        'next_num': pagination.next_num
    }

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

def get_filter_options():
    """Get available filter options for the UI"""
    # Get unique sources
    sources = db.session.query(Indicator.source).distinct().all()
    sources = [source[0] for source in sources if source and source[0]]
    
    # Get unique severity scores
    severities = db.session.query(Indicator.severity_score).distinct().all()
    severities = [sev[0] for sev in severities if sev and sev[0]]
    
    # Get date range
    date_range = db.session.query(
        func.min(Indicator.date_added),
        func.max(Indicator.date_added)
    ).first()
    
    return {
        'sources': sources,
        'severities': severities,
        'date_range': {
            'min': date_range[0] if date_range and date_range[0] else None,
            'max': date_range[1] if date_range and date_range[1] else None
        }
    }

def format_indicator_for_json(indicator):
    """Format an Indicator object for JSON serialization"""
    if not indicator:
        return None
    
    return {
        'id': indicator.id,
        'indicator_type': indicator.indicator_type,
        'indicator_value': indicator.indicator_value,
        'name': indicator.name,
        'description': indicator.description,
        'source': indicator.source,
        'severity_score': indicator.severity_score,
        'date_added': indicator.date_added,
        'timestamp': indicator.timestamp
    }

def record_export(export_type, report_type, format_type, days, filename, file_size=None, parameters=None):
    """Record an export in the database"""
    try:
        export = Export(
            export_type=export_type,
            report_type=report_type,
            format_type=format_type,
            days=days,
            filename=filename,
            file_size=file_size or 0,
            parameters=json.dumps(parameters) if parameters else None
        )
        db.session.add(export)
        db.session.commit()
        return True
    except Exception as e:
        print(f"Error recording export: {e}")
        db.session.rollback()
        return False

def get_export_history(limit=20):
    """Get recent export history"""
    try:
        exports = Export.query.order_by(Export.generated_at.desc()).limit(limit).all()
        return [
            {
                'id': export.id,
                'export_type': export.export_type,
                'report_type': export.report_type,
                'format_type': export.format_type,
                'days': export.days,
                'filename': export.filename,
                'file_size': export.file_size,
                'generated_at': export.generated_at.strftime('%Y-%m-%d %H:%M:%S'),
                'parameters': json.loads(export.parameters) if export.parameters else {}
            }
            for export in exports
        ]
    except Exception as e:
        print(f"Error getting export history: {e}")
        return []
