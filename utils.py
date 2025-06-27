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
    """Get comprehensive dashboard statistics for all 3 data sources"""
    total_indicators = Indicator.query.count()
    mitre_count = Indicator.query.filter_by(indicator_type='MITRE Technique').count()
    cve_count = Indicator.query.filter_by(indicator_type='CVE Vulnerability').count()
    urlhaus_count = Indicator.query.filter_by(indicator_type='Malicious URL').count()
    
    # Get recent activity (last 7 days)
    week_ago = datetime.now() - timedelta(days=7)
    recent_count = Indicator.query.filter(
        Indicator.date_added >= week_ago.strftime('%Y-%m-%d')
    ).count()
    
    return {
        'total_indicators': int(total_indicators),
        'mitre_count': int(mitre_count),
        'cve_count': int(cve_count),
        'urlhaus_count': int(urlhaus_count),
        'recent_count': int(recent_count),
        'severity_distribution': get_severity_distribution(),
        'source_distribution': get_source_distribution(),
        'recent_trend': get_recent_indicators(7),
        'top_techniques': get_top_techniques(5),
        'source_breakdown': {
            'MITRE ATT&CK': mitre_count,
            'CISA KEV': cve_count,
            'Abuse.ch URLhaus': urlhaus_count
        }
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

def get_filtered_dashboard_stats(time_range=7, severity_filter='all', sources=None):
    """Get filtered dashboard statistics based on time range, severity, and sources"""
    if sources is None:
        sources = ['MITRE ATT&CK', 'CISA KEV', 'Abuse.ch URLhaus']
    
    print(f"get_filtered_dashboard_stats called with: time_range={time_range}, severity={severity_filter}, sources={sources}")
    
    # Build base query
    query = Indicator.query
    
    # Apply time filter
    if time_range != 'all':
        try:
            days = int(time_range)
            cutoff_date = datetime.now() - timedelta(days=days)
            query = query.filter(Indicator.date_added >= cutoff_date.strftime('%Y-%m-%d'))
        except (ValueError, TypeError):
            # If time_range is not a valid number, skip time filtering
            pass
    
    # Apply severity filter
    if severity_filter != 'all':
        if severity_filter == 'high':
            query = query.filter(Indicator.severity_score >= 8)
        elif severity_filter == 'medium':
            query = query.filter(Indicator.severity_score >= 4, Indicator.severity_score < 8)
        elif severity_filter == 'low':
            query = query.filter(Indicator.severity_score < 4)
    
    # Apply source filters
    source_filters = []
    if 'MITRE ATT&CK' in sources:
        source_filters.append(Indicator.indicator_type == 'MITRE Technique')
    if 'CISA KEV' in sources:
        source_filters.append(Indicator.indicator_type == 'CVE Vulnerability')
    if 'Abuse.ch URLhaus' in sources:
        source_filters.append(Indicator.indicator_type == 'Malicious URL')
    
    if source_filters:
        from sqlalchemy import or_
        query = query.filter(or_(*source_filters))
    
    # Get filtered counts
    total_indicators = query.count()
    mitre_count = query.filter_by(indicator_type='MITRE Technique').count()
    cve_count = query.filter_by(indicator_type='CVE Vulnerability').count()
    urlhaus_count = query.filter_by(indicator_type='Malicious URL').count()
    
    # Get recent activity for the filtered data
    recent_trend = get_filtered_recent_indicators(time_range, severity_filter, sources)
    
    # Get severity distribution for filtered data
    severity_distribution = get_filtered_severity_distribution(time_range, severity_filter, sources)
    
    # Get top techniques for filtered data
    top_techniques = get_filtered_top_techniques(time_range, severity_filter, sources)
    
    return {
        'total_indicators': int(total_indicators),
        'mitre_count': int(mitre_count),
        'cve_count': int(cve_count),
        'urlhaus_count': int(urlhaus_count),
        'recent_count': int(total_indicators),  # For filtered data, this is the same as total
        'severity_distribution': severity_distribution,
        'source_distribution': get_filtered_source_distribution(time_range, severity_filter, sources),
        'recent_trend': recent_trend,
        'top_techniques': top_techniques,
        'source_breakdown': {
            'MITRE ATT&CK': mitre_count,
            'CISA KEV': cve_count,
            'Abuse.ch URLhaus': urlhaus_count
        }
    }

def get_filtered_recent_indicators(days=7, severity_filter='all', sources=None):
    """Get recent indicators with filters applied"""
    if sources is None:
        sources = ['MITRE ATT&CK', 'CISA KEV', 'Abuse.ch URLhaus']
    
    query = Indicator.query
    
    # Apply time filter
    if days != 'all':
        try:
            days_int = int(days)
            cutoff_date = datetime.now() - timedelta(days=days_int)
            query = query.filter(Indicator.date_added >= cutoff_date.strftime('%Y-%m-%d'))
        except (ValueError, TypeError):
            # If days is not a valid number, skip time filtering
            pass
    
    # Apply severity filter
    if severity_filter != 'all':
        if severity_filter == 'high':
            query = query.filter(Indicator.severity_score >= 8)
        elif severity_filter == 'medium':
            query = query.filter(Indicator.severity_score >= 4, Indicator.severity_score < 8)
        elif severity_filter == 'low':
            query = query.filter(Indicator.severity_score < 4)
    
    # Apply source filters
    source_filters = []
    if 'MITRE ATT&CK' in sources:
        source_filters.append(Indicator.indicator_type == 'MITRE Technique')
    if 'CISA KEV' in sources:
        source_filters.append(Indicator.indicator_type == 'CVE Vulnerability')
    if 'Abuse.ch URLhaus' in sources:
        source_filters.append(Indicator.indicator_type == 'Malicious URL')
    
    if source_filters:
        from sqlalchemy import or_
        query = query.filter(or_(*source_filters))
    
    results = query.with_entities(
        func.date(Indicator.date_added).label('date'),
        func.count(Indicator.id)
    ).group_by(
        func.date(Indicator.date_added)
    ).order_by(
        func.date(Indicator.date_added)
    ).all()
    
    return [[str(date) if date else 'Unknown', count] for date, count in results]

def get_filtered_severity_distribution(days=7, severity_filter='all', sources=None):
    """Get severity distribution with filters applied"""
    if sources is None:
        sources = ['MITRE ATT&CK', 'CISA KEV', 'Abuse.ch URLhaus']
    
    query = Indicator.query
    
    # Apply time filter
    if days != 'all':
        cutoff_date = datetime.now() - timedelta(days=days)
        query = query.filter(Indicator.date_added >= cutoff_date.strftime('%Y-%m-%d'))
    
    # Apply source filters
    source_filters = []
    if 'MITRE ATT&CK' in sources:
        source_filters.append(Indicator.indicator_type == 'MITRE Technique')
    if 'CISA KEV' in sources:
        source_filters.append(Indicator.indicator_type == 'CVE Vulnerability')
    if 'Abuse.ch URLhaus' in sources:
        source_filters.append(Indicator.indicator_type == 'Malicious URL')
    
    if source_filters:
        from sqlalchemy import or_
        query = query.filter(or_(*source_filters))
    
    results = query.with_entities(
        Indicator.severity_score,
        func.count(Indicator.id)
    ).group_by(Indicator.severity_score).all()
    
    return [[str(score) if score else 'Unknown', count] for score, count in results]

def get_filtered_source_distribution(days=7, severity_filter='all', sources=None):
    """Get source distribution with filters applied"""
    if sources is None:
        sources = ['MITRE ATT&CK', 'CISA KEV', 'Abuse.ch URLhaus']
    
    query = Indicator.query
    
    # Apply time filter
    if days != 'all':
        cutoff_date = datetime.now() - timedelta(days=days)
        query = query.filter(Indicator.date_added >= cutoff_date.strftime('%Y-%m-%d'))
    
    # Apply severity filter
    if severity_filter != 'all':
        if severity_filter == 'high':
            query = query.filter(Indicator.severity_score >= 8)
        elif severity_filter == 'medium':
            query = query.filter(Indicator.severity_score >= 4, Indicator.severity_score < 8)
        elif severity_filter == 'low':
            query = query.filter(Indicator.severity_score < 4)
    
    # Apply source filters
    source_filters = []
    if 'MITRE ATT&CK' in sources:
        source_filters.append(Indicator.indicator_type == 'MITRE Technique')
    if 'CISA KEV' in sources:
        source_filters.append(Indicator.indicator_type == 'CVE Vulnerability')
    if 'Abuse.ch URLhaus' in sources:
        source_filters.append(Indicator.indicator_type == 'Malicious URL')
    
    if source_filters:
        from sqlalchemy import or_
        query = query.filter(or_(*source_filters))
    
    results = query.with_entities(
        Indicator.source,
        func.count(Indicator.id)
    ).group_by(Indicator.source).all()
    
    return [[str(source) if source else 'Unknown', count] for source, count in results]

def get_filtered_top_techniques(days=7, severity_filter='all', sources=None, limit=5):
    """Get top techniques with filters applied"""
    if sources is None:
        sources = ['MITRE ATT&CK', 'CISA KEV', 'Abuse.ch URLhaus']
    
    query = Indicator.query
    
    # Apply time filter
    if days != 'all':
        cutoff_date = datetime.now() - timedelta(days=days)
        query = query.filter(Indicator.date_added >= cutoff_date.strftime('%Y-%m-%d'))
    
    # Apply severity filter
    if severity_filter != 'all':
        if severity_filter == 'high':
            query = query.filter(Indicator.severity_score >= 8)
        elif severity_filter == 'medium':
            query = query.filter(Indicator.severity_score >= 4, Indicator.severity_score < 8)
        elif severity_filter == 'low':
            query = query.filter(Indicator.severity_score < 4)
    
    # Apply source filters
    source_filters = []
    if 'MITRE ATT&CK' in sources:
        source_filters.append(Indicator.indicator_type == 'MITRE Technique')
    if 'CISA KEV' in sources:
        source_filters.append(Indicator.indicator_type == 'CVE Vulnerability')
    if 'Abuse.ch URLhaus' in sources:
        source_filters.append(Indicator.indicator_type == 'Malicious URL')
    
    if source_filters:
        from sqlalchemy import or_
        query = query.filter(or_(*source_filters))
    
    results = query.with_entities(
        Indicator.name,
        func.count(Indicator.id)
    ).filter(
        Indicator.indicator_type == 'MITRE Technique'
    ).group_by(
        Indicator.name
    ).order_by(
        func.count(Indicator.id).desc()
    ).limit(limit).all()
    
    return [[str(name) if name else 'Unknown', count] for name, count in results]
