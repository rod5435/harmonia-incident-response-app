from flask import Flask, render_template, request, jsonify
from config import SQLALCHEMY_DATABASE_URI, SQLALCHEMY_TRACK_MODIFICATIONS
from models import db, Indicator, UserQuery
from utils import get_indicator_counts, get_indicators_by_type, get_dashboard_stats, advanced_search_indicators, get_filter_options
from openai_integration import ask_gpt, analyze_threat_patterns, generate_threat_report, correlate_threats, analyze_attack_chain, get_ai_insights_summary
from datetime import datetime
import traceback

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = SQLALCHEMY_TRACK_MODIFICATIONS
    db.init_app(app)

    @app.route('/')
    def index():
        # Get some basic stats for the landing page
        try:
            total_indicators = Indicator.query.count()
            mitre_count = Indicator.query.filter_by(indicator_type='MITRE Technique').count()
            cve_count = Indicator.query.filter_by(indicator_type='CVE Vulnerability').count()
        except:
            total_indicators = 0
            mitre_count = 0
            cve_count = 0
        
        return render_template('index.html', 
                             total_indicators=total_indicators,
                             mitre_count=mitre_count,
                             cve_count=cve_count)

    @app.route('/data-explorer')
    def data_explorer():
        types = [t[0] for t in get_indicator_counts()]
        filter_options = get_filter_options()
        return render_template('data_explorer.html', 
                             indicator_types=types,
                             filter_options=filter_options)

    @app.route('/api/indicators')
    def api_indicators():
        indicator_type = request.args.get('type', default=None)
        indicators = get_indicators_by_type(indicator_type)
        results = []
        for ind in indicators:
            results.append({
                'id': ind.id,
                'type': ind.indicator_type,
                'value': ind.indicator_value,
                'name': ind.name,
                'description': ind.description,
                'source': ind.source,
                'severity_score': ind.severity_score,
                'date_added': ind.date_added,
                'timestamp': ind.timestamp
            })
        return jsonify(results)

    @app.route('/api/advanced-search')
    def api_advanced_search():
        """Advanced search API endpoint"""
        try:
            # Get search parameters and convert empty strings to None
            search_term = request.args.get('search', default=None)
            if search_term == '':
                search_term = None
                
            indicator_type = request.args.get('type', default=None)
            if indicator_type == '':
                indicator_type = None
                
            severity_min = request.args.get('severity_min', default=None)
            if severity_min == '':
                severity_min = None
                
            severity_max = request.args.get('severity_max', default=None)
            if severity_max == '':
                severity_max = None
                
            date_from = request.args.get('date_from', default=None)
            if date_from == '':
                date_from = None
                
            date_to = request.args.get('date_to', default=None)
            if date_to == '':
                date_to = None
                
            source = request.args.get('source', default=None)
            if source == '':
                source = None
                
            page = int(request.args.get('page', default=1))
            per_page = int(request.args.get('per_page', default=20))
            sort_by = request.args.get('sort_by', default='id')
            sort_order = request.args.get('sort_order', default='desc')
            
            # Convert severity to float if provided
            if severity_min:
                try:
                    severity_min = float(severity_min)
                except:
                    severity_min = None
            if severity_max:
                try:
                    severity_max = float(severity_max)
                except:
                    severity_max = None
            
            # Perform advanced search
            result = advanced_search_indicators(
                search_term=search_term,
                indicator_type=indicator_type,
                severity_min=severity_min,
                severity_max=severity_max,
                date_from=date_from,
                date_to=date_to,
                source=source,
                page=page,
                per_page=per_page,
                sort_by=sort_by,
                sort_order=sort_order
            )
            
            # Convert results to JSON-serializable format
            items = []
            for ind in result['items']:
                items.append({
                    'id': ind.id,
                    'type': ind.indicator_type,
                    'value': ind.indicator_value,
                    'name': ind.name,
                    'description': ind.description,
                    'source': ind.source,
                    'severity_score': ind.severity_score,
                    'date_added': ind.date_added,
                    'timestamp': ind.timestamp
                })
            
            return jsonify({
                'items': items,
                'total': result['total'],
                'pages': result['pages'],
                'current_page': result['current_page'],
                'per_page': result['per_page'],
                'has_prev': result['has_prev'],
                'has_next': result['has_next'],
                'prev_num': result['prev_num'],
                'next_num': result['next_num']
            })
            
        except Exception as e:
            print(f"Advanced search error: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/filter-options')
    def api_filter_options():
        """Get available filter options"""
        try:
            options = get_filter_options()
            return jsonify(options)
        except Exception as e:
            print(f"Filter options error: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/dashboard')
    def dashboard():
        try:
            stats = get_dashboard_stats()
            # Test JSON serialization
            import json
            json.dumps(stats)
        except Exception as e:
            print(f"Dashboard error: {e}")
            print(traceback.format_exc())
            # Fallback to safe default values
            stats = {
                'total_indicators': 0,
                'mitre_count': 0,
                'cve_count': 0,
                'recent_count': 0,
                'severity_distribution': [],
                'source_distribution': [],
                'recent_trend': [],
                'top_techniques': []
            }
        return render_template('dashboard.html', stats=stats)

    @app.route('/ai-insights', methods=['GET', 'POST'])
    def ai_insights():
        if request.method == 'POST':
            question = request.form.get('question')
            last_indicators = Indicator.query.order_by(Indicator.timestamp.desc()).limit(10).all()
            context = "\n".join([f"{ind.name}: {ind.description}" for ind in last_indicators])
            answer = ask_gpt(question, context)

            user_query = UserQuery(
                question=question,
                answer=answer,
                timestamp=datetime.utcnow().isoformat()
            )
            db.session.add(user_query)
            db.session.commit()
            return render_template('ai_insights.html', question=question, answer=answer)
        return render_template('ai_insights.html', question=None, answer=None)

    # Enhanced AI Features Routes
    @app.route('/ai-analysis')
    def ai_analysis():
        """Enhanced AI Analysis page"""
        return render_template('ai_analysis.html')

    @app.route('/api/threat-analysis')
    def api_threat_analysis():
        """Threat pattern analysis API"""
        try:
            days = int(request.args.get('days', default=30))
            analysis = analyze_threat_patterns(days)
            return jsonify({'analysis': analysis})
        except Exception as e:
            print(f"Threat analysis error: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/generate-report')
    def api_generate_report():
        """Generate threat intelligence report API"""
        try:
            report_type = request.args.get('type', default='comprehensive')
            days = int(request.args.get('days', default=30))
            report = generate_threat_report(report_type, days)
            return jsonify({'report': report})
        except Exception as e:
            print(f"Report generation error: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/correlate-threats')
    def api_correlate_threats():
        """Threat correlation API"""
        try:
            indicator_id = request.args.get('indicator_id', default=None)
            search_term = request.args.get('search_term', default=None)
            
            if indicator_id:
                indicator_id = int(indicator_id)
            
            correlation = correlate_threats(indicator_id, search_term)
            return jsonify({'correlation': correlation})
        except Exception as e:
            print(f"Threat correlation error: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/attack-chain-analysis')
    def api_attack_chain_analysis():
        """MITRE ATT&CK attack chain analysis API"""
        try:
            technique_name = request.args.get('technique', default=None)
            analysis = analyze_attack_chain(technique_name)
            return jsonify({'analysis': analysis})
        except Exception as e:
            print(f"Attack chain analysis error: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/ai-insights-summary')
    def api_ai_insights_summary():
        """Get AI insights summary API"""
        try:
            summary = get_ai_insights_summary()
            return jsonify({'summary': summary})
        except Exception as e:
            print(f"AI insights summary error: {e}")
            return jsonify({'error': str(e)}), 500

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
