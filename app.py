from flask import Flask, render_template, request, jsonify, send_file
from config import SQLALCHEMY_DATABASE_URI, SQLALCHEMY_TRACK_MODIFICATIONS
from models import db, Indicator, UserQuery
from utils import get_indicator_counts, get_indicators_by_type, get_dashboard_stats, advanced_search_indicators, get_filter_options, record_export, get_export_history
from openai_integration import ask_gpt, analyze_threat_patterns, generate_threat_report, correlate_threats, analyze_attack_chain, get_ai_insights_summary
from reporting import ReportGenerator
from datetime import datetime
import traceback
import io
import json
import csv
import os
from dotenv import load_dotenv

load_dotenv()

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
            cisa_count = Indicator.query.filter_by(source='CISA KEV').count()
        except:
            total_indicators = 0
            mitre_count = 0
            cisa_count = 0
        
        return render_template('index.html', 
                             total_indicators=total_indicators,
                             mitre_count=mitre_count,
                             cisa_count=cisa_count)

    @app.route('/data-explorer')
    def data_explorer():
        """Data Explorer page"""
        try:
            # Get indicator types for the filter dropdown
            indicator_types = [t[0] for t in get_indicator_counts()]
            
            # Get filter options
            filter_options = get_filter_options()
            
            return render_template('data_explorer.html', 
                                 indicator_types=indicator_types,
                                 filter_options=filter_options)
        except Exception as e:
            print(f"Data explorer error: {e}")
            return render_template('data_explorer.html', 
                                 indicator_types=[],
                                 filter_options={'sources': [], 'severities': [], 'date_range': {'min': None, 'max': None}})

    @app.route('/api/indicators')
    def api_indicators():
        """Get indicators with pagination and basic filtering"""
        try:
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('per_page', 50, type=int)
            indicator_type = request.args.get('type', '')
            source = request.args.get('source', '')
            
            query = Indicator.query
            
            if indicator_type:
                query = query.filter(Indicator.indicator_type == indicator_type)
            if source:
                query = query.filter(Indicator.source == source)
            
            pagination = query.paginate(
                page=page, per_page=per_page, error_out=False
            )
            
            indicators = []
            for indicator in pagination.items:
                indicators.append({
                    'id': indicator.id,
                    'name': indicator.name,
                    'type': indicator.indicator_type,
                    'description': indicator.description,
                    'severity_score': indicator.severity_score,
                    'source': indicator.source,
                    'date_added': indicator.date_added,
                    'indicator_value': indicator.indicator_value
                })
            
            return jsonify({
                'indicators': indicators,
                'total': pagination.total,
                'pages': pagination.pages,
                'current_page': page,
                'has_next': pagination.has_next,
                'has_prev': pagination.has_prev
            })
        except Exception as e:
            print(f"API indicators error: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/advanced-search')
    def api_advanced_search():
        """Advanced search and filtering API"""
        try:
            # Get search parameters
            search_term = request.args.get('search', '')
            indicator_type = request.args.get('type', '')
            source = request.args.get('source', '')
            severity_min = request.args.get('severity_min', type=float)
            severity_max = request.args.get('severity_max', type=float)
            date_from = request.args.get('date_from', '')
            date_to = request.args.get('date_to', '')
            sort_by = request.args.get('sort_by', 'date_added')
            sort_order = request.args.get('sort_order', 'desc')
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('per_page', 50, type=int)
            
            # Get filtered data
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
            
            return jsonify(result)
            
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
        """Dashboard page"""
        try:
            # Get dashboard statistics using the existing function
            stats = get_dashboard_stats()
            return render_template('dashboard.html', stats=stats)
        except Exception as e:
            print(f"Dashboard error: {e}")
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
        """AI Insights page"""
        if request.method == 'POST':
            question = request.form.get('question')
            last_indicators = Indicator.query.order_by(Indicator.date_added.desc()).limit(10).all()
            context = "\n".join([f"{ind.name}: {ind.description}" for ind in last_indicators])
            answer = ask_gpt(question, context)

            user_query = UserQuery(
                question=question,
                answer=answer
            )
            db.session.add(user_query)
            db.session.commit()
            return render_template('ai_insights.html', question=question, answer=answer)
        return render_template('ai_insights.html', question=None, answer=None)

    @app.route('/ai-analysis')
    def ai_analysis():
        """AI Analysis page"""
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
            
            print(f"Generating report: type={report_type}, days={days}")
            
            # Check if we have any indicators in the database
            indicator_count = Indicator.query.count()
            print(f"Total indicators in database: {indicator_count}")
            
            if indicator_count == 0:
                return jsonify({'error': 'No threat indicators found in database. Please ensure data has been loaded.'}), 400
            
            report = generate_threat_report(report_type, days)
            
            if report.startswith("Error"):
                return jsonify({'error': report}), 500
            
            return jsonify({'report': report})
        except Exception as e:
            print(f"Report generation error: {e}")
            import traceback
            traceback.print_exc()
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

    @app.route('/api/export-history')
    def api_export_history():
        """Get export history"""
        try:
            limit = request.args.get('limit', default=20, type=int)
            exports = get_export_history(limit)
            return jsonify({'exports': exports})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # Export and Reporting Routes
    @app.route('/reports')
    def reports():
        """Reports and Export page"""
        return render_template('reports.html')

    @app.route('/export/pdf')
    def export_pdf():
        """Export PDF report"""
        try:
            report_type = request.args.get('type', default='comprehensive')
            days = int(request.args.get('days', default=30))
            
            generator = ReportGenerator()
            filename, error = generator.generate_pdf_report(report_type, days)
            
            if error or not filename:
                return jsonify({'error': error or 'Failed to generate PDF'}), 500
            
            filepath = os.path.join(generator.reports_dir, filename)
            
            # Record the export
            file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
            record_export(
                export_type='pdf',
                report_type=report_type,
                format_type='pdf',
                days=days,
                filename=filename,
                file_size=file_size,
                parameters={'type': report_type, 'days': days}
            )
            
            return send_file(
                filepath,
                as_attachment=True,
                download_name=filename,
                mimetype='application/pdf'
            )
        except Exception as e:
            print(f"PDF export error: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/export/excel')
    def export_excel():
        """Export Excel report"""
        try:
            report_type = request.args.get('type', default='comprehensive')
            days = int(request.args.get('days', default=30))
            
            generator = ReportGenerator()
            filename, error = generator.generate_excel_report(report_type, days)
            
            if error or not filename:
                return jsonify({'error': error or 'Failed to generate Excel file'}), 500
            
            filepath = os.path.join(generator.reports_dir, filename)
            
            # Record the export
            file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
            record_export(
                export_type='excel',
                report_type=report_type,
                format_type='xlsx',
                days=days,
                filename=filename,
                file_size=file_size,
                parameters={'type': report_type, 'days': days}
            )
            
            return send_file(
                filepath,
                as_attachment=True,
                download_name=filename,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            )
        except Exception as e:
            print(f"Excel export error: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/export/html')
    def export_html():
        """Export HTML report"""
        try:
            report_type = request.args.get('type', default='comprehensive')
            days = int(request.args.get('days', default=30))
            
            generator = ReportGenerator()
            filename, error = generator.generate_html_report(report_type, days)
            
            if error or not filename:
                return jsonify({'error': error or 'Failed to generate HTML file'}), 500
            
            filepath = os.path.join(generator.reports_dir, filename)
            
            # Record the export
            file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
            record_export(
                export_type='html',
                report_type=report_type,
                format_type='html',
                days=days,
                filename=filename,
                file_size=file_size,
                parameters={'type': report_type, 'days': days}
            )
            
            return send_file(
                filepath,
                as_attachment=True,
                download_name=filename,
                mimetype='text/html'
            )
        except Exception as e:
            print(f"HTML export error: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/export/data')
    def export_data():
        """Export raw data as JSON/CSV"""
        try:
            format_type = request.args.get('format', default='json')
            indicator_type = request.args.get('type', default=None)
            limit = int(request.args.get('limit', default=1000))
            
            # Get indicators
            query = Indicator.query
            if indicator_type and indicator_type.lower() != 'all':
                query = query.filter_by(indicator_type=indicator_type)
            
            indicators = query.limit(limit).all()
            
            if format_type == 'csv':
                output = io.StringIO()
                writer = csv.writer(output)
                
                # Write header
                writer.writerow(['ID', 'Type', 'Name', 'Description', 'Value', 'Source', 'Severity', 'Date Added'])
                
                # Write data
                for ind in indicators:
                    writer.writerow([
                        ind.id,
                        ind.indicator_type,
                        ind.name,
                        ind.description,
                        ind.indicator_value,
                        ind.source,
                        ind.severity_score,
                        ind.date_added
                    ])
                
                output.seek(0)
                filename = f"harmonia_indicators_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                
                # Record the export
                data_content = output.getvalue().encode('utf-8')
                record_export(
                    export_type='data',
                    report_type='data',
                    format_type='csv',
                    days=0,
                    filename=filename,
                    file_size=len(data_content),
                    parameters={'format': 'csv', 'type': indicator_type, 'limit': limit}
                )
                
                return send_file(
                    io.BytesIO(data_content),
                    as_attachment=True,
                    download_name=filename,
                    mimetype='text/csv'
                )
            else:  # JSON
                data = []
                for ind in indicators:
                    data.append({
                        'id': ind.id,
                        'type': ind.indicator_type,
                        'name': ind.name,
                        'description': ind.description,
                        'value': ind.indicator_value,
                        'source': ind.source,
                        'severity_score': ind.severity_score,
                        'date_added': ind.date_added
                    })
                
                filename = f"harmonia_indicators_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                
                # Record the export
                data_content = json.dumps(data, indent=2, default=str).encode('utf-8')
                record_export(
                    export_type='data',
                    report_type='data',
                    format_type='json',
                    days=0,
                    filename=filename,
                    file_size=len(data_content),
                    parameters={'format': 'json', 'type': indicator_type, 'limit': limit}
                )
                
                return send_file(
                    io.BytesIO(data_content),
                    as_attachment=True,
                    download_name=filename,
                    mimetype='application/json'
                )
                
        except Exception as e:
            print(f"Data export error: {e}")
            return jsonify({'error': str(e)}), 500

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
