import unittest
import json
import tempfile
import os
from datetime import datetime, timedelta
from app import create_app
from models import db, Indicator, UserQuery


class TestApp(unittest.TestCase):
    """Test cases for the main Flask application"""

    def setUp(self):
        """Set up test environment before each test"""
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.client = self.app.test_client()
        
        with self.app.app_context():
            db.create_all()
            self._create_test_data()

    def tearDown(self):
        """Clean up after each test"""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def _create_test_data(self):
        """Create test data for all tests"""
        # Create test indicators
        indicators = [
            Indicator(
                indicator_type="MITRE Technique",
                indicator_value="T1001",
                name="Data Obfuscation",
                description="Technique for hiding data in transit.",
                source="MITRE ATT&CK",
                severity_score="7.5",
                date_added="2025-06-26",
                timestamp="2025-06-26T12:00:00Z"
            ),
            Indicator(
                indicator_type="CVE Vulnerability",
                indicator_value="CVE-2023-1234",
                name="Sample Vulnerable Product",
                description="A sample vulnerability in a product.",
                source="CISA KEV Catalog",
                severity_score="8.0",
                date_added="2025-06-25",
                timestamp="2025-06-25T08:00:00Z"
            ),
            Indicator(
                indicator_type="MITRE Technique",
                indicator_value="T1055",
                name="Process Injection",
                description="Technique for injecting code into processes.",
                source="MITRE ATT&CK",
                severity_score="9.0",
                date_added="2025-06-24",
                timestamp="2025-06-24T10:00:00Z"
            )
        ]
        
        for indicator in indicators:
            db.session.add(indicator)
        
        # Create test user queries
        queries = [
            UserQuery(
                question="What are the latest threats?",
                answer="Based on recent data, there are several high-severity threats...",
                timestamp="2025-06-26T12:00:00Z"
            )
        ]
        
        for query in queries:
            db.session.add(query)
        
        db.session.commit()

    def test_index_route(self):
        """Test the main index route"""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Harmonia Incident Response', response.data)

    def test_data_explorer_route(self):
        """Test the data explorer route"""
        response = self.client.get('/data-explorer')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Data Explorer', response.data)

    def test_dashboard_route(self):
        """Test the dashboard route"""
        response = self.client.get('/dashboard')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Dashboard', response.data)

    def test_ai_insights_route(self):
        """Test the AI insights route"""
        response = self.client.get('/ai-insights')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'AI Insights', response.data)

    def test_ai_analysis_route(self):
        """Test the AI analysis route"""
        response = self.client.get('/ai-analysis')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'AI Analysis', response.data)

    def test_reports_route(self):
        """Test the reports route"""
        response = self.client.get('/reports')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Reports', response.data)

    def test_api_indicators(self):
        """Test the indicators API endpoint"""
        response = self.client.get('/api/indicators')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('indicators', data)
        self.assertGreater(len(data['indicators']), 0)

    def test_api_indicators_with_pagination(self):
        """Test the indicators API with pagination"""
        response = self.client.get('/api/indicators?page=1&per_page=2')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('indicators', data)
        self.assertLessEqual(len(data['indicators']), 2)

    def test_api_advanced_search(self):
        """Test the advanced search API"""
        response = self.client.get('/api/advanced-search?query=Data')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('items', data)

    def test_api_filter_options(self):
        """Test the filter options API"""
        response = self.client.get('/api/filter-options')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('sources', data)
        self.assertIn('severities', data)

    def test_api_threat_analysis(self):
        """Test the threat analysis API"""
        response = self.client.get('/api/threat-analysis?days=30')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('analysis', data)

    def test_api_generate_report(self):
        """Test the report generation API"""
        response = self.client.get('/api/generate-report?type=executive&days=7')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('report', data)

    def test_api_correlate_threats(self):
        """Test the threat correlation API"""
        response = self.client.get('/api/correlate-threats?search_term=Data')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('correlation', data)

    def test_api_attack_chain_analysis(self):
        """Test the attack chain analysis API"""
        response = self.client.get('/api/attack-chain-analysis?technique=Injection')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('analysis', data)

    def test_api_ai_insights_summary(self):
        """Test the AI insights summary API"""
        response = self.client.get('/api/ai-insights-summary')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('summary', data)

    def test_export_pdf(self):
        """Test PDF export functionality"""
        response = self.client.get('/export/pdf?type=executive&days=7')
        self.assertEqual(response.status_code, 200)
        self.assertIn('application/pdf', response.headers['Content-Type'])

    def test_export_excel(self):
        """Test Excel export functionality"""
        response = self.client.get('/export/excel?days=30')
        self.assertEqual(response.status_code, 200)
        self.assertIn('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 
                     response.headers['Content-Type'])

    def test_export_html(self):
        """Test HTML export functionality"""
        response = self.client.get('/export/html?type=comprehensive&days=90')
        self.assertEqual(response.status_code, 200)
        self.assertIn('text/html', response.headers['Content-Type'])

    def test_export_data_json(self):
        """Test JSON data export"""
        response = self.client.get('/export/data?format=json&limit=10')
        self.assertEqual(response.status_code, 200)
        self.assertIn('application/json', response.headers['Content-Type'])

    def test_export_data_csv(self):
        """Test CSV data export"""
        response = self.client.get('/export/data?format=csv&limit=10')
        self.assertEqual(response.status_code, 200)
        self.assertIn('text/csv', response.headers['Content-Type'])

    def test_ai_insights_post(self):
        """Test AI insights POST functionality"""
        response = self.client.post('/ai-insights', data={
            'question': 'What are the latest threats?'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'AI Insights', response.data)

    def test_invalid_route(self):
        """Test handling of invalid routes"""
        response = self.client.get('/invalid-route')
        self.assertEqual(response.status_code, 404)

    def test_api_error_handling(self):
        """Test API error handling with invalid parameters"""
        response = self.client.get('/api/generate-report?type=invalid&days=invalid')
        self.assertEqual(response.status_code, 500)

    def test_database_operations(self):
        """Test basic database operations"""
        with self.app.app_context():
            # Test indicator count
            count = Indicator.query.count()
            self.assertEqual(count, 3)
            
            # Test query by type
            mitre_indicators = Indicator.query.filter_by(indicator_type="MITRE Technique").all()
            self.assertEqual(len(mitre_indicators), 2)
            
            # Test query by severity
            high_severity = Indicator.query.filter(Indicator.severity_score >= "8.0").all()
            self.assertEqual(len(high_severity), 2)


if __name__ == '__main__':
    unittest.main() 