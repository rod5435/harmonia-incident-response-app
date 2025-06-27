import unittest
import json
import tempfile
import os
from datetime import datetime, timedelta
from app import create_app
from models import db, Indicator, UserQuery
from utils import advanced_search_indicators, get_filter_options, get_dashboard_stats
from reporting import ReportGenerator


class TestIntegration(unittest.TestCase):
    """Integration tests for complete workflows"""

    def setUp(self):
        """Set up test environment before each test"""
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.client = self.app.test_client()
        
        # Create temporary directory for test reports
        self.test_dir = tempfile.mkdtemp()
        
        with self.app.app_context():
            db.create_all()
            self._create_test_data()

    def tearDown(self):
        """Clean up after each test"""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
        
        # Clean up temporary directory
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_test_data(self):
        """Create comprehensive test data"""
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
            ),
            Indicator(
                indicator_type="Malware",
                indicator_value="MALWARE-001",
                name="Test Malware",
                description="A test malware sample.",
                source="Internal Analysis",
                severity_score="6.5",
                date_added="2025-06-23",
                timestamp="2025-06-23T14:00:00Z"
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
            ),
            UserQuery(
                question="How to detect process injection?",
                answer="Process injection can be detected through monitoring...",
                timestamp="2025-06-25T10:00:00Z"
            )
        ]
        
        for query in queries:
            db.session.add(query)
        
        db.session.commit()

    def test_complete_data_explorer_workflow(self):
        """Test complete data explorer workflow"""
        with self.app.app_context():
            # 1. Get filter options
            filter_options = get_filter_options()
            self.assertIn('sources', filter_options)
            self.assertIn('severities', filter_options)
            
            # 2. Perform advanced search
            search_results = advanced_search_indicators("Data")
            self.assertIsInstance(search_results, list)
            self.assertGreater(len(search_results), 0)
            
            # 3. Search with filters
            filtered_results = advanced_search_indicators(
                "",
                indicator_type="MITRE Technique",
                source="MITRE ATT&CK"
            )
            self.assertIsInstance(filtered_results, list)
            
            # 4. Test pagination
            paginated_results = advanced_search_indicators("", page=1, per_page=2)
            self.assertLessEqual(len(paginated_results), 2)

    def test_complete_dashboard_workflow(self):
        """Test complete dashboard workflow"""
        with self.app.app_context():
            # 1. Get dashboard statistics
            stats = get_dashboard_stats()
            self.assertIn('total_indicators', stats)
            self.assertIn('mitre_count', stats)
            self.assertIn('cve_count', stats)
            
            # 2. Verify statistics are accurate
            self.assertEqual(stats['total_indicators'], 4)
            self.assertEqual(stats['mitre_count'], 2)
            self.assertEqual(stats['cve_count'], 1)

    def test_complete_reporting_workflow(self):
        """Test complete reporting workflow"""
        with self.app.app_context():
            generator = ReportGenerator()
            
            # 1. Generate different types of reports
            pdf_filename, pdf_error = generator.generate_pdf_report("executive", 7)
            excel_filename, excel_error = generator.generate_excel_report("technical", 30)
            html_filename, html_error = generator.generate_html_report("comprehensive", 90)
            
            # 2. Verify all reports were generated successfully
            self.assertIsNone(pdf_error)
            self.assertIsNone(excel_error)
            self.assertIsNone(html_error)
            
            # 3. Verify files exist
            self.assertTrue(os.path.exists(os.path.join(generator.reports_dir, pdf_filename)))
            self.assertTrue(os.path.exists(os.path.join(generator.reports_dir, excel_filename)))
            self.assertTrue(os.path.exists(os.path.join(generator.reports_dir, html_filename)))

    def test_complete_api_workflow(self):
        """Test complete API workflow"""
        # 1. Test indicators API
        response = self.client.get('/api/indicators')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('indicators', data)
        
        # 2. Test filter options API
        response = self.client.get('/api/filter-options')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('sources', data)
        
        # 3. Test advanced search API
        response = self.client.get('/api/advanced-search?query=Data')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('items', data)
        
        # 4. Test threat analysis API
        response = self.client.get('/api/threat-analysis?days=30')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('analysis', data)
        
        # 5. Test report generation API
        response = self.client.get('/api/generate-report?type=executive&days=7')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('report', data)

    def test_complete_export_workflow(self):
        """Test complete export workflow"""
        # 1. Test PDF export
        response = self.client.get('/export/pdf?type=executive&days=7')
        self.assertEqual(response.status_code, 200)
        self.assertIn('application/pdf', response.headers['Content-Type'])
        
        # 2. Test Excel export
        response = self.client.get('/export/excel?days=30')
        self.assertEqual(response.status_code, 200)
        self.assertIn('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 
                     response.headers['Content-Type'])
        
        # 3. Test HTML export
        response = self.client.get('/export/html?type=comprehensive&days=90')
        self.assertEqual(response.status_code, 200)
        self.assertIn('text/html', response.headers['Content-Type'])
        
        # 4. Test JSON data export
        response = self.client.get('/export/data?format=json&limit=10')
        self.assertEqual(response.status_code, 200)
        self.assertIn('application/json', response.headers['Content-Type'])
        
        # 5. Test CSV data export
        response = self.client.get('/export/data?format=csv&limit=10')
        self.assertEqual(response.status_code, 200)
        self.assertIn('text/csv', response.headers['Content-Type'])

    def test_complete_web_interface_workflow(self):
        """Test complete web interface workflow"""
        # 1. Test main page
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Harmonia Incident Response', response.data)
        
        # 2. Test data explorer page
        response = self.client.get('/data-explorer')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Data Explorer', response.data)
        
        # 3. Test dashboard page
        response = self.client.get('/dashboard')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Dashboard', response.data)
        
        # 4. Test AI insights page
        response = self.client.get('/ai-insights')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'AI Insights', response.data)
        
        # 5. Test AI analysis page
        response = self.client.get('/ai-analysis')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'AI Analysis', response.data)
        
        # 6. Test reports page
        response = self.client.get('/reports')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Reports', response.data)

    def test_data_consistency_across_apis(self):
        """Test data consistency across different APIs"""
        with self.app.app_context():
            # Get data from different sources
            total_indicators = Indicator.query.count()
            dashboard_stats = get_dashboard_stats()
            api_response = self.client.get('/api/indicators')
            api_data = json.loads(api_response.data)
            
            # Verify consistency
            self.assertEqual(total_indicators, dashboard_stats['total_indicators'])
            self.assertEqual(total_indicators, len(api_data['indicators']))

    def test_error_handling_workflow(self):
        """Test error handling across the application"""
        # 1. Test invalid route
        response = self.client.get('/invalid-route')
        self.assertEqual(response.status_code, 404)
        
        # 2. Test invalid API parameters
        response = self.client.get('/api/generate-report?type=invalid&days=invalid')
        self.assertEqual(response.status_code, 500)
        
        # 3. Test invalid export parameters
        response = self.client.get('/export/pdf?type=invalid&days=invalid')
        self.assertEqual(response.status_code, 500)

    def test_performance_workflow(self):
        """Test performance with larger datasets"""
        with self.app.app_context():
            # Add more test data
            for i in range(50):
                indicator = Indicator(
                    indicator_type="Test Type",
                    indicator_value=f"TEST{i:03d}",
                    name=f"Test Indicator {i}",
                    description=f"Test description {i}",
                    source="Test Source",
                    severity_score="5.0",
                    date_added="2025-06-26",
                    timestamp="2025-06-26T12:00:00Z"
                )
                db.session.add(indicator)
            db.session.commit()
            
            # Test performance of key operations
            import time
            
            # Test dashboard stats generation
            start_time = time.time()
            stats = get_dashboard_stats()
            dashboard_time = time.time() - start_time
            self.assertLess(dashboard_time, 1.0)  # Should complete in under 1 second
            
            # Test advanced search
            start_time = time.time()
            search_results = advanced_search_indicators("Test")
            search_time = time.time() - start_time
            self.assertLess(search_time, 1.0)  # Should complete in under 1 second
            
            # Test report generation
            generator = ReportGenerator()
            start_time = time.time()
            filename, error = generator.generate_pdf_report("executive", 7)
            report_time = time.time() - start_time
            self.assertLess(report_time, 5.0)  # Should complete in under 5 seconds

    def test_data_integrity_workflow(self):
        """Test data integrity across operations"""
        with self.app.app_context():
            # 1. Verify initial data
            initial_count = Indicator.query.count()
            self.assertEqual(initial_count, 4)
            
            # 2. Add new indicator
            new_indicator = Indicator(
                indicator_type="New Type",
                indicator_value="NEW001",
                name="New Indicator",
                description="New description",
                source="New Source",
                severity_score="7.0",
                date_added="2025-06-26",
                timestamp="2025-06-26T12:00:00Z"
            )
            db.session.add(new_indicator)
            db.session.commit()
            
            # 3. Verify data consistency
            updated_count = Indicator.query.count()
            self.assertEqual(updated_count, initial_count + 1)
            
            # 4. Verify dashboard stats are updated
            stats = get_dashboard_stats()
            self.assertEqual(stats['total_indicators'], updated_count)
            
            # 5. Verify API reflects changes
            response = self.client.get('/api/indicators')
            data = json.loads(response.data)
            self.assertEqual(len(data['indicators']), updated_count)


if __name__ == '__main__':
    unittest.main() 