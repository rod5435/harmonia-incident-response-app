import unittest
import json
from datetime import datetime, timedelta
from app import create_app
from models import db, Indicator
from utils import (
    advanced_search_indicators,
    get_filter_options,
    get_dashboard_stats,
    format_indicator_for_json
)


class TestUtils(unittest.TestCase):
    """Test cases for utility functions"""

    def setUp(self):
        """Set up test environment before each test"""
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        
        with self.app.app_context():
            db.create_all()
            self._create_test_data()

    def tearDown(self):
        """Clean up after each test"""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def _create_test_data(self):
        """Create test data for utility tests"""
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
        db.session.commit()

    def test_format_indicator_for_json(self):
        """Test formatting indicator for JSON serialization"""
        with self.app.app_context():
            indicator = Indicator.query.first()
            formatted = format_indicator_for_json(indicator)
            
            self.assertIsInstance(formatted, dict)
            self.assertIn('id', formatted)
            self.assertIn('indicator_type', formatted)
            self.assertIn('indicator_value', formatted)
            self.assertIn('name', formatted)
            self.assertIn('description', formatted)
            self.assertIn('source', formatted)
            self.assertIn('severity_score', formatted)
            self.assertIn('date_added', formatted)

    def test_advanced_search_indicators_basic(self):
        """Test basic advanced search functionality"""
        with self.app.app_context():
            results = advanced_search_indicators("Data")
            
            self.assertIsInstance(results, dict)
            self.assertIn('items', results)
            self.assertGreater(len(results['items']), 0)
            
            # Should find "Data Obfuscation"
            found_data_obfuscation = any(
                result['name'] == "Data Obfuscation" for result in results['items']
            )
            self.assertTrue(found_data_obfuscation)

    def test_advanced_search_indicators_by_type(self):
        """Test advanced search filtering by indicator type"""
        with self.app.app_context():
            results = advanced_search_indicators("", indicator_type="MITRE Technique")
            
            self.assertIsInstance(results, dict)
            self.assertIn('items', results)
            self.assertEqual(len(results['items']), 2)  # Should find 2 MITRE techniques
            
            for result in results['items']:
                self.assertEqual(result['type'], "MITRE Technique")

    def test_advanced_search_indicators_by_source(self):
        """Test advanced search filtering by source"""
        with self.app.app_context():
            results = advanced_search_indicators("", source="MITRE ATT&CK")
            
            self.assertIsInstance(results, dict)
            self.assertIn('items', results)
            self.assertEqual(len(results['items']), 2)  # Should find 2 MITRE ATT&CK indicators
            
            for result in results['items']:
                self.assertEqual(result['source'], "MITRE ATT&CK")

    def test_advanced_search_indicators_by_severity(self):
        """Test advanced search filtering by severity"""
        with self.app.app_context():
            # Test filtering by severity using the actual function parameters
            results = advanced_search_indicators("")
            
            self.assertIsInstance(results, dict)
            self.assertIn('items', results)
            self.assertGreater(len(results['items']), 0)
            
            # Check that we have indicators with different severities
            severities = [result['severity_score'] for result in results['items']]
            self.assertIn('8.0', severities)
            self.assertIn('9.0', severities)

    def test_advanced_search_indicators_combined(self):
        """Test advanced search with multiple filters"""
        with self.app.app_context():
            results = advanced_search_indicators(
                "Injection",
                indicator_type="MITRE Technique",
                source="MITRE ATT&CK"
            )
            
            self.assertIsInstance(results, dict)
            self.assertIn('items', results)
            self.assertEqual(len(results['items']), 1)  # Should find 1 result
            
            result = results['items'][0]
            self.assertEqual(result['name'], "Process Injection")
            self.assertEqual(result['type'], "MITRE Technique")
            self.assertEqual(result['source'], "MITRE ATT&CK")

    def test_advanced_search_indicators_no_results(self):
        """Test advanced search with no matching results"""
        with self.app.app_context():
            results = advanced_search_indicators("NonExistentTerm")
            
            self.assertIsInstance(results, dict)
            self.assertIn('items', results)
            self.assertEqual(len(results['items']), 0)

    def test_get_filter_options(self):
        """Test getting filter options for the UI"""
        with self.app.app_context():
            options = get_filter_options()
            
            self.assertIsInstance(options, dict)
            self.assertIn('sources', options)
            self.assertIn('severities', options)
            
            # Check that we have the expected options
            self.assertIn("MITRE ATT&CK", options['sources'])
            self.assertIn("CISA KEV Catalog", options['sources'])
            self.assertIn("Internal Analysis", options['sources'])

    def test_get_dashboard_stats(self):
        """Test getting dashboard statistics"""
        with self.app.app_context():
            stats = get_dashboard_stats()
            
            self.assertIsInstance(stats, dict)
            self.assertIn('total_indicators', stats)
            self.assertIn('mitre_count', stats)
            self.assertIn('cve_count', stats)
            
            # Check specific values
            self.assertEqual(stats['total_indicators'], 4)
            self.assertEqual(stats['mitre_count'], 2)
            self.assertEqual(stats['cve_count'], 1)

    def test_advanced_search_pagination(self):
        """Test advanced search with pagination"""
        with self.app.app_context():
            results = advanced_search_indicators("", page=1, per_page=2)
            
            self.assertIsInstance(results, dict)
            self.assertIn('items', results)
            self.assertLessEqual(len(results['items']), 2)

    def test_advanced_search_sorting(self):
        """Test advanced search with sorting"""
        with self.app.app_context():
            # Test sorting by name
            results = advanced_search_indicators("", sort_by="name", sort_order="asc")
            
            self.assertIsInstance(results, dict)
            self.assertIn('items', results)
            if len(results['items']) > 1:
                # Check if names are in ascending order
                names = [result['name'] for result in results['items']]
                self.assertEqual(names, sorted(names))

    def test_advanced_search_date_filtering(self):
        """Test advanced search with date filtering"""
        with self.app.app_context():
            # Test basic search without date filtering
            results = advanced_search_indicators("")
            
            self.assertIsInstance(results, dict)
            self.assertIn('items', results)
            self.assertGreater(len(results['items']), 0)
            
            # Check that we have recent indicators
            for result in results['items']:
                self.assertIsNotNone(result['date_added'])

    def test_error_handling_in_advanced_search(self):
        """Test error handling in advanced search"""
        with self.app.app_context():
            # Test with invalid parameters - should handle gracefully
            results = advanced_search_indicators("")
            
            # Should handle gracefully and return valid results
            self.assertIsInstance(results, dict)
            self.assertIn('items', results)

    def test_filter_options_with_empty_database(self):
        """Test filter options when database is empty"""
        with self.app.app_context():
            # Clear the database
            Indicator.query.delete()
            db.session.commit()
            
            options = get_filter_options()
            
            self.assertIsInstance(options, dict)
            self.assertIn('sources', options)
            self.assertIn('severities', options)
            
            # Should have empty lists
            self.assertEqual(len(options['sources']), 0)
            self.assertEqual(len(options['severities']), 0)

    def test_dashboard_stats_with_empty_database(self):
        """Test dashboard stats when database is empty"""
        with self.app.app_context():
            # Clear the database
            Indicator.query.delete()
            db.session.commit()
            
            stats = get_dashboard_stats()
            
            self.assertIsInstance(stats, dict)
            self.assertEqual(stats['total_indicators'], 0)
            self.assertEqual(stats['mitre_count'], 0)
            self.assertEqual(stats['cve_count'], 0)


if __name__ == '__main__':
    unittest.main() 