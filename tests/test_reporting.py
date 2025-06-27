import unittest
import tempfile
import os
from datetime import datetime
from app import create_app
from models import db, Indicator
from reporting import ReportGenerator


class TestReporting(unittest.TestCase):
    """Test cases for reporting functionality"""

    def setUp(self):
        """Set up test environment before each test"""
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        
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
        """Create test data for reporting tests"""
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
        db.session.commit()

    def test_report_generator_initialization(self):
        """Test ReportGenerator initialization"""
        with self.app.app_context():
            generator = ReportGenerator()
            
            self.assertIsNotNone(generator)
            self.assertIsNotNone(generator.reports_dir)
            self.assertTrue(os.path.exists(generator.reports_dir))

    def test_get_indicators_for_period(self):
        """Test getting indicators for a specific time period"""
        with self.app.app_context():
            generator = ReportGenerator()
            
            # Test getting indicators for last 7 days
            indicators = generator._get_filtered_data(7)
            self.assertIsInstance(indicators, list)
            self.assertGreater(len(indicators), 0)
            
            # Test getting indicators for last 30 days
            indicators = generator._get_filtered_data(30)
            self.assertIsInstance(indicators, list)
            self.assertGreater(len(indicators), 0)

    def test_generate_pdf_report_executive(self):
        """Test PDF report generation for executive summary"""
        with self.app.app_context():
            generator = ReportGenerator()
            filename, error = generator.generate_pdf_report("executive", 7)
            
            self.assertIsInstance(filename, str)
            self.assertIsNone(error)
            self.assertTrue(filename.endswith('.pdf'))
            
            # Check if file was created
            filepath = os.path.join(generator.reports_dir, filename)
            self.assertTrue(os.path.exists(filepath))

    def test_generate_pdf_report_technical(self):
        """Test PDF report generation for technical report"""
        with self.app.app_context():
            generator = ReportGenerator()
            filename, error = generator.generate_pdf_report("technical", 30)
            
            self.assertIsInstance(filename, str)
            self.assertIsNone(error)
            self.assertTrue(filename.endswith('.pdf'))
            
            # Check if file was created
            filepath = os.path.join(generator.reports_dir, filename)
            self.assertTrue(os.path.exists(filepath))

    def test_generate_pdf_report_comprehensive(self):
        """Test PDF report generation for comprehensive report"""
        with self.app.app_context():
            generator = ReportGenerator()
            filename, error = generator.generate_pdf_report("comprehensive", 90)
            
            self.assertIsInstance(filename, str)
            self.assertIsNone(error)
            self.assertTrue(filename.endswith('.pdf'))
            
            # Check if file was created
            filepath = os.path.join(generator.reports_dir, filename)
            self.assertTrue(os.path.exists(filepath))

    def test_generate_excel_report(self):
        """Test Excel report generation"""
        with self.app.app_context():
            generator = ReportGenerator()
            filename, error = generator.generate_excel_report("comprehensive", 30)
            
            self.assertIsInstance(filename, str)
            self.assertIsNone(error)
            self.assertTrue(filename.endswith('.xlsx'))
            
            # Check if file was created
            filepath = os.path.join(generator.reports_dir, filename)
            self.assertTrue(os.path.exists(filepath))

    def test_generate_html_report(self):
        """Test HTML report generation"""
        with self.app.app_context():
            generator = ReportGenerator()
            filename, error = generator.generate_html_report("comprehensive", 30)
            
            self.assertIsInstance(filename, str)
            self.assertIsNone(error)
            self.assertTrue(filename.endswith('.html'))
            
            # Check if file was created
            filepath = os.path.join(generator.reports_dir, filename)
            self.assertTrue(os.path.exists(filepath))

    def test_report_with_no_data(self):
        """Test report generation when no data is available"""
        with self.app.app_context():
            # Clear the database
            Indicator.query.delete()
            db.session.commit()
            
            generator = ReportGenerator()
            filename, error = generator.generate_pdf_report("executive", 7)
            
            # Should still generate a report (even with no data)
            self.assertIsInstance(filename, str)
            self.assertIsNone(error)

    def test_invalid_report_type(self):
        """Test report generation with invalid report type"""
        with self.app.app_context():
            generator = ReportGenerator()
            filename, error = generator.generate_pdf_report("invalid_type", 30)
            
            # Should handle gracefully and generate a default report
            self.assertIsInstance(filename, str)
            self.assertIsNone(error)

    def test_report_filename_format(self):
        """Test that report filenames follow the expected format"""
        with self.app.app_context():
            generator = ReportGenerator()
            filename, error = generator.generate_pdf_report("executive", 7)
            
            # Check filename format: threat_intelligence_report_executive_YYYYMMDD_HHMMSS.pdf
            self.assertIn("threat_intelligence_report_executive_", filename)
            self.assertTrue(filename.endswith('.pdf'))
            
            # Check that filename contains timestamp
            parts = filename.split('_')
            self.assertGreaterEqual(len(parts), 5)

    def test_multiple_report_generation(self):
        """Test generating multiple reports in sequence"""
        with self.app.app_context():
            generator = ReportGenerator()
            
            # Generate multiple reports
            pdf_filename, pdf_error = generator.generate_pdf_report("executive", 7)
            excel_filename, excel_error = generator.generate_excel_report("technical", 30)
            html_filename, html_error = generator.generate_html_report("comprehensive", 90)
            
            # All should succeed
            self.assertIsNone(pdf_error)
            self.assertIsNone(excel_error)
            self.assertIsNone(html_error)
            
            # All files should be created
            self.assertTrue(os.path.exists(os.path.join(generator.reports_dir, pdf_filename)))
            self.assertTrue(os.path.exists(os.path.join(generator.reports_dir, excel_filename)))
            self.assertTrue(os.path.exists(os.path.join(generator.reports_dir, html_filename)))

    def test_report_content_validation(self):
        """Test that generated reports contain expected content"""
        with self.app.app_context():
            generator = ReportGenerator()
            filename, error = generator.generate_html_report("executive", 7)
            
            self.assertIsNone(error)
            
            # Read the generated HTML file
            filepath = os.path.join(generator.reports_dir, filename)
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for expected content
            self.assertIn("Threat Intelligence Report", content)
            self.assertIn("Executive Summary", content)

    def test_report_directory_creation(self):
        """Test that report directory is created if it doesn't exist"""
        with self.app.app_context():
            # Create a new generator with a non-existent directory
            test_reports_dir = os.path.join(self.test_dir, "new_reports")
            generator = ReportGenerator()
            generator.reports_dir = test_reports_dir
            
            # Directory should be created
            self.assertTrue(os.path.exists(test_reports_dir))
            
            filename, error = generator.generate_pdf_report("executive", 7)
            
            self.assertIsNone(error)
            self.assertTrue(os.path.exists(os.path.join(test_reports_dir, filename)))

    def test_error_handling_in_report_generation(self):
        """Test error handling during report generation"""
        with self.app.app_context():
            generator = ReportGenerator()
            
            # Test with invalid parameters
            filename, error = generator.generate_pdf_report("executive", -1)
            
            # Should handle gracefully
            self.assertIsInstance(filename, str)
            # Error might be None or contain error message

    def test_report_statistics(self):
        """Test that reports include proper statistics"""
        with self.app.app_context():
            generator = ReportGenerator()
            filename, error = generator.generate_html_report("comprehensive", 30)
            
            self.assertIsNone(error)
            
            # Read the generated HTML file
            filepath = os.path.join(generator.reports_dir, filename)
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for statistics content
            self.assertIn("Total Indicators", content)
            self.assertIn("MITRE Technique", content)
            self.assertIn("CVE Vulnerability", content)


if __name__ == '__main__':
    unittest.main() 