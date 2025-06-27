import unittest
import os
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
from app import create_app
from models import db, Indicator
from openai_integration import (
    ask_gpt,
    analyze_threat_patterns,
    generate_threat_report,
    correlate_threats,
    analyze_attack_chain,
    get_ai_insights_summary
)


class TestOpenAIIntegration(unittest.TestCase):
    """Test cases for OpenAI integration functions"""

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
        """Create test data for AI integration tests"""
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

    @patch('openai_integration.openai')
    def test_ask_gpt_success(self, mock_openai):
        """Test successful GPT question answering"""
        # Mock the OpenAI response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "This is a test response from GPT."
        mock_openai.ChatCompletion.create.return_value = mock_response
        
        with self.app.app_context():
            result = ask_gpt("What is cybersecurity?", "Test context")
            
            self.assertIsInstance(result, str)
            self.assertIn("test response", result.lower())
            mock_openai.ChatCompletion.create.assert_called_once()

    @patch('openai_integration.openai')
    def test_ask_gpt_error(self, mock_openai):
        """Test GPT function with API error"""
        # Mock OpenAI to raise an exception
        mock_openai.ChatCompletion.create.side_effect = Exception("API Error")
        
        with self.app.app_context():
            result = ask_gpt("What is cybersecurity?", "Test context")
            
            self.assertIsInstance(result, str)
            self.assertIn("Error", result)
            self.assertIn("API Error", result)

    @patch('openai_integration.openai')
    def test_analyze_threat_patterns_success(self, mock_openai):
        """Test successful threat pattern analysis"""
        # Mock the OpenAI response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Threat analysis: Multiple high-severity indicators detected."
        mock_openai.ChatCompletion.create.return_value = mock_response
        
        with self.app.app_context():
            result = analyze_threat_patterns(30)
            
            self.assertIsInstance(result, str)
            self.assertIn("Threat analysis", result)
            mock_openai.ChatCompletion.create.assert_called_once()

    @patch('openai_integration.openai')
    def test_analyze_threat_patterns_no_data(self, mock_openai):
        """Test threat analysis with no data"""
        with self.app.app_context():
            # Clear the database
            Indicator.query.delete()
            db.session.commit()
            
            result = analyze_threat_patterns(30)
            
            self.assertIsInstance(result, str)
            self.assertIn("No recent threat data", result)
            # Should not call OpenAI if no data
            mock_openai.ChatCompletion.create.assert_not_called()

    @patch('openai_integration.openai')
    def test_generate_threat_report_executive(self, mock_openai):
        """Test executive report generation"""
        # Mock the OpenAI response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Executive Summary Report"
        mock_openai.ChatCompletion.create.return_value = mock_response
        
        with self.app.app_context():
            result = generate_threat_report("executive", 7)
            
            self.assertIsInstance(result, str)
            self.assertIn("Executive Summary", result)
            mock_openai.ChatCompletion.create.assert_called_once()

    @patch('openai_integration.openai')
    def test_generate_threat_report_technical(self, mock_openai):
        """Test technical report generation"""
        # Mock the OpenAI response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Technical Analysis Report"
        mock_openai.ChatCompletion.create.return_value = mock_response
        
        with self.app.app_context():
            result = generate_threat_report("technical", 30)
            
            self.assertIsInstance(result, str)
            self.assertIn("Technical Analysis", result)
            mock_openai.ChatCompletion.create.assert_called_once()

    @patch('openai_integration.openai')
    def test_generate_threat_report_comprehensive(self, mock_openai):
        """Test comprehensive report generation"""
        # Mock the OpenAI response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Comprehensive Security Report"
        mock_openai.ChatCompletion.create.return_value = mock_response
        
        with self.app.app_context():
            result = generate_threat_report("comprehensive", 90)
            
            self.assertIsInstance(result, str)
            self.assertIn("Comprehensive Security", result)
            mock_openai.ChatCompletion.create.assert_called_once()

    @patch('openai_integration.openai')
    def test_correlate_threats_by_search_term(self, mock_openai):
        """Test threat correlation by search term"""
        # Mock the OpenAI response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Threat correlation analysis"
        mock_openai.ChatCompletion.create.return_value = mock_response
        
        with self.app.app_context():
            result = correlate_threats(search_term="Data")
            
            self.assertIsInstance(result, str)
            self.assertIn("Threat correlation", result)
            mock_openai.ChatCompletion.create.assert_called_once()

    @patch('openai_integration.openai')
    def test_correlate_threats_by_indicator_id(self, mock_openai):
        """Test threat correlation by indicator ID"""
        # Mock the OpenAI response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Indicator correlation analysis"
        mock_openai.ChatCompletion.create.return_value = mock_response
        
        with self.app.app_context():
            indicator = Indicator.query.first()
            result = correlate_threats(indicator_id=indicator.id)
            
            self.assertIsInstance(result, str)
            self.assertIn("Indicator correlation", result)
            mock_openai.ChatCompletion.create.assert_called_once()

    def test_correlate_threats_no_parameters(self):
        """Test threat correlation with no parameters"""
        with self.app.app_context():
            result = correlate_threats()
            
            self.assertIsInstance(result, str)
            self.assertIn("Please provide", result)

    def test_correlate_threats_invalid_indicator(self):
        """Test threat correlation with invalid indicator ID"""
        with self.app.app_context():
            result = correlate_threats(indicator_id=99999)
            
            self.assertIsInstance(result, str)
            self.assertIn("Indicator not found", result)

    @patch('openai_integration.openai')
    def test_analyze_attack_chain_with_technique(self, mock_openai):
        """Test attack chain analysis with technique name"""
        # Mock the OpenAI response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Attack chain analysis for Injection"
        mock_openai.ChatCompletion.create.return_value = mock_response
        
        with self.app.app_context():
            result = analyze_attack_chain("Injection")
            
            self.assertIsInstance(result, str)
            self.assertIn("Attack chain analysis", result)
            mock_openai.ChatCompletion.create.assert_called_once()

    @patch('openai_integration.openai')
    def test_analyze_attack_chain_no_technique(self, mock_openai):
        """Test attack chain analysis without technique name"""
        # Mock the OpenAI response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "General attack chain analysis"
        mock_openai.ChatCompletion.create.return_value = mock_response
        
        with self.app.app_context():
            result = analyze_attack_chain()
            
            self.assertIsInstance(result, str)
            self.assertIn("General attack chain", result)
            mock_openai.ChatCompletion.create.assert_called_once()

    @patch('openai_integration.openai')
    def test_get_ai_insights_summary(self, mock_openai):
        """Test AI insights summary generation"""
        # Mock the OpenAI response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "AI Insights Summary"
        mock_openai.ChatCompletion.create.return_value = mock_response
        
        with self.app.app_context():
            result = get_ai_insights_summary()
            
            self.assertIsInstance(result, str)
            self.assertIn("AI Insights Summary", result)
            mock_openai.ChatCompletion.create.assert_called_once()

    def test_generate_threat_report_error_handling(self):
        """Test error handling in report generation"""
        with self.app.app_context():
            # Test with invalid report type
            result = generate_threat_report("invalid_type", 30)
            
            self.assertIsInstance(result, str)
            # Should still generate a report (defaults to comprehensive)

    def test_date_filtering_in_reports(self):
        """Test date filtering in report generation"""
        with self.app.app_context():
            # Test with different date ranges
            result_7_days = generate_threat_report("executive", 7)
            result_30_days = generate_threat_report("executive", 30)
            
            self.assertIsInstance(result_7_days, str)
            self.assertIsInstance(result_30_days, str)

    def test_openai_api_key_handling(self):
        """Test handling of missing OpenAI API key"""
        # Save original API key
        original_key = os.getenv('OPENAI_API_KEY')
        
        # Remove API key
        if 'OPENAI_API_KEY' in os.environ:
            del os.environ['OPENAI_API_KEY']
        
        with self.app.app_context():
            result = ask_gpt("Test question")
            self.assertIn("Error", result)
        
        # Restore API key
        if original_key:
            os.environ['OPENAI_API_KEY'] = original_key

    def test_model_parameter_handling(self):
        """Test handling of different model parameters"""
        with self.app.app_context():
            # Test with different report types
            executive_result = generate_threat_report("executive", 7)
            technical_result = generate_threat_report("technical", 30)
            comprehensive_result = generate_threat_report("comprehensive", 90)
            
            self.assertIsInstance(executive_result, str)
            self.assertIsInstance(technical_result, str)
            self.assertIsInstance(comprehensive_result, str)


if __name__ == '__main__':
    unittest.main() 