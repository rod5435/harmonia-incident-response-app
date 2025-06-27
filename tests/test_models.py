import unittest
from datetime import datetime
from app import create_app
from models import db, Indicator, UserQuery


class TestModels(unittest.TestCase):
    """Test cases for database models"""

    def setUp(self):
        """Set up test environment before each test"""
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        
        with self.app.app_context():
            db.create_all()

    def tearDown(self):
        """Clean up after each test"""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def test_indicator_creation(self):
        """Test creating an Indicator"""
        with self.app.app_context():
            indicator = Indicator(
                indicator_type="MITRE Technique",
                indicator_value="T1001",
                name="Data Obfuscation",
                description="Technique for hiding data in transit.",
                source="MITRE ATT&CK",
                severity_score="7.5",
                date_added="2025-06-26",
                timestamp="2025-06-26T12:00:00Z"
            )
            
            db.session.add(indicator)
            db.session.commit()
            
            # Verify the indicator was created
            saved_indicator = Indicator.query.filter_by(indicator_value="T1001").first()
            self.assertIsNotNone(saved_indicator)
            self.assertEqual(saved_indicator.name, "Data Obfuscation")
            self.assertEqual(saved_indicator.indicator_type, "MITRE Technique")
            self.assertEqual(saved_indicator.severity_score, "7.5")

    def test_user_query_creation(self):
        """Test creating a UserQuery"""
        with self.app.app_context():
            query = UserQuery(
                question="What are the latest threats?",
                answer="Based on recent data, there are several high-severity threats...",
                timestamp="2025-06-26T12:00:00Z"
            )
            
            db.session.add(query)
            db.session.commit()
            
            # Verify the query was created
            saved_query = UserQuery.query.filter_by(question="What are the latest threats?").first()
            self.assertIsNotNone(saved_query)
            self.assertEqual(saved_query.answer, "Based on recent data, there are several high-severity threats...")

    def test_indicator_relationships(self):
        """Test indicator relationships and queries"""
        with self.app.app_context():
            # Create multiple indicators
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
            
            # Test filtering by type
            mitre_indicators = Indicator.query.filter_by(indicator_type="MITRE Technique").all()
            self.assertEqual(len(mitre_indicators), 2)
            
            # Test filtering by source
            mitre_source_indicators = Indicator.query.filter_by(source="MITRE ATT&CK").all()
            self.assertEqual(len(mitre_source_indicators), 2)
            
            # Test filtering by severity
            high_severity = Indicator.query.filter(Indicator.severity_score >= "8.0").all()
            self.assertEqual(len(high_severity), 2)
            
            # Test filtering by date
            recent_indicators = Indicator.query.filter(Indicator.date_added >= "2025-06-25").all()
            self.assertEqual(len(recent_indicators), 2)

    def test_indicator_validation(self):
        """Test indicator field validation"""
        with self.app.app_context():
            # Test with minimal required fields
            indicator = Indicator(
                indicator_type="Test Type",
                indicator_value="TEST001",
                name="Test Indicator",
                description="Test description",
                source="Test Source",
                severity_score="5.0",
                date_added="2025-06-26",
                timestamp="2025-06-26T12:00:00Z"
            )
            
            db.session.add(indicator)
            db.session.commit()
            
            # Verify all fields are saved correctly
            saved_indicator = Indicator.query.filter_by(indicator_value="TEST001").first()
            self.assertEqual(saved_indicator.indicator_type, "Test Type")
            self.assertEqual(saved_indicator.name, "Test Indicator")
            self.assertEqual(saved_indicator.description, "Test description")
            self.assertEqual(saved_indicator.source, "Test Source")
            self.assertEqual(saved_indicator.severity_score, "5.0")

    def test_user_query_validation(self):
        """Test user query field validation"""
        with self.app.app_context():
            query = UserQuery(
                question="Test question?",
                answer="Test answer.",
                timestamp="2025-06-26T12:00:00Z"
            )
            
            db.session.add(query)
            db.session.commit()
            
            # Verify all fields are saved correctly
            saved_query = UserQuery.query.filter_by(question="Test question?").first()
            self.assertEqual(saved_query.answer, "Test answer.")
            self.assertEqual(saved_query.timestamp, "2025-06-26T12:00:00Z")

    def test_database_constraints(self):
        """Test database constraints and unique fields"""
        with self.app.app_context():
            # Create first indicator
            indicator1 = Indicator(
                indicator_type="Test Type",
                indicator_value="UNIQUE001",
                name="Test Indicator 1",
                description="Test description 1",
                source="Test Source",
                severity_score="5.0",
                date_added="2025-06-26",
                timestamp="2025-06-26T12:00:00Z"
            )
            
            db.session.add(indicator1)
            db.session.commit()
            
            # Create second indicator with same value (should be allowed)
            indicator2 = Indicator(
                indicator_type="Test Type",
                indicator_value="UNIQUE001",
                name="Test Indicator 2",
                description="Test description 2",
                source="Test Source",
                severity_score="6.0",
                date_added="2025-06-26",
                timestamp="2025-06-26T12:00:00Z"
            )
            
            db.session.add(indicator2)
            db.session.commit()
            
            # Should have two indicators with same value
            indicators = Indicator.query.filter_by(indicator_value="UNIQUE001").all()
            self.assertEqual(len(indicators), 2)

    def test_cascade_operations(self):
        """Test cascade operations and data integrity"""
        with self.app.app_context():
            # Create indicators
            indicator = Indicator(
                indicator_type="Test Type",
                indicator_value="CASCADE001",
                name="Test Indicator",
                description="Test description",
                source="Test Source",
                severity_score="5.0",
                date_added="2025-06-26",
                timestamp="2025-06-26T12:00:00Z"
            )
            
            db.session.add(indicator)
            db.session.commit()
            
            # Verify indicator exists
            saved_indicator = Indicator.query.filter_by(indicator_value="CASCADE001").first()
            self.assertIsNotNone(saved_indicator)
            
            # Delete the indicator
            db.session.delete(saved_indicator)
            db.session.commit()
            
            # Verify indicator is deleted
            deleted_indicator = Indicator.query.filter_by(indicator_value="CASCADE001").first()
            self.assertIsNone(deleted_indicator)

    def test_data_types(self):
        """Test data type handling"""
        with self.app.app_context():
            # Test with different data types
            indicator = Indicator(
                indicator_type="Test Type",
                indicator_value="DT001",
                name="Test Indicator",
                description="Test description with special chars: !@#$%^&*()",
                source="Test Source",
                severity_score="9.9",
                date_added="2025-06-26",
                timestamp="2025-06-26T12:00:00Z"
            )
            
            db.session.add(indicator)
            db.session.commit()
            
            # Verify data types are preserved
            saved_indicator = Indicator.query.filter_by(indicator_value="DT001").first()
            self.assertEqual(saved_indicator.indicator_type, "Test Type")
            self.assertEqual(saved_indicator.description, "Test description with special chars: !@#$%^&*()")
            self.assertEqual(saved_indicator.severity_score, "9.9")


if __name__ == '__main__':
    unittest.main() 