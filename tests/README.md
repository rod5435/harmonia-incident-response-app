# Test Suite for Harmonia Incident Response App

This directory contains comprehensive unit tests and integration tests for the Harmonia Incident Response App.

## Test Structure

### `test_app.py`
Tests for the main Flask application routes and API endpoints:
- Route accessibility and response codes
- API endpoint functionality
- Error handling
- Database operations
- Export functionality

### `test_models.py`
Tests for database models:
- Model creation and validation
- Database relationships
- Data type handling
- Constraint testing
- Cascade operations

### `test_utils.py`
Tests for utility functions:
- Advanced search functionality
- Filter options generation
- Dashboard statistics
- Data formatting
- Error handling

### `test_openai_integration.py`
Tests for OpenAI integration:
- AI question answering
- Threat pattern analysis
- Report generation
- Threat correlation
- Attack chain analysis
- Error handling with mocked OpenAI API

### `test_reporting.py`
Tests for reporting functionality:
- PDF report generation
- Excel report generation
- HTML report generation
- Report content validation
- File creation and management

### `test_integration.py`
Integration tests for complete workflows:
- End-to-end data explorer workflow
- Dashboard statistics workflow
- Reporting workflow
- API workflow
- Export workflow
- Web interface workflow
- Performance testing
- Data integrity testing

## Running Tests

### Run All Tests
```bash
python run_tests.py
```

### Run Specific Test Module
```bash
python run_tests.py test_app
python run_tests.py test_models
python run_tests.py test_utils
python run_tests.py test_openai_integration
python run_tests.py test_reporting
python run_tests.py test_integration
```

### Run Individual Test Files
```bash
python -m unittest tests.test_app
python -m unittest tests.test_models
python -m unittest tests.test_utils
python -m unittest tests.test_openai_integration
python -m unittest tests.test_reporting
python -m unittest tests.test_integration
```

## Test Coverage

The test suite covers:

### ✅ Core Functionality
- Flask routes and API endpoints
- Database models and operations
- Utility functions
- Error handling

### ✅ AI Integration
- OpenAI API integration (mocked)
- Threat analysis
- Report generation
- Threat correlation

### ✅ Reporting System
- PDF, Excel, and HTML report generation
- Report content validation
- File management

### ✅ Data Management
- Advanced search and filtering
- Dashboard statistics
- Data export functionality

### ✅ Integration Workflows
- Complete user workflows
- Performance testing
- Data integrity validation

## Test Data

Tests use in-memory SQLite databases with sample data including:
- MITRE ATT&CK techniques
- CVE vulnerabilities
- Malware indicators
- User queries

## Mocking

The OpenAI integration tests use mocking to avoid actual API calls during testing, ensuring:
- Fast test execution
- No API costs during testing
- Reliable test results
- Offline testing capability

## Continuous Integration

These tests are designed to be run in CI/CD pipelines and provide:
- Clear pass/fail results
- Detailed error reporting
- Performance benchmarks
- Code coverage insights

## Best Practices

- Tests are isolated and independent
- Each test cleans up after itself
- Tests use temporary directories for file operations
- Mock external dependencies
- Comprehensive error handling testing
- Performance testing for critical operations 