# Harmonia Incident Response App

A comprehensive threat intelligence platform that provides real-time insights into cybersecurity threats, vulnerabilities, and attack techniques. Built with cutting-edge AI to help security teams make data-driven decisions and respond to incidents faster.

## 🚀 Features

### 📊 **Enterprise Threat Intelligence**
- **MITRE ATT&CK Techniques**: 691+ techniques from official GitHub JSON feed
- **CISA Known Exploited Vulnerabilities**: 1,370+ active exploitation data from CISA's KEV catalog
- **Abuse.ch URLhaus**: 80,000+ malicious URLs with real-time threat data
- **Enhanced ETL Pipeline**: Robust data processing with ZIP handling and error recovery

### 📈 **Advanced Analytics Dashboard**
- **Interactive Charts**: 7 different chart types including pie charts, bar charts, trend analysis, and geographic visualization
- **Real-time Statistics**: Live counts and metrics for 82,000+ threat indicators
- **Severity Distribution**: Visual analysis of threat severity levels across all sources
- **Source Analytics**: Breakdown of data sources and their contributions
- **Dynamic Filtering**: Real-time filtering by time range, severity, and data sources
- **Drill-down Capabilities**: Click charts to explore specific threat categories
- **Temporal Analysis**: Time-based threat trends with peak period detection
- **Geographic Intelligence**: Country-based threat mapping with regional hotspots

### 🔍 **Data Explorer**
- **Advanced Filtering**: Filter by indicator type, source, severity, and date
- **Real-time Search**: Search across all threat intelligence fields
- **Modern UI**: Beautiful, responsive design with badges and icons
- **Quick Statistics**: Live counts and metrics display
- **Multi-source Support**: Browse MITRE, CISA, and URLhaus data

### ⏰ **Temporal Analysis & Threat Trends**
- **Multi-line Time Series**: Track threat trends over time with source-specific lines
- **Peak Period Detection**: Identify high-activity threat periods automatically
- **Weekly Pattern Analysis**: Discover day-of-week threat patterns
- **Trend Direction Analysis**: Determine if threats are increasing, decreasing, or stable
- **Average Daily Threats**: Real-time calculation of threat activity levels
- **Filter-Responsive**: All temporal analysis responds to dashboard filters

### 🌍 **Geographic Threat Intelligence**
- **Country-based Threat Mapping**: Visualize threat distribution by geographic region
- **Color-coded Threat Levels**: Red (high), orange (medium), yellow (low), green (minimal)
- **Regional Hotspot Identification**: Automatic detection of high-threat regions
- **Threat Distribution Analysis**: Breakdown of countries by threat severity
- **URL-based Geographic Detection**: Extract country information from malicious URLs
- **Filter-Integrated**: Geographic data updates based on time range, severity, and sources

### 🤖 **AI-Powered Insights**
- **Natural Language Queries**: Ask questions about your threat data in plain English
- **GPT-4o Integration**: Powered by the latest OpenAI model
- **Threat Pattern Analysis**: AI-driven analysis of attack patterns and correlations
- **Automated Reports**: AI-generated threat intelligence reports
- **Attack Chain Analysis**: Intelligent mapping of attack sequences
- **10 Suggested Questions**: Quick access to comprehensive threat intelligence queries
- **Multi-source Analysis**: AI insights across MITRE, CISA, and URLhaus data

### 📋 **Professional Reporting & Export**
- **PDF Reports**: Comprehensive, executive, and technical report formats
- **Excel Export**: Formatted spreadsheets with threat data
- **HTML Reports**: Web-ready reports with embedded styling
- **Data Export**: Raw data export in JSON/CSV formats
- **Quick Reports**: Weekly, monthly, and quarterly AI-generated summaries
- **Export History**: Complete audit trail of all generated reports
- **Auto-refresh**: Real-time updates of export history panel

### 🔄 **Export Tracking System**
- **Export Database Model**: Persistent storage of all export metadata
- **API Endpoints**: RESTful access to export history
- **Frontend Integration**: Automatic panel refresh after exports
- **Download Links**: Direct access to generated files
- **Export Analytics**: Track report generation patterns

## 🛠️ Technology Stack

- **Backend**: Flask (Python) with SQLAlchemy ORM
- **Database**: SQLite with comprehensive data models
- **Frontend**: Bootstrap 5 + Custom CSS + Plotly.js
- **Charts**: Interactive visualizations with real-time data and filtering
- **AI**: OpenAI GPT-4o for intelligent insights and report generation
- **Data Sources**: MITRE ATT&CK GitHub JSON, CISA KEV Catalog, Abuse.ch URLhaus
- **Export**: PDF (reportlab), Excel (openpyxl), HTML templates
- **Analytics**: Advanced temporal and geographic analysis with filter integration

## 📋 Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- OpenAI API key (for AI features)

## 🚀 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/rod5435/harmonia-incident-response-app.git
   cd harmonia-incident-response-app
   ```

2. **Create a virtual environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   Create a `.env` file in the project root:
   ```
   OPENAI_API_KEY=your_openai_api_key_here
   ```

5. **Initialize the database**
   ```bash
   python3 simple_init_db.py
   ```

6. **Run the ETL pipeline to get threat intelligence data**
   ```bash
   python3 etl_pipeline.py
   ```
   This will download:
   - 691+ MITRE ATT&CK techniques
   - 1,370+ CISA vulnerabilities
   - 80,000+ malicious URLs from URLhaus

7. **Start the application**
   ```bash
   python3 app.py
   ```

8. **Access the application**
   Open your browser and go to: `http://localhost:5000`

## 📖 Usage

### **Landing Page**
- View real-time statistics about your threat intelligence data
- Learn about data sources and capabilities
- Quick navigation to all features

### **Data Explorer**
- Browse through 82,000+ threat indicators
- Filter by type (MITRE Techniques, CVE Vulnerabilities, Malicious URLs)
- View detailed information about each threat
- See real-time counts and statistics
- Advanced search and filtering capabilities

### **Dashboard & Analytics**
- **Indicator Types Distribution**: Pie chart showing MITRE vs CVE vs URL data
- **Source Distribution**: Bar chart of data sources
- **Recent Activity Trend**: Line chart of new indicators over time
- **Top MITRE Techniques**: Horizontal bar chart of most common techniques
- **Severity Distribution**: Donut chart of threat severity levels
- **Temporal Analysis**: Multi-line time series showing threat trends over time
- **Geographic Intelligence**: Country-based threat distribution with color-coded levels
- **Dynamic Filtering**: Real-time filtering by time range, severity, and data sources
- **Interactive Insights**: Peak period detection, weekly patterns, and regional hotspots

### **AI Insights**
- Ask questions about your threat data in natural language
- Get intelligent responses powered by GPT-4o
- Use suggested questions for quick insights
- Press Enter to submit questions quickly
- Threat pattern analysis and correlation

### **Reports & Export**
- **Professional Reports**: Generate comprehensive, executive, and technical reports
- **Quick Reports**: AI-generated weekly, monthly, and quarterly summaries
- **Multiple Formats**: PDF, Excel, HTML, and raw data exports
- **Export History**: Track all generated reports with download links
- **Template System**: Pre-configured report templates for different audiences

## 🔧 Configuration

### **Database Configuration**
The app uses SQLite by default. Database settings are in `config.py`:
```python
SQLALCHEMY_DATABASE_URI = 'sqlite:///incident_response.db'
```

### **OpenAI Configuration**
Set your OpenAI API key in the `.env` file:
```
OPENAI_API_KEY=your_api_key_here
```

### **ETL Pipeline Configuration**
The enhanced ETL pipeline downloads data from:
- **MITRE ATT&CK**: Official GitHub JSON feed with 691+ techniques
- **CISA KEV**: Full catalog of 1,370+ exploited vulnerabilities
- **Abuse.ch URLhaus**: 80,000+ malicious URLs with ZIP handling

## 📁 Project Structure

```
harmonia-incident-response-app/
├── app.py                  # Main Flask application
├── config.py               # Configuration settings
├── models.py               # SQLAlchemy database models (including Export model)
├── utils.py                # Utility functions, analytics, and export tracking
├── etl_pipeline.py         # Enhanced ETL pipeline for threat intelligence data
├── etl_pipeline_enhanced.py # Alternative ETL with additional features
├── openai_integration.py   # OpenAI GPT integration
├── reporting.py            # Report generation and export functionality
├── simple_init_db.py       # Database initialization script
├── requirements.txt        # Python dependencies
├── .env                    # Environment variables (create this)
├── .gitignore             # Git ignore file
├── README.md              # This file
├── templates/             # HTML templates
│   ├── base.html          # Base template with styling
│   ├── index.html         # Landing page
│   ├── data_explorer.html # Data explorer interface
│   ├── dashboard.html     # Analytics dashboard
│   ├── ai_insights.html   # AI chat interface
│   └── reports.html       # Reports and export interface
├── static/                # Static files (CSS, JS, generated reports)
    ├── css/
    ├── js/
    └── reports/           # Generated report files
└── tests/                 # Comprehensive test suite
    ├── test_app.py
    ├── test_models.py
    ├── test_openai_integration.py
    ├── test_reporting.py
    └── test_utils.py
```

## 🔄 Data Updates

To update your threat intelligence data:

1. **Manual Update**
   ```bash
   python3 etl_pipeline.py
   ```
   This will download the latest data from all sources and replace existing data.

2. **Data Sources**
   - **MITRE ATT&CK**: Updated via GitHub JSON feed
   - **CISA KEV**: Real-time vulnerability data
   - **URLhaus**: Live malicious URL feed

## 🧪 Testing

Run the comprehensive test suite:
```bash
python3 run_tests.py
```

Tests cover:
- Flask routes and API endpoints
- Database models and operations
- OpenAI integration (mocked)
- Reporting and export functionality
- Utility functions and data processing

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue in the GitHub repository
- Check the documentation in this README
- Review the code comments for implementation details

## 🎯 Current Status

### ✅ **Completed Features**
- [x] Real-time threat intelligence from 3 sources
- [x] Advanced search and filtering
- [x] Export functionality (PDF, Excel, HTML, CSV)
- [x] AI-powered insights and analysis
- [x] Professional reporting system
- [x] Export tracking and history
- [x] Comprehensive test suite
- [x] Enhanced ETL pipeline with error handling
- [x] Temporal analysis with threat trends and peak detection
- [x] Geographic threat intelligence with country mapping
- [x] Dynamic filtering system with real-time chart updates
- [x] Interactive dashboard with drill-down capabilities

### 🔮 **Future Enhancements**
- [ ] Real-time data updates with webhooks
- [ ] User authentication and roles
- [ ] API endpoints for external integration
- [ ] Additional threat intelligence sources
- [ ] Automated scheduling and alerts
- [ ] Threat correlation analysis
- [ ] Machine learning threat detection

## 📊 **Data Statistics**

**Current Database:**
- **Total Indicators**: 82,173+
- **MITRE Techniques**: 691+
- **CISA Vulnerabilities**: 1,370+
- **Malicious URLs**: 80,000+
- **Data Sources**: 3 authoritative feeds
- **Export Formats**: 4 (PDF, Excel, HTML, CSV)

**Performance:**
- **ETL Processing Time**: ~30-60 seconds
- **Database Size**: Optimized for speed
- **Real-time Updates**: Instant UI refresh
- **Export Generation**: <10 seconds per report

## 🏆 **Major Achievements**

### **Enterprise-Grade Threat Intelligence Platform**
- **82,000+ Indicators**: Comprehensive coverage across multiple threat types
- **3 Authoritative Sources**: MITRE ATT&CK, CISA KEV, Abuse.ch URLhaus
- **Real-time Processing**: Robust ETL pipeline with error handling and ZIP extraction
- **AI-Powered Analysis**: GPT-4o integration for intelligent threat insights

### **Professional Reporting System**
- **Multiple Export Formats**: PDF, Excel, HTML, CSV with professional styling
- **Export Tracking**: Complete audit trail with auto-refresh functionality
- **Quick Reports**: AI-generated summaries for different time periods
- **Template System**: Pre-configured reports for executives, technical teams, and analysts

### **Production-Ready Features**
- **Comprehensive Testing**: Full test suite covering all major functionality
- **Error Handling**: Robust fallback mechanisms and graceful degradation
- **Scalable Architecture**: Optimized database and efficient data processing
- **Modern UI/UX**: Responsive design with real-time updates and intuitive navigation

### **Latest Enhancements**
- **Enhanced ETL Pipeline**: ZIP file handling, multiple data sources, error recovery
- **Export History Panel**: Real-time tracking of all generated reports
- **Auto-refresh Functionality**: Seamless user experience with automatic updates
- **Multi-source Data Explorer**: Unified interface for all threat intelligence data


Dashboard Enhancement Proposals
1. Multi-Source Data Visualization
3-Source Pie Chart: MITRE, CISA, URLhaus distribution
Source Comparison Bar Chart: Indicators per source with severity breakdown
Real-time Source Stats: Live counters for each data source
2. Enhanced Interactivity
Clickable Charts: Drill-down into specific sources/types
Dynamic Filtering: Filter charts by date range, severity, source
Hover Details: Rich tooltips with detailed information
Animated Transitions: Smooth chart updates and transitions
3. New Analytics Sections
Threat Type Analysis:
MITRE Techniques by tactic
CISA Vulnerabilities by vendor/product
URLhaus URLs by threat type (malware, phishing, etc.)
Severity Distribution: Cross-source severity analysis
Temporal Analysis: New indicators over time by source
Geographic Analysis: URLhaus data by country/region
4. Interactive Features
Source Toggle: Show/hide specific data sources
Time Range Selector: Last 7 days, 30 days, 90 days, all time
Severity Filter: Filter by severity levels
Search Integration: Search results reflected in charts
5. Real-time Updates
Live Data Refresh: Auto-update charts every 30 seconds
New Indicator Alerts: Highlight recent additions
Trend Indicators: Show increasing/decreasing trends