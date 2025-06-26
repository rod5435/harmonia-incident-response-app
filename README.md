# Harmoni Incident Response App

A comprehensive threat intelligence platform that provides real-time insights into cybersecurity threats, vulnerabilities, and attack techniques. Built with cutting-edge AI to help security teams make data-driven decisions and respond to incidents faster.

## 🚀 Features

### 📊 **Real-time Threat Intelligence**
- **MITRE ATT&CK Techniques**: Comprehensive database of adversary tactics, techniques, and procedures
- **CISA Known Exploited Vulnerabilities**: Active exploitation data from CISA's KEV catalog
- **Automated ETL Pipeline**: Continuous data updates from authoritative sources

### 📈 **Advanced Analytics Dashboard**
- **Interactive Charts**: 5 different chart types including pie charts, bar charts, and trend analysis
- **Real-time Statistics**: Live counts and metrics for threat indicators
- **Severity Distribution**: Visual analysis of threat severity levels
- **Source Analytics**: Breakdown of data sources and their contributions

### 🔍 **Data Explorer**
- **Advanced Filtering**: Filter by indicator type, source, and severity
- **Real-time Search**: Search across all threat intelligence fields
- **Modern UI**: Beautiful, responsive design with badges and icons
- **Quick Statistics**: Live counts and metrics display

### 🤖 **AI-Powered Insights**
- **Natural Language Queries**: Ask questions about your threat data in plain English
- **GPT-4o Integration**: Powered by the latest OpenAI model
- **Suggested Questions**: Quick access to common threat intelligence queries
- **Context-Aware Responses**: AI understands your specific threat landscape

## 🛠️ Technology Stack

- **Backend**: Flask (Python)
- **Database**: SQLite with SQLAlchemy ORM
- **Frontend**: Bootstrap 5 + Custom CSS
- **Charts**: Plotly.js for interactive visualizations
- **AI**: OpenAI GPT-4o for intelligent insights
- **Data Sources**: MITRE ATT&CK API, CISA KEV Catalog

## 📋 Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- OpenAI API key (for AI features)

## 🚀 Installation

1. **Clone the repository**
   ```bash
   git clone <your-repo-url>
   cd incident_response_app
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
- Browse through threat indicators
- Filter by type (MITRE Techniques, CVE Vulnerabilities)
- View detailed information about each threat
- See real-time counts and statistics

### **Dashboard & Analytics**
- **Indicator Types Distribution**: Pie chart showing MITRE vs CVE data
- **Source Distribution**: Bar chart of data sources
- **Recent Activity Trend**: Line chart of new indicators over time
- **Top MITRE Techniques**: Horizontal bar chart of most common techniques
- **Severity Distribution**: Donut chart of threat severity levels

### **AI Insights**
- Ask questions about your threat data in natural language
- Get intelligent responses powered by GPT-4o
- Use suggested questions for quick insights
- Press Enter to submit questions quickly

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
The ETL pipeline downloads data from:
- MITRE ATT&CK: `https://attack.mitre.org/api/techniques/enterprise/`
- CISA KEV: `https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv`

## 📁 Project Structure

```
incident_response_app/
├── app.py                  # Main Flask application
├── config.py               # Configuration settings
├── models.py               # SQLAlchemy database models
├── utils.py                # Utility functions and analytics
├── etl_pipeline.py         # ETL pipeline for threat intelligence data
├── openai_integration.py   # OpenAI GPT integration
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
│   └── ai_insights.html   # AI chat interface
└── static/                # Static files (CSS, JS)
    ├── css/
    └── js/
```

## 🔄 Data Updates

To update your threat intelligence data:

1. **Manual Update**
   ```bash
   python3 etl_pipeline.py
   ```

2. **Automatic Updates** (Future Feature)
   - Scheduled ETL pipeline runs
   - Real-time data feeds
   - Webhook integrations

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

## 🔮 Roadmap

### **Version 2.0 Features**
- [ ] Real-time data updates with webhooks
- [ ] Advanced search and filtering
- [ ] Export functionality (PDF, CSV)
- [ ] User authentication and roles
- [ ] API endpoints for integration
- [ ] Threat correlation analysis
- [ ] Incident response recommendations
- [ ] Custom report templates

### **Version 3.0 Features**
- [ ] Machine learning threat detection
- [ ] Automated incident response
- [ ] Integration with SIEM systems
- [ ] Mobile application
- [ ] Multi-tenant architecture
- [ ] Advanced threat hunting tools

---

**Built with ❤️ for the cybersecurity community**

