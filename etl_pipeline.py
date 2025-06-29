import requests
import json
import csv
import sqlite3
from datetime import datetime
import os
from typing import List, Dict, Any
import zipfile
import io

MITRE_GITHUB_JSON_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
ABUSE_CH_URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv/"

# Import for data update tracking
try:
    from app import create_app
    from models import db, DataUpdate
    TRACKING_AVAILABLE = True
except ImportError:
    TRACKING_AVAILABLE = False
    print("Warning: Data update tracking not available (Flask app not accessible)")

class ThreatIntelligenceETL:
    def __init__(self, db_path: str = 'incident_response.db'):
        self.db_path = db_path
        self.mitre_url = "https://attack.mitre.org/api/techniques/enterprise/"  # legacy, not used
        self.cisa_url = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
        
    def get_sample_mitre_data(self) -> List[Dict[str, Any]]:
        """Get sample MITRE ATT&CK data as fallback"""
        sample_techniques = [
            {
                'technique_id': 'T1001',
                'name': 'Data Obfuscation',
                'description': 'Adversaries may obfuscate data to hide information from being discovered.'
            },
            {
                'technique_id': 'T1002',
                'name': 'Data Compressed',
                'description': 'Adversaries may compress data to make it unavailable to discover and analysis tools.'
            },
            {
                'technique_id': 'T1003',
                'name': 'OS Credential Dumping',
                'description': 'Adversaries may attempt to dump credentials to obtain account login and credential material.'
            },
            {
                'technique_id': 'T1004',
                'name': 'Winlogon Helper DLL',
                'description': 'Adversaries may abuse features of Winlogon to execute DLLs and/or executables.'
            },
            {
                'technique_id': 'T1005',
                'name': 'Data from Local System',
                'description': 'Adversaries may search local system sources to find files of interest and sensitive data.'
            },
            {
                'technique_id': 'T1006',
                'name': 'File System Logical Offsets',
                'description': 'Adversaries may use file system logical offset manipulations to hide file system data.'
            },
            {
                'technique_id': 'T1007',
                'name': 'System Service Discovery',
                'description': 'Adversaries may try to get information about registered services.'
            },
            {
                'technique_id': 'T1008',
                'name': 'Fallback Channels',
                'description': 'Adversaries may use fallback or alternate communication channels if the primary channel is compromised.'
            },
            {
                'technique_id': 'T1009',
                'name': 'Binary Padding',
                'description': 'Adversaries may use binary padding to add junk data and change the on-disk representation of malware.'
            },
            {
                'technique_id': 'T1010',
                'name': 'Application Window Discovery',
                'description': 'Adversaries may attempt to get a listing of open application windows.'
            }
        ]
        
        indicators = []
        for technique in sample_techniques:
            indicators.append({
                'indicator_type': 'MITRE Technique',
                'indicator_value': technique['technique_id'],
                'name': technique['name'],
                'description': technique['description'],
                'source': 'MITRE ATT&CK',
                'severity_score': '5.0',
                'date_added': datetime.now().strftime('%Y-%m-%d'),
                'timestamp': datetime.now().isoformat()
            })
        
        return indicators
        
    def get_mitre_github_techniques(self) -> List[Dict[str, Any]]:
        """Download and parse MITRE ATT&CK techniques from GitHub JSON feed"""
        print("Downloading MITRE ATT&CK techniques from GitHub JSON feed...")
        try:
            response = requests.get(MITRE_GITHUB_JSON_URL, timeout=60)
            response.raise_for_status()
            data = response.json()
            objects = data.get('objects', [])
            techniques = []
            for obj in objects:
                if obj.get('type') == 'attack-pattern' and not obj.get('revoked', False):
                    technique_id = None
                    for ext_ref in obj.get('external_references', []):
                        if ext_ref.get('source_name') == 'mitre-attack':
                            technique_id = ext_ref.get('external_id')
                            break
                    if not technique_id:
                        continue
                    techniques.append({
                        'indicator_type': 'MITRE Technique',
                        'indicator_value': technique_id,
                        'name': obj.get('name', ''),
                        'description': obj.get('description', ''),
                        'source': 'MITRE ATT&CK (GitHub)',
                        'severity_score': '5.0',
                        'date_added': datetime.now().strftime('%Y-%m-%d'),
                        'timestamp': datetime.now().isoformat()
                    })
            print(f"Downloaded {len(techniques)} MITRE techniques from GitHub JSON feed")
            return techniques
        except Exception as e:
            print(f"Error downloading/parsing MITRE GitHub JSON: {e}")
            print("Using sample MITRE data as fallback...")
            return self.get_sample_mitre_data()

    def download_mitre_data(self) -> List[Dict[str, Any]]:
        """Download MITRE ATT&CK techniques (now from GitHub JSON feed)"""
        return self.get_mitre_github_techniques()
    
    def download_cisa_data(self) -> List[Dict[str, Any]]:
        """Download CISA Known Exploited Vulnerabilities"""
        print("Downloading CISA Known Exploited Vulnerabilities...")
        try:
            response = requests.get(self.cisa_url, timeout=30)
            response.raise_for_status()
            
            # Parse CSV data
            csv_data = response.text.splitlines()
            reader = csv.DictReader(csv_data)
            
            indicators = []
            for row in reader:
                indicators.append({
                    'indicator_type': 'CVE Vulnerability',
                    'indicator_value': row.get('cveID', ''),
                    'name': row.get('product', ''),
                    'description': row.get('shortDescription', ''),
                    'source': 'CISA KEV Catalog',
                    'severity_score': '8.0',  # High severity for exploited vulnerabilities
                    'date_added': row.get('dateAdded', datetime.now().strftime('%Y-%m-%d')),
                    'timestamp': datetime.now().isoformat()
                })
            
            print(f"Downloaded {len(indicators)} CISA vulnerabilities")
            return indicators  # Removed limit for more data
            
        except Exception as e:
            print(f"Error downloading CISA data: {e}")
            return []

    def download_urlhaus_data(self) -> List[Dict[str, Any]]:
        """Download Abuse.ch URLhaus malicious URLs (handle ZIP file, no header in CSV)"""
        print("Downloading Abuse.ch URLhaus malicious URLs...")
        try:
            response = requests.get(ABUSE_CH_URLHAUS_URL, timeout=60)
            response.raise_for_status()
            
            # Open as ZIP file
            with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
                csv_filename = None
                for name in zip_file.namelist():
                    if name.endswith('.csv') or name.endswith('.txt'):
                        csv_filename = name
                        break
                if not csv_filename:
                    print("No CSV file found in ZIP")
                    return []
                with zip_file.open(csv_filename) as csv_file:
                    csv_content = csv_file.read().decode('utf-8', errors='replace')
            
            # Use the correct header for URLhaus plain CSV
            urlhaus_header = [
                'id', 'dateadded', 'url', 'url_status', 'last_online', 'threat', 'tags', 'reference', 'reporter'
            ]
            lines = csv_content.splitlines()
            # Remove any empty lines
            data_lines = [line for line in lines if line.strip()]
            print(f"First 5 data lines:")
            for l in data_lines[:5]:
                print(l)
            reader = csv.DictReader(data_lines, fieldnames=urlhaus_header)
            indicators = []
            for row in reader:
                if not row.get('url') or row['url'] == 'url':
                    continue
                severity = self.calculate_urlhaus_severity(row)
                indicators.append({
                    'indicator_type': 'Malicious URL',
                    'indicator_value': row.get('url', ''),
                    'name': f"Malicious URL - {row.get('tags', 'Unknown')}",
                    'description': f"Malicious URL detected by Abuse.ch URLhaus. Tags: {row.get('tags', 'None')}. Status: {row.get('url_status', 'Unknown')}",
                    'source': 'Abuse.ch URLhaus',
                    'severity_score': str(severity),
                    'date_added': row.get('dateadded', datetime.now().strftime('%Y-%m-%d')),
                    'timestamp': datetime.now().isoformat()
                })
            print(f"Downloaded {len(indicators)} malicious URLs from URLhaus")
            return indicators
        except Exception as e:
            print(f"Error downloading URLhaus data: {e}")
            return []

    def calculate_urlhaus_severity(self, row: Dict) -> float:
        """Calculate severity score for URLhaus entry"""
        base_score = 7.0  # High base score for malicious URLs
        
        # Increase severity for active URLs
        url_status = row.get('url_status', '').lower()
        if url_status == 'online':
            base_score += 1.0
        
        # Increase severity for certain tags
        tags = row.get('tags', '').lower()
        if 'malware' in tags:
            base_score += 1.0
        if 'phishing' in tags:
            base_score += 0.5
        if 'ransomware' in tags:
            base_score += 1.5
        
        return min(base_score, 10.0)
    
    def normalize_data(self, mitre_data: List[Dict], cisa_data: List[Dict], urlhaus_data: List[Dict]) -> List[Dict]:
        """Normalize and merge the data"""
        print("Normalizing data...")
        
        all_indicators = []
        
        # Add MITRE data
        for item in mitre_data:
            all_indicators.append(item)
        
        # Add CISA data
        for item in cisa_data:
            all_indicators.append(item)
        
        # Add URLhaus data
        for item in urlhaus_data:
            all_indicators.append(item)
        
        print(f"Total normalized indicators: {len(all_indicators)}")
        print(f"  - MITRE Techniques: {len(mitre_data)}")
        print(f"  - CVE Vulnerabilities: {len(cisa_data)}")
        print(f"  - Malicious URLs: {len(urlhaus_data)}")
        return all_indicators
    
    def store_data(self, indicators: List[Dict]) -> bool:
        """Store indicators in SQLite database"""
        print("Storing data in database...")
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Clear existing data (optional - comment out if you want to keep existing data)
            cursor.execute("DELETE FROM indicators")
            print("Cleared existing indicators")
            
            # Insert new data
            for indicator in indicators:
                cursor.execute('''
                    INSERT INTO indicators 
                    (indicator_type, indicator_value, name, description, source, severity_score, date_added, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    indicator['indicator_type'],
                    indicator['indicator_value'],
                    indicator['name'],
                    indicator['description'],
                    indicator['source'],
                    indicator['severity_score'],
                    indicator['date_added'],
                    indicator['timestamp']
                ))
            
            conn.commit()
            conn.close()
            
            print(f"Successfully stored {len(indicators)} indicators in database")
            return True
            
        except Exception as e:
            print(f"Error storing data: {e}")
            return False
    
    def run_etl(self) -> bool:
        """Run the complete ETL pipeline"""
        print("=== STARTING ETL PIPELINE ===")
        
        # Download data
        mitre_data = self.download_mitre_data()
        cisa_data = self.download_cisa_data()
        urlhaus_data = self.download_urlhaus_data()
        
        if not mitre_data and not cisa_data and not urlhaus_data:
            print("❌ No data downloaded. ETL pipeline failed.")
            return False
        
        # Normalize data
        normalized_data = self.normalize_data(mitre_data, cisa_data, urlhaus_data)
        
        # Store data
        success = self.store_data(normalized_data)
        
        if success:
            print("✅ ETL pipeline completed successfully!")
            if TRACKING_AVAILABLE:
                try:
                    # Record data update using Flask app context
                    app = create_app()
                    with app.app_context():
                        update = DataUpdate(
                            update_type='etl_pipeline',
                            status='success',
                            records_processed=len(normalized_data),
                            details=json.dumps({
                                'mitre_count': len(mitre_data),
                                'cisa_count': len(cisa_data),
                                'urlhaus_count': len(urlhaus_data)
                            })
                        )
                        db.session.add(update)
                        db.session.commit()
                        print(f"📊 Data update recorded: {len(normalized_data)} indicators processed")
                except Exception as e:
                    print(f"Warning: Could not record data update: {e}")
        else:
            print("❌ ETL pipeline failed at storage step.")
            if TRACKING_AVAILABLE:
                try:
                    app = create_app()
                    with app.app_context():
                        update = DataUpdate(
                            update_type='etl_pipeline',
                            status='failed',
                            error_message='ETL pipeline failed at storage step'
                        )
                        db.session.add(update)
                        db.session.commit()
                except Exception as e:
                    print(f"Warning: Could not record failed update: {e}")
        
        return success

def main():
    """Main function to run the ETL pipeline"""
    etl = ThreatIntelligenceETL()
    success = etl.run_etl()
    
    if success:
        print("\n🎉 Your incident response app now has real threat intelligence data!")
        print("You can now run the Flask app and explore the enriched data.")
    else:
        print("\n⚠️  ETL pipeline failed. Check the error messages above.")

if __name__ == "__main__":
    main() 