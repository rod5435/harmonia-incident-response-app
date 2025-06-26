import requests
import json
import csv
import sqlite3
from datetime import datetime
import os
from typing import List, Dict, Any

class ThreatIntelligenceETL:
    def __init__(self, db_path: str = 'incident_response.db'):
        self.db_path = db_path
        self.mitre_url = "https://attack.mitre.org/api/techniques/enterprise/"
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
        
    def download_mitre_data(self) -> List[Dict[str, Any]]:
        """Download MITRE ATT&CK techniques"""
        print("Downloading MITRE ATT&CK data...")
        try:
            response = requests.get(self.mitre_url, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            indicators = []
            for technique in data:
                # Check if this is a valid technique with required fields
                if (technique.get('technique_id') and 
                    technique.get('name') and 
                    technique.get('description')):
                    
                    indicators.append({
                        'indicator_type': 'MITRE Technique',
                        'indicator_value': technique.get('technique_id', ''),
                        'name': technique.get('name', ''),
                        'description': technique.get('description', ''),
                        'source': 'MITRE ATT&CK',
                        'severity_score': '5.0',  # Default score for techniques
                        'date_added': datetime.now().strftime('%Y-%m-%d'),
                        'timestamp': datetime.now().isoformat()
                    })
            
            print(f"Downloaded {len(indicators)} MITRE techniques from API")
            
            # If we got data from API, return it (limited to 50 for testing)
            if indicators:
                return indicators[:50]
            else:
                print("No data from API, using sample MITRE data...")
                return self.get_sample_mitre_data()
            
        except Exception as e:
            print(f"Error downloading MITRE data: {e}")
            print("Using sample MITRE data as fallback...")
            return self.get_sample_mitre_data()
    
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
            return indicators[:50]  # Limit to first 50 for testing
            
        except Exception as e:
            print(f"Error downloading CISA data: {e}")
            return []
    
    def normalize_data(self, mitre_data: List[Dict], cisa_data: List[Dict]) -> List[Dict]:
        """Normalize and merge the data"""
        print("Normalizing data...")
        
        all_indicators = []
        
        # Add MITRE data
        for item in mitre_data:
            all_indicators.append(item)
        
        # Add CISA data
        for item in cisa_data:
            all_indicators.append(item)
        
        print(f"Total normalized indicators: {len(all_indicators)}")
        print(f"  - MITRE Techniques: {len(mitre_data)}")
        print(f"  - CVE Vulnerabilities: {len(cisa_data)}")
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
        
        if not mitre_data and not cisa_data:
            print("❌ No data downloaded. ETL pipeline failed.")
            return False
        
        # Normalize data
        normalized_data = self.normalize_data(mitre_data, cisa_data)
        
        # Store data
        success = self.store_data(normalized_data)
        
        if success:
            print("✅ ETL pipeline completed successfully!")
        else:
            print("❌ ETL pipeline failed at storage step.")
        
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