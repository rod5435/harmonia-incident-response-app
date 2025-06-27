#!/usr/bin/env python3
"""
Enhanced ETL Pipeline for Harmonia Incident Response App
- Removes artificial limits
- Adds more comprehensive data fetching
- Includes incremental update capability
- Better error handling and logging
"""

import requests
import json
import csv
import sqlite3
from datetime import datetime, timedelta
import os
from typing import List, Dict, Any, Optional
import time

class EnhancedThreatIntelligenceETL:
    def __init__(self, db_path: str = 'incident_response.db'):
        self.db_path = db_path
        # Updated MITRE ATT&CK API endpoints
        self.mitre_techniques_url = "https://attack.mitre.org/api/techniques/enterprise/"
        self.mitre_tactics_url = "https://attack.mitre.org/api/tactics/enterprise/"
        self.cisa_url = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Harmonia-ETL/1.0 (Security Research)'
        })
        
    def download_mitre_data(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Download MITRE ATT&CK techniques with configurable limit"""
        print("Downloading MITRE ATT&CK data...")
        
        # Try multiple API endpoints in case of changes
        api_endpoints = [
            "https://attack.mitre.org/api/techniques/enterprise/",
            "https://attack.mitre.org/api/techniques/",
            "https://attack.mitre.org/api/enterprise/techniques/"
        ]
        
        for endpoint in api_endpoints:
            try:
                print(f"Trying endpoint: {endpoint}")
                response = self.session.get(endpoint, timeout=60)
                response.raise_for_status()
                data = response.json()
                
                indicators = []
                count = 0
                
                for technique in data:
                    # Check if this is a valid technique with required fields
                    if (technique.get('technique_id') and 
                        technique.get('name') and 
                        technique.get('description')):
                        
                        # Calculate severity based on technique properties
                        severity = self.calculate_mitre_severity(technique)
                        
                        indicators.append({
                            'indicator_type': 'MITRE Technique',
                            'indicator_value': technique.get('technique_id', ''),
                            'name': technique.get('name', ''),
                            'description': technique.get('description', ''),
                            'source': 'MITRE ATT&CK',
                            'severity_score': str(severity),
                            'date_added': datetime.now().strftime('%Y-%m-%d'),
                            'timestamp': datetime.now().isoformat()
                        })
                        
                        count += 1
                        if limit and count >= limit:
                            break
                
                print(f"✅ Successfully downloaded {len(indicators)} MITRE techniques from {endpoint}")
                return indicators
                
            except requests.exceptions.RequestException as e:
                print(f"❌ Failed to fetch from {endpoint}: {e}")
                continue
            except Exception as e:
                print(f"❌ Error processing data from {endpoint}: {e}")
                continue
        
        # If all API endpoints fail, use sample data
        print("⚠️  All MITRE API endpoints failed. Using sample data...")
        return self.get_sample_mitre_data()
    
    def calculate_mitre_severity(self, technique: Dict) -> float:
        """Calculate severity score for MITRE technique"""
        base_score = 5.0
        
        # Increase severity for techniques with more platforms
        platforms = technique.get('platform', [])
        if len(platforms) > 3:
            base_score += 1.0
        
        # Increase severity for techniques with data sources
        data_sources = technique.get('data_sources', [])
        if data_sources:
            base_score += 0.5
        
        # Cap at 10.0
        return min(base_score, 10.0)
    
    def download_cisa_data(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Download CISA Known Exploited Vulnerabilities with configurable limit"""
        print("Downloading CISA Known Exploited Vulnerabilities...")
        
        # Try multiple CISA endpoints in case of changes
        cisa_endpoints = [
            "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.csv",
            "https://www.cisa.gov/sites/default/files/feeds/kev.csv"
        ]
        
        for endpoint in cisa_endpoints:
            try:
                print(f"Trying CISA endpoint: {endpoint}")
                response = self.session.get(endpoint, timeout=60)
                response.raise_for_status()
                
                # Parse CSV data
                csv_data = response.text.splitlines()
                reader = csv.DictReader(csv_data)
                
                indicators = []
                count = 0
                
                for row in reader:
                    # Calculate severity based on CISA data
                    severity = self.calculate_cisa_severity(row)
                    
                    indicators.append({
                        'indicator_type': 'CVE Vulnerability',
                        'indicator_value': row.get('cveID', ''),
                        'name': row.get('product', ''),
                        'description': row.get('shortDescription', ''),
                        'source': 'CISA KEV Catalog',
                        'severity_score': str(severity),
                        'date_added': row.get('dateAdded', datetime.now().strftime('%Y-%m-%d')),
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    count += 1
                    if limit and count >= limit:
                        break
                
                print(f"✅ Successfully downloaded {len(indicators)} CISA vulnerabilities from {endpoint}")
                return indicators
                
            except requests.exceptions.RequestException as e:
                print(f"❌ Failed to fetch from {endpoint}: {e}")
                continue
            except Exception as e:
                print(f"❌ Error processing CISA data from {endpoint}: {e}")
                continue
        
        # If all CISA endpoints fail, return sample data
        print("⚠️  All CISA endpoints failed. Using sample CISA data...")
        return self.get_sample_cisa_data()
    
    def calculate_cisa_severity(self, row: Dict) -> float:
        """Calculate severity score for CISA vulnerability"""
        base_score = 8.0  # High base score for exploited vulnerabilities
        
        # Check if it's a recent addition
        date_added = row.get('dateAdded', '')
        if date_added:
            try:
                added_date = datetime.strptime(date_added, '%Y-%m-%d')
                days_old = (datetime.now() - added_date).days
                if days_old <= 30:  # Recent vulnerabilities get higher score
                    base_score += 1.0
            except:
                pass
        
        # Check required action urgency
        required_action = row.get('requiredAction', '').lower()
        if 'immediate' in required_action or 'urgent' in required_action:
            base_score += 0.5
        
        return min(base_score, 10.0)
    
    def get_sample_mitre_data(self) -> List[Dict[str, Any]]:
        """Get comprehensive sample MITRE ATT&CK data as fallback"""
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
            },
            {
                'technique_id': 'T1011',
                'name': 'Exfiltration Over Other Network Medium',
                'description': 'Adversaries may steal data by exfiltrating it over a different network medium than the primary command and control channel.'
            },
            {
                'technique_id': 'T1012',
                'name': 'Query Registry',
                'description': 'Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.'
            },
            {
                'technique_id': 'T1013',
                'name': 'Port Monitors',
                'description': 'Adversaries may use port monitors to capture data passed between the I/O ports and system bus.'
            },
            {
                'technique_id': 'T1014',
                'name': 'Rootkit',
                'description': 'Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components.'
            },
            {
                'technique_id': 'T1015',
                'name': 'Accessibility Features',
                'description': 'Adversaries may use accessibility features to establish persistence or gain privileges.'
            }
        ]
        
        indicators = []
        for technique in sample_techniques:
            indicators.append({
                'indicator_type': 'MITRE Technique',
                'indicator_value': technique['technique_id'],
                'name': technique['name'],
                'description': technique['description'],
                'source': 'MITRE ATT&CK (Sample Data)',
                'severity_score': '5.0',
                'date_added': datetime.now().strftime('%Y-%m-%d'),
                'timestamp': datetime.now().isoformat()
            })
        
        print(f"📋 Using {len(indicators)} sample MITRE techniques")
        return indicators
    
    def get_sample_cisa_data(self) -> List[Dict[str, Any]]:
        """Get sample CISA Known Exploited Vulnerabilities data as fallback"""
        sample_vulnerabilities = [
            {
                'cveID': 'CVE-2023-1234',
                'product': 'Sample Product 1',
                'shortDescription': 'A critical vulnerability in sample product that allows remote code execution.',
                'dateAdded': '2023-01-15'
            },
            {
                'cveID': 'CVE-2023-5678',
                'product': 'Sample Product 2',
                'shortDescription': 'Authentication bypass vulnerability in sample product.',
                'dateAdded': '2023-02-20'
            },
            {
                'cveID': 'CVE-2023-9012',
                'product': 'Sample Product 3',
                'shortDescription': 'SQL injection vulnerability in sample product web interface.',
                'dateAdded': '2023-03-10'
            },
            {
                'cveID': 'CVE-2023-3456',
                'product': 'Sample Product 4',
                'shortDescription': 'Cross-site scripting vulnerability in sample product.',
                'dateAdded': '2023-04-05'
            },
            {
                'cveID': 'CVE-2023-7890',
                'product': 'Sample Product 5',
                'shortDescription': 'Privilege escalation vulnerability in sample product.',
                'dateAdded': '2023-05-12'
            }
        ]
        
        indicators = []
        for vuln in sample_vulnerabilities:
            severity = self.calculate_cisa_severity(vuln)
            indicators.append({
                'indicator_type': 'CVE Vulnerability',
                'indicator_value': vuln['cveID'],
                'name': vuln['product'],
                'description': vuln['shortDescription'],
                'source': 'CISA KEV Catalog (Sample Data)',
                'severity_score': str(severity),
                'date_added': vuln['dateAdded'],
                'timestamp': datetime.now().isoformat()
            })
        
        print(f"📋 Using {len(indicators)} sample CISA vulnerabilities")
        return indicators
    
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
    
    def store_data(self, indicators: List[Dict], clear_existing: bool = True) -> bool:
        """Store indicators in SQLite database"""
        print("Storing data in database...")
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if clear_existing:
                # Clear existing data
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
    
    def run_etl(self, mitre_limit: Optional[int] = None, cisa_limit: Optional[int] = None, 
                clear_existing: bool = True) -> bool:
        """Run the complete ETL pipeline with configurable limits"""
        print("=== STARTING ENHANCED ETL PIPELINE ===")
        print(f"MITRE limit: {mitre_limit or 'No limit'}")
        print(f"CISA limit: {cisa_limit or 'No limit'}")
        print(f"Clear existing: {clear_existing}")
        
        # Download data
        mitre_data = self.download_mitre_data(mitre_limit)
        cisa_data = self.download_cisa_data(cisa_limit)
        
        if not mitre_data and not cisa_data:
            print("❌ No data downloaded. ETL pipeline failed.")
            return False
        
        # Normalize data
        normalized_data = self.normalize_data(mitre_data, cisa_data)
        
        # Store data
        success = self.store_data(normalized_data, clear_existing)
        
        if success:
            print("✅ Enhanced ETL pipeline completed successfully!")
            print(f"📊 Total indicators in database: {len(normalized_data)}")
        else:
            print("❌ ETL pipeline failed at storage step.")
        
        return success

def main():
    """Main function to run the enhanced ETL pipeline"""
    etl = EnhancedThreatIntelligenceETL()
    
    # Example configurations:
    
    # 1. Full data load (no limits)
    print("\n🚀 Option 1: Full data load (recommended for production)")
    success = etl.run_etl(clear_existing=True)
    
    # 2. Limited load for testing
    # print("\n🧪 Option 2: Limited load for testing")
    # success = etl.run_etl(mitre_limit=100, cisa_limit=100, clear_existing=True)
    
    # 3. Incremental load (keep existing data)
    # print("\n📈 Option 3: Incremental load (keep existing data)")
    # success = etl.run_etl(mitre_limit=50, cisa_limit=50, clear_existing=False)
    
    if success:
        print("\n🎉 Your incident response app now has enhanced threat intelligence data!")
        print("You can now run the Flask app and explore the enriched data.")
    else:
        print("\n⚠️  ETL pipeline failed. Check the error messages above.")

if __name__ == "__main__":
    main() 