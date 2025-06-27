#!/usr/bin/env python3
"""
Test script for Enhanced ETL Pipeline
Demonstrates different configurations and capabilities
"""

from etl_pipeline_enhanced import EnhancedThreatIntelligenceETL
from models import db, Indicator
from app import create_app

def test_current_data():
    """Check current data in database"""
    app = create_app()
    with app.app_context():
        total = Indicator.query.count()
        mitre = Indicator.query.filter_by(indicator_type='MITRE Technique').count()
        cisa = Indicator.query.filter_by(indicator_type='CVE Vulnerability').count()
        
        print(f"📊 Current Database Status:")
        print(f"  Total indicators: {total}")
        print(f"  MITRE techniques: {mitre}")
        print(f"  CVE vulnerabilities: {cisa}")
        print()

def test_limited_load():
    """Test limited load (100 each)"""
    print("🧪 Testing Limited Load (100 MITRE + 100 CISA)")
    etl = EnhancedThreatIntelligenceETL()
    success = etl.run_etl(mitre_limit=100, cisa_limit=100, clear_existing=True)
    
    if success:
        test_current_data()
    return success

def test_full_load():
    """Test full load (no limits)"""
    print("🚀 Testing Full Load (No Limits)")
    etl = EnhancedThreatIntelligenceETL()
    success = etl.run_etl(clear_existing=True)
    
    if success:
        test_current_data()
    return success

def test_incremental_load():
    """Test incremental load (keep existing data)"""
    print("📈 Testing Incremental Load (Keep Existing Data)")
    etl = EnhancedThreatIntelligenceETL()
    success = etl.run_etl(mitre_limit=50, cisa_limit=50, clear_existing=False)
    
    if success:
        test_current_data()
    return success

def main():
    """Main test function"""
    print("🔬 Enhanced ETL Pipeline Test Suite")
    print("=" * 50)
    
    # Check current state
    test_current_data()
    
    # Ask user what to test
    print("Choose test option:")
    print("1. Limited load (100 each) - Fast test")
    print("2. Full load (no limits) - Production ready")
    print("3. Incremental load (keep existing) - Add to current data")
    print("4. Exit")
    
    choice = input("\nEnter choice (1-4): ").strip()
    
    if choice == "1":
        test_limited_load()
    elif choice == "2":
        test_full_load()
    elif choice == "3":
        test_incremental_load()
    elif choice == "4":
        print("Exiting...")
    else:
        print("Invalid choice. Exiting...")

if __name__ == "__main__":
    main() 