import openai
import os
from datetime import datetime, timedelta
from models import Indicator, UserQuery, db
from sqlalchemy import func, and_, or_
import json
import re

# Initialize OpenAI client
openai.api_key = os.getenv('OPENAI_API_KEY')

def ask_gpt(question, context=""):
    """Basic GPT-4o question answering"""
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert specializing in threat intelligence and incident response. Provide clear, actionable insights based on the data provided."},
                {"role": "user", "content": f"Context: {context}\n\nQuestion: {question}"}
            ],
            max_tokens=1000,
            temperature=0.3
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error: Unable to get AI response. Please check your OpenAI API key and try again. ({str(e)})"

def analyze_threat_patterns(days=30):
    """Advanced threat pattern analysis using AI"""
    try:
        # Get recent indicators
        cutoff_date = datetime.now() - timedelta(days=days)
        indicators = Indicator.query.filter(
            Indicator.date_added >= cutoff_date.strftime('%Y-%m-%d')
        ).all()
        
        if not indicators:
            return "No recent threat data available for analysis."
        
        # Prepare data for analysis
        threat_data = []
        for ind in indicators:
            threat_data.append({
                'type': ind.indicator_type,
                'name': ind.name,
                'description': ind.description,
                'severity': ind.severity_score,
                'source': ind.source,
                'date': ind.date_added
            })
        
        # Create analysis prompt
        analysis_prompt = f"""
        Analyze the following threat intelligence data and provide insights on:
        
        1. **Emerging Threat Patterns**: What patterns or trends do you observe?
        2. **High-Risk Indicators**: Which indicators pose the highest risk and why?
        3. **Attack Vector Analysis**: What attack vectors are most prevalent?
        4. **Temporal Trends**: Are there any time-based patterns in the threats?
        5. **Source Analysis**: Which threat sources are most active?
        6. **Recommendations**: What security measures should be prioritized?
        
        Threat Data (Last {days} days):
        {json.dumps(threat_data, indent=2)}
        
        Provide a comprehensive analysis with specific examples from the data.
        """
        
        response = openai.ChatCompletion.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a senior cybersecurity analyst with expertise in threat intelligence, incident response, and security operations. Provide detailed, actionable analysis with specific recommendations."},
                {"role": "user", "content": analysis_prompt}
            ],
            max_tokens=2000,
            temperature=0.2
        )
        
        return response.choices[0].message.content
        
    except Exception as e:
        return f"Error performing threat analysis: {str(e)}"

def generate_threat_report(report_type="comprehensive", days=30):
    """Generate automated threat intelligence reports"""
    try:
        # Get data based on report type
        cutoff_date = datetime.now() - timedelta(days=days)
        cutoff_date_str = cutoff_date.strftime('%Y-%m-%d')
        
        # Get all indicators first, then filter by date if needed
        all_indicators = Indicator.query.all()
        
        # Filter indicators by date (handle string dates)
        indicators = []
        for ind in all_indicators:
            try:
                if ind.date_added and ind.date_added >= cutoff_date_str:
                    indicators.append(ind)
            except (ValueError, TypeError):
                # If date parsing fails, include the indicator anyway
                indicators.append(ind)
        
        # Limit indicators based on report type
        if report_type == "executive":
            indicators = indicators[:50]  # Limit to 50 for executive summary
            
            prompt = f"""
            Create an executive summary threat intelligence report covering the last {days} days.
            
            Include:
            1. **Executive Summary**: Key findings and business impact
            2. **Threat Landscape**: Overview of current threat environment
            3. **Risk Assessment**: High, medium, low risk categorization
            4. **Recommendations**: Strategic security recommendations
            5. **Metrics**: Key security metrics and trends
            
            Data: {len(indicators)} recent threat indicators
            
            Format as a professional executive report with clear sections and bullet points.
            """
            
        elif report_type == "technical":
            prompt = f"""
            Create a detailed technical threat intelligence report covering the last {days} days.
            
            Include:
            1. **Technical Analysis**: Deep dive into threat indicators
            2. **Attack Patterns**: Detailed analysis of attack techniques
            3. **IOC Analysis**: Analysis of indicators of compromise
            4. **Mitigation Strategies**: Technical mitigation recommendations
            5. **Detection Rules**: Suggested detection and monitoring rules
            6. **Threat Hunting**: Proactive threat hunting recommendations
            
            Data: {len(indicators)} threat indicators
            
            Provide technical details, code examples, and specific implementation guidance.
            """
            
        else:  # comprehensive
            prompt = f"""
            Create a comprehensive threat intelligence report covering the last {days} days.
            
            Include:
            1. **Executive Summary**: High-level overview for leadership
            2. **Threat Landscape**: Current threat environment analysis
            3. **Technical Analysis**: Detailed technical findings
            4. **Attack Patterns**: Analysis of attack techniques and trends
            5. **Risk Assessment**: Comprehensive risk analysis
            6. **IOC Analysis**: Detailed indicator analysis
            7. **Mitigation Strategies**: Technical and strategic recommendations
            8. **Detection & Response**: Detection rules and response procedures
            9. **Future Outlook**: Threat predictions and trends
            10. **Appendices**: Technical details, code examples, and references
            
            Data: {len(indicators)} threat indicators
            
            Format as a comprehensive security report suitable for both technical and executive audiences.
            """
        
        # Add some sample data to the prompt for better context
        sample_data = []
        for ind in indicators[:10]:  # Include first 10 indicators as examples
            sample_data.append({
                'name': ind.name,
                'type': ind.indicator_type,
                'description': ind.description,
                'severity': ind.severity_score,
                'source': ind.source
            })
        
        if sample_data:
            prompt += f"\n\nSample Data:\n{json.dumps(sample_data, indent=2)}"
        
        response = openai.ChatCompletion.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a senior cybersecurity consultant and threat intelligence analyst. Create professional, comprehensive security reports that are both technically accurate and business-relevant."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=3000,
            temperature=0.1
        )
        
        return response.choices[0].message.content
        
    except Exception as e:
        print(f"Error in generate_threat_report: {str(e)}")
        return f"Error generating threat report: {str(e)}"

def correlate_threats(indicator_id=None, search_term=None):
    """Correlate threats and find related indicators"""
    try:
        if indicator_id:
            # Correlate based on specific indicator
            indicator = Indicator.query.get(indicator_id)
            if not indicator:
                return "Indicator not found."
            
            # Find related indicators
            related_indicators = Indicator.query.filter(
                and_(
                    Indicator.id != indicator_id,
                    or_(
                        Indicator.indicator_type == indicator.indicator_type,
                        Indicator.source == indicator.source,
                        Indicator.severity_score == indicator.severity_score
                    )
                )
            ).limit(10).all()
            
            correlation_data = {
                'primary_indicator': {
                    'id': indicator.id,
                    'name': indicator.name,
                    'type': indicator.indicator_type,
                    'description': indicator.description,
                    'severity': indicator.severity_score,
                    'source': indicator.source
                },
                'related_indicators': [
                    {
                        'id': ind.id,
                        'name': ind.name,
                        'type': ind.indicator_type,
                        'description': ind.description,
                        'severity': ind.severity_score,
                        'source': ind.source
                    } for ind in related_indicators
                ]
            }
            
        elif search_term:
            # Correlate based on search term
            indicators = Indicator.query.filter(
                or_(
                    Indicator.name.ilike(f'%{search_term}%'),
                    Indicator.description.ilike(f'%{search_term}%'),
                    Indicator.indicator_value.ilike(f'%{search_term}%')
                )
            ).limit(20).all()
            
            correlation_data = {
                'search_term': search_term,
                'found_indicators': [
                    {
                        'id': ind.id,
                        'name': ind.name,
                        'type': ind.indicator_type,
                        'description': ind.description,
                        'severity': ind.severity_score,
                        'source': ind.source
                    } for ind in indicators
                ]
            }
        
        else:
            return "Please provide either an indicator ID or search term for correlation analysis."
        
        # Generate correlation analysis
        correlation_prompt = f"""
        Analyze the following threat correlation data and provide insights on:
        
        1. **Threat Relationships**: How are these threats related?
        2. **Attack Patterns**: What attack patterns emerge from this correlation?
        3. **Risk Assessment**: What is the combined risk level?
        4. **Mitigation Strategy**: What unified mitigation approach should be taken?
        5. **Detection Recommendations**: How can these correlated threats be detected?
        
        Correlation Data:
        {json.dumps(correlation_data, indent=2)}
        
        Provide detailed analysis with specific recommendations for threat response.
        """
        
        response = openai.ChatCompletion.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a threat intelligence analyst specializing in threat correlation and pattern recognition. Provide detailed analysis of threat relationships and actionable recommendations."},
                {"role": "user", "content": correlation_prompt}
            ],
            max_tokens=2000,
            temperature=0.2
        )
        
        return response.choices[0].message.content
        
    except Exception as e:
        return f"Error performing threat correlation: {str(e)}"

def analyze_attack_chain(technique_name=None):
    """Analyze MITRE ATT&CK attack chains and provide defensive recommendations"""
    try:
        if technique_name:
            # Find specific technique and related techniques
            technique = Indicator.query.filter(
                and_(
                    Indicator.indicator_type == 'MITRE Technique',
                    Indicator.name.ilike(f'%{technique_name}%')
                )
            ).first()
            
            if not technique:
                return f"MITRE technique '{technique_name}' not found in the database."
            
            # Find related techniques (same source, similar severity)
            related_techniques = Indicator.query.filter(
                and_(
                    Indicator.indicator_type == 'MITRE Technique',
                    Indicator.id != technique.id,
                    Indicator.source == technique.source
                )
            ).limit(15).all()
            
            attack_chain_data = {
                'primary_technique': {
                    'name': technique.name,
                    'description': technique.description,
                    'severity': technique.severity_score,
                    'source': technique.source
                },
                'related_techniques': [
                    {
                        'name': tech.name,
                        'description': tech.description,
                        'severity': tech.severity_score
                    } for tech in related_techniques
                ]
            }
            
        else:
            # Analyze overall attack patterns
            techniques = Indicator.query.filter_by(
                indicator_type='MITRE Technique'
            ).order_by(Indicator.severity_score.desc()).limit(20).all()
            
            attack_chain_data = {
                'attack_techniques': [
                    {
                        'name': tech.name,
                        'description': tech.description,
                        'severity': tech.severity_score,
                        'source': tech.source
                    } for tech in techniques
                ]
            }
        
        # Generate attack chain analysis
        analysis_prompt = f"""
        Analyze the following MITRE ATT&CK attack chain data and provide:
        
        1. **Attack Chain Mapping**: How do these techniques relate in attack chains?
        2. **Tactics, Techniques, and Procedures (TTPs)**: What TTPs are represented?
        3. **Defensive Recommendations**: What defensive measures should be implemented?
        4. **Detection Strategies**: How can these attack chains be detected?
        5. **Response Procedures**: What should be the response when these techniques are detected?
        6. **Threat Hunting**: What proactive hunting should be conducted?
        
        Attack Chain Data:
        {json.dumps(attack_chain_data, indent=2)}
        
        Provide detailed analysis with specific defensive and detection recommendations.
        """
        
        response = openai.ChatCompletion.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert specializing in MITRE ATT&CK framework, attack chain analysis, and defensive strategies. Provide detailed analysis of attack techniques and comprehensive defensive recommendations."},
                {"role": "user", "content": analysis_prompt}
            ],
            max_tokens=2500,
            temperature=0.2
        )
        
        return response.choices[0].message.content
        
    except Exception as e:
        return f"Error analyzing attack chain: {str(e)}"

def get_ai_insights_summary():
    """Get a summary of recent AI insights and recommendations"""
    try:
        # Get recent user queries and their AI responses
        recent_queries = UserQuery.query.order_by(
            UserQuery.timestamp.desc()
        ).limit(10).all()
        
        if not recent_queries:
            return "No recent AI insights available."
        
        insights_data = [
            {
                'question': query.question,
                'answer': query.answer[:500] + "..." if len(query.answer) > 500 else query.answer,
                'timestamp': query.timestamp
            } for query in recent_queries
        ]
        
        summary_prompt = f"""
        Analyze the following recent AI security insights and provide:
        
        1. **Key Themes**: What are the main security themes emerging?
        2. **Trending Concerns**: What security concerns are most frequently discussed?
        3. **Recommendation Patterns**: What types of recommendations are most common?
        4. **Action Items**: What immediate actions should be prioritized?
        5. **Knowledge Gaps**: What areas need more investigation or analysis?
        
        Recent AI Insights:
        {json.dumps(insights_data, indent=2)}
        
        Provide a concise summary highlighting the most important findings and recommendations.
        """
        
        response = openai.ChatCompletion.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a cybersecurity analyst reviewing recent AI-generated security insights. Provide a clear, actionable summary of key findings and recommendations."},
                {"role": "user", "content": summary_prompt}
            ],
            max_tokens=1500,
            temperature=0.2
        )
        
        return response.choices[0].message.content
        
    except Exception as e:
        return f"Error generating insights summary: {str(e)}"
