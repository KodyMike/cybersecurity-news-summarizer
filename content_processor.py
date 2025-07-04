#!/usr/bin/env python3
"""Content Processor - Threat scoring and content generation with multiple AI providers"""

import os
import subprocess
from datetime import datetime
import google.generativeai as genai

class ContentProcessor:
    def __init__(self, quiet=False, ai_provider='gemini'):
        self.quiet = quiet
        self.ai_provider = ai_provider
        self.source_scores = {
            'CISA KEV': 8, 'KrebsOnSecurity': 8, 'Security Week': 7,
            'The Hacker News': 6, 'Bleeping Computer': 6, 'Unit 42': 8,
            'Dark Reading': 5, 'Recorded Future': 7, 'Mandiant': 8
        }

    def calculate_threat_score(self, title, summary, source_name):
        content = f"{title} {summary}".lower()
        score = 0
        
        critical_keywords = [
            'zero-day', 'critical', 'actively exploited', 'emergency patch',
            'remote code execution', 'rce', 'authentication bypass', 'privilege escalation',
            'supply chain attack', 'nation-state', 'apt',
            'ai security', 'artificial intelligence', 'ai vulnerability', 'ai threat',
            'generative ai', 'llm security', 'ai attack', 'deepfake', 'ai model',
            'advanced persistent threat', 'threat actor', 'espionage', 'attribution',
            'threat group', 'cyber warfare', 'state-sponsored', 'campaign'
        ]
        
        high_keywords = [
            'vulnerability', 'exploit', 'breach', 'ransomware', 'malware',
            'phishing', 'attack', 'compromise', 'backdoor', 'trojan',
            'machine learning', 'ai bias', 'model poisoning', 'prompt injection'
        ]
        
        medium_keywords = [
            'security flaw', 'patch', 'update', 'cve', 'exposure', 'hack'
        ]
        
        for keyword in critical_keywords:
            if keyword in content:
                score += 10
        for keyword in high_keywords:
            if keyword in content:
                score += 5
        for keyword in medium_keywords:
            if keyword in content:
                score += 2
        
        score += self.source_scores.get(source_name, 0)
        
        return score

    def generate_with_gemini(self, data):
        """Use Google Gemini API to analyze data and generate content."""
        try:
            api_key = os.getenv("GOOGLE_API_KEY")
            if not api_key:
                if not self.quiet:
                    print("Error: GOOGLE_API_KEY environment variable not set.")
                return None, None
            genai.configure(api_key=api_key)

            summary_data = []
            for source in data['sources']:
                if source['count'] > 0:
                    source_summary = f"Source: {source['name']} ({source['count']} items)\n"
                    for article in source['articles'][:5]:
                        if source['name'] == 'CISA KEV':
                            title = f"{article.get('cve_id', 'Unknown CVE')} - {article.get('vulnerability_name', 'Unknown Vulnerability')}"
                            summary = f"{article.get('description', 'No description')} Due date: {article.get('due_date', 'Not specified')}"
                            link = ''
                        else:
                            title = article.get('title', 'No title')
                            if source['name'] == 'CrowdStrike' and article.get('full_content'):
                                content = article.get('full_content', 'No content available')
                                if len(content) > 500:
                                    content = content[:500] + "..."
                            else:
                                content = article.get('summary', 'No content available')
                                if len(content) > 300:
                                    content = content[:300] + "..."
                            link = article.get('link', '')
                        
                        if link:
                            source_summary += f"- {title}\n  {content}\n  Link: {link}\n\n"
                        else:
                            source_summary += f"- {title}\n  {content}\n\n"
                    summary_data.append(source_summary)
            
            prompt = f"""Analyze this comprehensive cybersecurity intelligence data from multiple authoritative sources and create professional content with accurate, detailed executive summaries:

{chr(10).join(summary_data)}

EXECUTIVE SUMMARY REQUIREMENTS:
- Create a comprehensive overview that reflects the FULL scope of threats and incidents from ALL sources
- Include specific threat categories (ransomware, APT campaigns, critical vulnerabilities, data breaches, etc.)
- Mention key threat actors, affected sectors, and geographic regions where relevant
- Reference major vendors, platforms, and technologies affected
- Provide quantified metrics based on actual data (number of articles, sources, critical CVEs, etc.)
- Highlight emerging trends, attack vectors, and significant security developments
- Make it informative and executive-level appropriate, not generic

Create TWO outputs with IDENTICAL comprehensive executive summaries:

1. LINKEDIN POST:
- Professional social media post with emojis and hashtags
- Include comprehensive executive summary covering all major threat categories and developments
- List top 10 most critical threats with brief descriptions 
- MUST include 🔗 followed by plain URL (NOT markdown links) for each threat that has a link
- NO markdown formatting like **bold** - LinkedIn doesn't support it
- Use engaging format for cybersecurity professionals
- Add relevant hashtags at the end

2. YAMMER BRIEF:
- Internal company briefing in PLAIN TEXT (no markdown formatting like ** or ##)
- Include SAME comprehensive executive summary as LinkedIn (identical wording and numbers)
- Use clear header: "CYBERSECURITY INTELLIGENCE BRIEF - WEEK OF [DATE]" 
- Provide detailed analysis of the threat landscape with specific examples
- List top 12 threats with detailed, technical descriptions that vary in structure and language
- MUST include "Link: [URL]" for each threat that has a link
- Include technical details: CVE numbers, affected versions, attack vectors, IOCs, MITRE ATT&CK techniques where available
- Focus on business impact and specific actionable intelligence
- Write each threat description differently - vary sentence structure, avoid repetitive phrases
- CRITICAL: Do not use repetitive phrases like "This highlights", "This underscores", "This emphasizes" 
- Use varied language: "Attackers leveraged...", "The campaign utilized...", "Security researchers discovered...", "Analysis reveals..."
- Include threat actor attribution, campaign names, and technical details where available
- End with: "Here are the top 12 most valuable threats that were curated from this comprehensive intelligence analysis:"

CRITICAL REQUIREMENTS:
- Executive summary must be comprehensive and reflect the full scope of collected intelligence
- Both outputs must have IDENTICAL executive summaries and threat counts
- Include ALL available URLs in both formats
- LinkedIn URLs: Use plain URLs with 🔗 emoji only (NO markdown [text](url) format)
- LinkedIn formatting: NO **bold** markdown - LinkedIn doesn't support it
- Yammer must be PLAIN TEXT only (no ** bold ** or ## headers)
- Use professional, informative tone suitable for executive briefings
- Focus on actionable intelligence and strategic threat awareness

Format EXACTLY as:
=== LINKEDIN ===
[content]

=== YAMMER ===
[content]"""

            if not self.quiet:
                print(f"Sending prompt to Gemini API ({len(prompt)} characters)...")

            model = genai.GenerativeModel('gemini-1.5-flash')
            response = model.generate_content(prompt)
            
            with open('gemini_raw_response.txt', 'w') as f:
                f.write(response.text)
            
            if response.text and '=== LINKEDIN ===' in response.text and '=== YAMMER ===' in response.text:
                parts = response.text.split('=== LINKEDIN ===')[1].split('=== YAMMER ===')
                linkedin_content = parts[0].strip()
                yammer_content = parts[1].strip()
                return linkedin_content, yammer_content
            else:
                if not self.quiet:
                    print("Error: Could not parse Gemini response.")
                    print(f"Response text: {response.text[:500]}...")
                return None, None

        except Exception as e:
            if not self.quiet:
                print(f"Gemini API processing error: {e}")
            return None, None

    def generate_with_claude(self, data):
        """Use Claude CLI to analyze data and generate accurate content"""
        
        
        summary_data = []
        for source in data['sources']:
            if source['count'] > 0:
                source_summary = f"Source: {source['name']} ({source['count']} items)\n"
                for article in source['articles'][:5]:  # Top 5 from each source
                    if source['name'] == 'CISA KEV':
                        title = f"{article.get('cve_id', 'Unknown CVE')} - {article.get('vulnerability_name', 'Unknown Vulnerability')}"
                        summary = f"{article.get('description', 'No description')} Due date: {article.get('due_date', 'Not specified')}"
                        link = ''
                    else:
                        title = article.get('title', 'No title')
                        content = article.get('summary', 'No content available')
                        if len(content) > 300:
                            content = content[:300] + "..."
                        link = article.get('link', '')
                    
                    if link:
                        source_summary += f"- {title}\n  {content}\n  Link: {link}\n\n"
                    else:
                        source_summary += f"- {title}\n  {content}\n\n"
                summary_data.append(source_summary)
        
        
        prompt = f"""Analyze this comprehensive cybersecurity intelligence data from multiple authoritative sources and create professional content with accurate, detailed executive summaries:

{chr(10).join(summary_data)}

EXECUTIVE SUMMARY REQUIREMENTS:
- Create a comprehensive overview that reflects the FULL scope of threats and incidents from ALL sources
- Include specific threat categories (ransomware, APT campaigns, critical vulnerabilities, data breaches, etc.)
- Mention key threat actors, affected sectors, and geographic regions where relevant
- Reference major vendors, platforms, and technologies affected
- Provide quantified metrics based on actual data (number of articles, sources, critical CVEs, etc.)
- Highlight emerging trends, attack vectors, and significant security developments
- Make it informative and executive-level appropriate, not generic

Create TWO outputs with IDENTICAL comprehensive executive summaries:

1. LINKEDIN POST:
- Professional social media post with emojis and hashtags
- Include comprehensive executive summary covering all major threat categories and developments
- List top 10 most critical threats with brief descriptions 
- MUST include 🔗 followed by plain URL (NOT markdown links) for each threat that has a link
- NO markdown formatting like **bold** - LinkedIn doesn't support it
- Use engaging format for cybersecurity professionals
- Add relevant hashtags at the end

2. YAMMER BRIEF:
- Internal company briefing in PLAIN TEXT (no markdown formatting like ** or ##)
- Include SAME comprehensive executive summary as LinkedIn (identical wording and numbers)
- Use clear header: "CYBERSECURITY INTELLIGENCE BRIEF - WEEK OF [DATE]" 
- Provide detailed analysis of the threat landscape with specific examples
- List top 12 threats with detailed, technical descriptions that vary in structure and language
- MUST include "Link: [URL]" for each threat that has a link
- Include technical details: CVE numbers, affected versions, attack vectors, IOCs, MITRE ATT&CK techniques where available
- Focus on business impact and specific actionable intelligence
- Write each threat description differently - vary sentence structure, avoid repetitive phrases
- CRITICAL: Do not use repetitive phrases like "This highlights", "This underscores", "This emphasizes" 
- Use varied language: "Attackers leveraged...", "The campaign utilized...", "Security researchers discovered...", "Analysis reveals..."
- Include threat actor attribution, campaign names, and technical details where available
- End with: "Here are the top 12 most valuable threats that were curated from this comprehensive intelligence analysis:"

CRITICAL REQUIREMENTS:
- Executive summary must be comprehensive and reflect the full scope of collected intelligence
- Both outputs must have IDENTICAL executive summaries and threat counts
- Include ALL available URLs in both formats
- LinkedIn URLs: Use plain URLs with 🔗 emoji only (NO markdown [text](url) format)
- LinkedIn formatting: NO **bold** markdown - LinkedIn doesn't support it
- Yammer must be PLAIN TEXT only (no ** bold ** or ## headers)
- Use professional, informative tone suitable for executive briefings
- Focus on actionable intelligence and strategic threat awareness

Format EXACTLY as:
=== LINKEDIN ===
[content]

=== YAMMER ===
[content]"""

        try:
            result = subprocess.run(
                ['claude', '--quiet'], input=prompt, text=True,
                capture_output=True, check=True
            )
            
            response_text = result.stdout.strip()
            
            if response_text and '=== LINKEDIN ===' in response_text and '=== YAMMER ===' in response_text:
                parts = response_text.split('=== LINKEDIN ===')[1].split('=== YAMMER ===')
                linkedin_content = parts[0].strip()
                yammer_content = parts[1].strip()
                return linkedin_content, yammer_content
            else:
                if not self.quiet:
                    print("Error: Could not parse Claude response.")
                    print(f"Response text: {response_text[:500]}...")
                return None, None

        except Exception as e:
            if not self.quiet:
                print(f"Claude processing error: {e}")
            return None, None

    def get_top_threats(self, data):
        all_threats = []
        
        for source in data['sources']:
            if source['count'] > 0:
                for article in source['articles']:
                    if source['name'] == 'CISA KEV':
                        title = f"{article.get('cve_id', 'Unknown CVE')} - {article.get('vulnerability_name', 'Unknown Vulnerability')}"
                        summary = f"{article.get('description', 'No description')} Due date: {article.get('due_date', 'Not specified')}"
                        link = ''
                    else:
                        title = article.get('title', 'No title')
                        summary = article.get('summary', 'No summary available')
                        link = article.get('link', '')
                    
                    score = self.calculate_threat_score(title, summary, source['name'])
                    all_threats.append({
                        'title': title, 'summary': summary, 'link': link,
                        'source': source['name'], 'score': score
                    })
        
        all_threats.sort(key=lambda x: x['score'], reverse=True)
        
        top_threats = []
        source_counts = {}
        
        for threat in all_threats:
            source = threat['source']
            count = source_counts.get(source, 0)
            
            if count == 0 or len(top_threats) < 6 or count < 3:
                top_threats.append(threat)
                source_counts[source] = count + 1
            
            if len(top_threats) >= 12:
                break
        
        return top_threats

    def generate_content(self, data):
        """Generate content using the selected AI provider with fallback to basic generation"""
        
        linkedin_content, yammer_content = None, None

        if self.ai_provider == 'gemini':
            if not self.quiet:
                print("Generating content with Google Gemini...")
            linkedin_content, yammer_content = self.generate_with_gemini(data)
        elif self.ai_provider == 'claude':
            if not self.quiet:
                print("Generating content with Claude CLI...")
            linkedin_content, yammer_content = self.generate_with_claude(data)
        else:
            if not self.quiet:
                print(f"Unknown AI provider: '{self.ai_provider}'. Falling back to basic generation.")

        if linkedin_content and yammer_content:
            with open('linkedin_ready.md', 'w') as f:
                f.write(linkedin_content)
            with open('yammer_ready.txt', 'w') as f:
                f.write(yammer_content)
            
            if not self.quiet:
                print(f"AI processing successful ({self.ai_provider})!")
            return True
        else:
            if not self.quiet:
                print(f"AI provider '{self.ai_provider}' failed, falling back to basic generation...")
            return self.generate_fallback_content(data)
    
    def generate_fallback_content(self, data):
        """Fallback content generation without flawed counting"""
        today = datetime.now().strftime('%Y-%m-%d')
        top_threats = self.get_top_threats(data)
        active_sources = [s['name'] for s in data['sources'] if s['count'] > 0]
        
        cisa_count = len([s for s in data['sources'] if s['name'] == 'CISA KEV' and s['count'] > 0])
        total_articles = sum(s['count'] for s in data['sources'])
        
        exec_summary = f"This week's cybersecurity intelligence analysis covers {total_articles} security-related articles from {len(active_sources)} authoritative sources"
        if cisa_count > 0:
            cisa_vulns = next((s['count'] for s in data['sources'] if s['name'] == 'CISA KEV'), 0)
            exec_summary += f", including {cisa_vulns} new CISA Known Exploited Vulnerabilities"
        exec_summary += ". Key focus areas include critical vulnerabilities, security incidents, and emerging threat campaigns requiring immediate attention."
        
        linkedin_content = f"""🔒 Cybersecurity Intelligence Update - {today}

📋 Executive Summary:
{exec_summary}

📰 Latest Threats & Vulnerabilities:
"""
        
        yammer_content = f"""CYBERSECURITY INTELLIGENCE BRIEF - {today.upper()}

EXECUTIVE SUMMARY:
{exec_summary}

KEY THREATS AND VULNERABILITIES:
"""
        
        for threat in top_threats:
            title_short = threat['title'][:80]
            
            if threat['link']:
                linkedin_content += f"• {title_short} - {threat['source']}\n  {threat['summary']}\n  🔗 {threat['link']}\n\n"
            else:
                linkedin_content += f"• {title_short} - {threat['source']}\n  {threat['summary']}\n\n"
            
            if threat['link']:
                yammer_content += f"- {threat['title']}\n  {threat['summary']}\n  Source: {threat['source']}\n  Link: {threat['link']}\n\n"
            else:
                yammer_content += f"- {threat['title']}\n  {threat['summary']}\n  Source: {threat['source']}\n\n"
        
        linkedin_content += f"\n📊 Data Sources: {', '.join(active_sources)}\n\n#CyberSecurity #ThreatIntelligence #InfoSec #Security"
        
        yammer_content += f"""
RECOMMENDED ACTIONS:
1. Review and assess impact of identified vulnerabilities
2. Update security monitoring for emerging threats
3. Ensure timely patching of critical vulnerabilities
4. Monitor for indicators of compromise

Intelligence sources: {', '.join(active_sources)}"""
        
        with open('linkedin_ready.md', 'w') as f:
            f.write(linkedin_content)
        with open('yammer_ready.txt', 'w') as f:
            f.write(yammer_content)
        
        return True