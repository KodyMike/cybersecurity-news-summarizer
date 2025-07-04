#!/usr/bin/env python3
"""Cybersecurity Data Collector - Focused RSS and API collection"""

import requests
import feedparser
import json
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
from dateutil.parser import parse

class DataCollector:
    def __init__(self, quiet=False):
        self.quiet = quiet
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'})
        
        
        self.threat_keywords = [
            'vulnerability', 'exploit', 'zero-day', 'cve', 'patch', 'malware', 'ransomware', 
            'phishing', 'attack', 'breach', 'hack', 'compromise', 'critical', 'security flaw',
            'artificial intelligence', 'ai security', 'machine learning', 'ai vulnerability',
            'ai threat', 'generative ai', 'llm security', 'ai attack', 'deepfake', 'ai model',
            'apt', 'advanced persistent threat', 'nation-state', 'threat actor', 'campaign',
            'espionage', 'attribution', 'threat group', 'cyber warfare', 'state-sponsored',
            'mobile security', 'hardening', 'encryption', 'privacy'
        ]
        
        
        self.exclude_keywords = [
            'career', 'hiring', 'job', 'training course', 'webinar', 'conference',
            'open position', 'we are hiring', 'join our team', 'career opportunity'
        ]

    def is_threat_relevant(self, title, summary, source_name=""):
        content = f"{title} {summary}".lower()
        
        
        trusted_sources = ['Recorded Future', 'Mandiant', 'Unit 42']
        if source_name in trusted_sources:
            
            basic_excludes = ['career', 'hiring', 'job', 'we are hiring', 'join our team']
            if any(word in content for word in basic_excludes):
                return False
            security_terms = ['cyber', 'security', 'threat', 'attack', 'protection', 'vulnerability', 'malware']
            return any(word in content for word in security_terms)
        
        if any(word in content for word in self.exclude_keywords):
            return False
            
        return any(word in content for word in self.threat_keywords)

    def scrape_full_article(self, url):
        """Scrape full article content for better analysis"""
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code != 200:
                return None
                
            soup = BeautifulSoup(response.content, 'html.parser')
            
            
            for tag in soup(['script', 'style', 'nav', 'header', 'footer', 'aside', 'ad']):
                tag.decompose()
            
        
            article_selectors = [
                'article', '.article-content', '.post-content', '.entry-content',
                '.article-body', '.content', 'main', '.story-body'
            ]
            
            content = ""
            for selector in article_selectors:
                article_element = soup.select_one(selector)
                if article_element:
                    content = article_element.get_text(strip=True)
                    break
            
            
            if not content:
                
                for tag in soup(['nav', 'header', 'footer', 'sidebar', '.sidebar', '.menu']):
                    tag.decompose()
                content = soup.get_text(strip=True)
            
            
            lines = [line.strip() for line in content.split('\n') if line.strip()]
            content = ' '.join(lines)
            
            
            max_words = 1000
            words = content.split()
            if len(words) > max_words:
                content = ' '.join(words[:max_words]) + "..."
            
            return content if len(content) > 100 else None
            
        except Exception as e:
            if not self.quiet:
                print(f"Error scraping {url}: {e}")
            return None

    def enhance_with_metadata(self, title, summary, link):
        """Enhance articles with metadata analysis when scraping fails"""
        enhanced_summary = summary
        
        if link:
            url_parts = link.split('/')
            for part in url_parts:
                if len(part) > 20 and any(keyword in part.lower() for keyword in ['vulnerability', 'breach', 'attack', 'exploit']):
                    enhanced_summary += f" [URL indicates: {part.replace('-', ' ')}]"
                    break
        
        title_lower = title.lower()
        if 'cve-' in title_lower:
            cve_match = title_lower.split('cve-')[1][:9]  # Get CVE number
            enhanced_summary += f" [CVE Reference: CVE-{cve_match}]"
        
        if any(urgent in title_lower for urgent in ['critical', 'zero-day', 'actively exploited']):
            enhanced_summary += " [High Priority Threat]"
        
        if any(vendor in title_lower for vendor in ['microsoft', 'google', 'apple', 'cisco', 'citrix']):
            enhanced_summary += " [Major Vendor Impact]"
        
        return enhanced_summary

    def clean_summary(self, raw_summary):
        if not raw_summary:
            return "No summary available"
        
        clean_text = BeautifulSoup(raw_summary, 'html.parser').get_text()
        clean_text = ' '.join(clean_text.split())
        
        if len(clean_text) <= 300:
            return clean_text
        
        sentences = clean_text.split('. ')
        result = ""
        for sentence in sentences:
            if len(result + sentence + '. ') <= 300:
                result += sentence + '. '
            else:
                break
        
        return result.strip() if result.strip() else clean_text[:297] + "..."

    def collect_rss_source(self, source):
        try:
            response = self.session.get(source['url'], timeout=30)
            if response.status_code != 200:
                return []
                
            feed = feedparser.parse(response.content)
            articles = []
            
            for entry in feed.entries[:20]:
                try:
                    pub_date = None
                    if hasattr(entry, 'published_parsed') and entry.published_parsed:
                        pub_date = datetime(*entry.published_parsed[:6])
                    elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                        pub_date = datetime(*entry.updated_parsed[:6])
                    elif hasattr(entry, 'published') and entry.published:
                        try:
                            
                            pub_date = parse(entry.published)
                        except:
                            pass
                    
                    cutoff_date = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=14)
                    
                    if pub_date and pub_date.tzinfo is not None:
                        pub_date = pub_date.replace(tzinfo=None)
                    if pub_date and pub_date >= cutoff_date:
                        title = getattr(entry, 'title', '')
                        summary = self.clean_summary(getattr(entry, 'summary', ''))
                        
                        if source['name'] in ['Recorded Future', 'Mandiant'] or self.is_threat_relevant(title, summary, source['name']):
                            link = getattr(entry, 'link', '')
                            
                            full_content = None
                            enhanced_summary = summary
                            
                            if link and len(articles) < 5:  
                                if not self.quiet:
                                    print(f"  Scraping: {title[:50]}...")
                                full_content = self.scrape_full_article(link)
                            
                            if not full_content and link:
                                enhanced_summary = self.enhance_with_metadata(title, summary, link)
                            
                            articles.append({
                                'title': title,
                                'summary': enhanced_summary,
                                'full_content': full_content,
                                'link': link,
                                'published': pub_date.isoformat(),
                                'source_type': 'rss'
                            })
                            
                        if len(articles) >= 10:
                            break
                except:
                    continue
            
            return articles
        except Exception as e:
            if not self.quiet:
                print(f"Error collecting from {source['name']}: {e}")
            return []

    def collect_cisa_kev(self):
        try:
            response = self.session.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', timeout=30)
            cisa_data = response.json()
            
            recent_kevs = []
            recent_date = datetime.now() - timedelta(days=14)
            
            for vuln in cisa_data.get('vulnerabilities', []):
                try:
                    date_added = datetime.strptime(vuln.get('dateAdded', ''), '%Y-%m-%d')
                    if date_added >= recent_date:
                        recent_kevs.append({
                            'cve_id': vuln.get('cveID', ''),
                            'vendor': vuln.get('vendorProject', ''),
                            'product': vuln.get('product', ''),
                            'vulnerability_name': vuln.get('vulnerabilityName', ''),
                            'description': vuln.get('shortDescription', ''),
                            'required_action': vuln.get('requiredAction', ''),
                            'due_date': vuln.get('dueDate', ''),
                            'date_added': date_added.isoformat(),
                            'source_type': 'cisa_kev'
                        })
                except:
                    continue
            
            return recent_kevs
        except Exception as e:
            if not self.quiet:
                print(f"Error collecting CISA KEV: {e}")
            return []

    def collect_all(self):
        if not self.quiet:
            print("Collecting cybersecurity intelligence...")
        
        sources = [
            {'name': 'KrebsOnSecurity', 'url': 'https://krebsonsecurity.com/feed/'},
            {'name': 'Bleeping Computer', 'url': 'https://www.bleepingcomputer.com/feed/'},
            {'name': 'The Hacker News', 'url': 'https://feeds.feedburner.com/TheHackersNews'},
            {'name': 'Unit 42', 'url': 'https://unit42.paloaltonetworks.com/feed/'},
            {'name': 'Dark Reading', 'url': 'https://www.darkreading.com/rss.xml'},
            {'name': 'Security Week', 'url': 'https://www.securityweek.com/feed/'},
            {'name': 'Recorded Future', 'url': 'https://www.recordedfuture.com/feed'},
            {'name': 'Mandiant', 'url': 'https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/'},
        ]
        
        all_data = {
            'collection_date': datetime.now().isoformat(),
            'sources': []
        }
        
        for source in sources:
            articles = self.collect_rss_source(source)
            all_data['sources'].append({
                'name': source['name'],
                'type': 'rss',
                'articles': articles,
                'count': len(articles)
            })
        
        cisa_kevs = self.collect_cisa_kev()
        all_data['sources'].append({
            'name': 'CISA KEV',
            'type': 'government',
            'articles': cisa_kevs,
            'count': len(cisa_kevs)
        })
        
        with open('raw_cybersec_data.json', 'w') as f:
            json.dump(all_data, f, indent=2)
        
        total = sum(s['count'] for s in all_data['sources'])
        if not self.quiet:
            print(f"Collection complete: {total} items from {len(all_data['sources'])} sources")
        
        return all_data