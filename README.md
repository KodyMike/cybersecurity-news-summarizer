# Cybersecurity News Summarizer

An advanced, modular Python system that collects cybersecurity intelligence from the past two weeks, performs intelligent content analysis with AI (Google Gemini or Anthropic Claude), and generates professional briefings for LinkedIn and Viva Engage.

## Features

- **Two-Week Intelligence Window**: Focused on the most recent 14 days of security news.
- **Dual AI Provider Support**: Choose between Google's Gemini API (free tier) or Anthropic's Claude for content generation.
- **Multi-Source Collection**: RSS feeds from 8+ premium security sources + CISA KEV.
- **Web Scraping Enhancement**: Full article content extraction for detailed analysis.
- **Smart Threat Scoring**: Balanced algorithm prioritizing critical vulnerabilities.
- **Source Diversity**: Prevents any single source from dominating output.
- **Dual Output**: LinkedIn posts with emojis + professional Viva Engage briefs.

## Architecture

- **`data_collector.py`** - RSS/API data collection with threat filtering
- **`content_processor.py`** - Threat scoring and content generation  
- **`main.py`** - Simple orchestrator for command-line execution

## Installation & Usage

### 1. Install Dependencies
First, install the required Python packages from the `requirements.txt` file.
```bash
python3 -m pip install -r requirements.txt
```

### 2. Install the Command
Use `pipx` to install the script and make the `cybersec-news-summarizer` command available globally.
```bash
# Install pipx if you don't have it
python3 -m pip install --user pipx

# Install the package
pipx install .
```
*Note: You may need to restart your terminal for the command to be available.*

### 3. Configure API Keys
This tool requires API access for AI-powered content generation.

**For Google Gemini (Default):**
1. Get a free API key from [Google AI Studio](https://aistudio.google.com/).
2. Set it as an environment variable.
   ```bash
   export GOOGLE_API_KEY="YOUR_API_KEY_HERE"
   ```
   (Add this line to your `~/.bashrc` or `~/.zshrc` to make it permanent).

**For Claude:**
- Ensure the [Claude CLI](https://github.com/anthropics/claude-cli) is installed and configured.

## Running the Summarizer

Once installed, you can run the command from any directory.

```bash
# Run using the default provider (Gemini)
cybersec-news-summarizer

# Run silently (useful for cron jobs)
cybersec-news-summarizer --quiet
```

## Command-line Options

```bash
# Get help information
cybersec-news-summarizer --help

# Choose a specific AI provider
cybersec-news-summarizer --provider gemini
cybersec-news-summarizer --provider claude
```

## Dependencies

- `beautifulsoup4>=4.13.4`
- `feedparser>=6.0.11`
- `google-generativeai>=0.5.4`
- `python-dateutil>=2.8.2`
- `requests>=2.32.4`

## Automation with Cron

Since the program collects news from the past two weeks, running it once every 2 weeks is sufficient.

```bash
# Run every 2 weeks (Monday at 8am) using Gemini
0 8 1,15 * * cybersec-news-summarizer --provider gemini --quiet
```


## Data Sources

- **KrebsOnSecurity** - Independent security journalism
- **Bleeping Computer** - Technical security news
- **The Hacker News** - Security industry coverage  
- **Unit 42** - Threat intelligence research
- **Mandiant** - Advanced threat intelligence
- **Recorded Future** - Strategic threat research
- **CrowdStrike** - Threat intelligence research
- **Security Week** - Enterprise security news
- **Dark Reading** - Cybersecurity analysis
- **CISA KEV** - Government vulnerability catalog

## Output Files

- **`raw_cybersec_data.json`** - Collected intelligence data
- **`linkedin_ready.md`** - Social media posts with emojis
- **`yammer_ready.txt`** - Viva Engage briefing format

## Configuration

The system automatically:

- Filters last 14 days of content
- Scores threats by severity and credibility
- Balances source diversity (max 3 per source)
- Generates dynamic executive summaries

## Example Output

### LinkedIn Format

```
Cybersecurity Threat Landscape Update: Week of [DATE] 🚨

[Executive summary paragraph describing the week's threat landscape, 
key trends, and statistics from multiple sources...]

Top 10 Critical Threats:

1. [Threat Title]: [Brief description] 🔗 [source-url]
2. [Threat Title]: [Brief description] 🔗 [source-url]
...

#cybersecurity #threatintelligence #ransomware #vulnerabilities
```

### Viva Engage Format

```text
CYBERSECURITY INTELLIGENCE BRIEF - 2025-07-02

EXECUTIVE SUMMARY:
This week's threat landscape shows elevated activity...

KEY THREATS AND VULNERABILITIES:
- Critical Microsens Product Flaws Allow Hackers to Go 'From Zero to Hero'
  CISA has informed organizations about critical authentication bypass...
  Source: Security Week
  Link: https://www.securityweek.com/...
```
