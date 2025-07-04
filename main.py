#!/usr/bin/env python3
"""
Cybersecurity News Summarizer
This script collects cybersecurity news and intelligence from multiple sources,
processes the content, and generates summarized briefings in multiple formats.
It outputs ready-to-use content for social media and internal communications.
"""

import argparse
from data_collector import DataCollector
from content_processor import ContentProcessor

def main():
    parser = argparse.ArgumentParser(
        description="Cybersecurity News Summarizer - Collects and summarizes cybersecurity news from multiple sources."
    )
    parser.add_argument(
        "--version", action="version", version="Cybersecurity News Summarizer v2.0.0"
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Run with minimal output"
    )
    parser.add_argument(
        '--provider',
        type=str,
        default='gemini',
        choices=['gemini', 'claude'],
        help="The AI provider to use for content generation (default: gemini)."
    )
    args = parser.parse_args()

    if not args.quiet:
        print("Cybersecurity News Summarizer")
        print("=" * 40)
    
    collector = DataCollector(quiet=args.quiet)
    data = collector.collect_all()
    
    processor = ContentProcessor(quiet=args.quiet, ai_provider=args.provider)
    processor.generate_content(data)
    
    if not args.quiet:
        print(f"Files generated: linkedin_ready.md, yammer_ready.txt (using {args.provider})")

if __name__ == "__main__":
    main()