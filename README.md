# GitHub Commit Reviewer 🔍

A comprehensive, automated code review system that analyzes GitHub commits and pull requests, performs security vulnerability scanning and logical behavior analysis, then delivers technical reviews to both GitHub and Slack.

## Features

- 🔒 **Security Analysis**: Scans for vulnerabilities using Bandit
- 📊 **Complexity Analysis**: Measures code complexity with Radon
- 🎨 **Style Analysis**: Checks code style and best practices
- 🧠 **Logical Behavior**: Identifies potential logical issues
- 💬 **Multi-Platform Delivery**: Posts reviews to GitHub PR comments and Slack
- ⚡ **High Performance**: Handles large codebases efficiently
- 📈 **Scoring System**: Provides overall code quality scores (0-10)

## Quick Start

### Standalone Script (Recommended for Testing)

```bash
# Install dependencies
pip install -r requirements.txt

# Analyze a GitHub pull request
python commit_reviewer.py --repo Playyo807/frontend-car-booking-system --pr 123 \
  --github-token your_github_token \
  --post-github

# Analyze local code
python commit_reviewer.py --local /path/to/your/code